package apple

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"
)

const enrollmentAccessRights = 1 | 2 | 16 | 256 | 512 | 1024 | 2048 | 4096

type enrollmentLayout struct {
	profileUUID, mdmUUID, identityUUID, caUUID string
	identityType, publicURL, topic             string
	accessRights                               int64
	bootstrapToken                             bool
}

func newEnrollmentLayout(c *Settings) enrollmentLayout {
	return enrollmentLayout{profileUUID: uuid.NewString(), mdmUUID: uuid.NewString(), identityUUID: uuid.NewString(), caUUID: uuid.NewString(), identityType: "com.apple.security.scep", publicURL: c.PublicURL, topic: c.Topic, accessRights: enrollmentAccessRights}
}

func (l enrollmentLayout) validate() error {
	seen := make(map[string]bool)
	for i, value := range []string{l.profileUUID, l.mdmUUID, l.identityUUID, l.caUUID} {
		if i == 3 && value == "" && l.identityType == "com.apple.security.pkcs12" {
			continue
		}
		id, err := uuid.Parse(value)
		if err != nil || id == uuid.Nil || seen[id.String()] {
			return ErrConflict
		}
		seen[id.String()] = true
	}
	if (l.identityType != "com.apple.security.scep" && l.identityType != "com.apple.security.pkcs12") || l.accessRights != enrollmentAccessRights || l.publicURL == "" || l.topic == "" {
		return ErrConflict
	}
	return nil
}

func saveEnrollmentLayout(ctx context.Context, tx *sql.Tx, tenant int, deviceID string, l enrollmentLayout) error {
	if err := l.validate(); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO mdm_apple_enrollment_layouts(device_id,tenant_id,profile_uuid,mdm_uuid,identity_uuid,ca_uuid,identity_type,public_url,topic,access_rights,bootstrap_token) VALUES($1,$2,$3,$4,$5,NULLIF($6,''),$7,$8,$9,$10,$11) ON CONFLICT(device_id) DO NOTHING`, deviceID, tenant, l.profileUUID, l.mdmUUID, l.identityUUID, l.caUUID, l.identityType, l.publicURL, l.topic, l.accessRights, l.bootstrapToken)
	return err
}

func loadEnrollmentLayout(ctx context.Context, tx *sql.Tx, deviceID string) (*enrollmentLayout, error) {
	var l enrollmentLayout
	err := tx.QueryRowContext(ctx, `SELECT profile_uuid,mdm_uuid,identity_uuid,COALESCE(ca_uuid,''),identity_type,public_url,topic,access_rights,bootstrap_token FROM mdm_apple_enrollment_layouts WHERE device_id=$1`, deviceID).Scan(&l.profileUUID, &l.mdmUUID, &l.identityUUID, &l.caUUID, &l.identityType, &l.publicURL, &l.topic, &l.accessRights, &l.bootstrapToken)
	if err != nil {
		return nil, notFound(err)
	}
	return &l, l.validate()
}

// Recover only our own known enrollment structure from authenticated inventory.
// Payload UUID reporting needs iOS/iPadOS 17+. Missing metadata is never guessed.
func (s *Store) recoverEnrollmentLayout(ctx context.Context, tx *sql.Tx, d *Device, profiles []InstalledProfile) error {
	if _, err := loadEnrollmentLayout(ctx, tx, d.ID); err == nil {
		return nil
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	prefix := "eu.openuem.enrollment." + d.ID
	var found *InstalledProfile
	for i := range profiles {
		if profiles[i].Identifier == prefix {
			if found != nil {
				return nil
			}
			found = &profiles[i]
		}
	}
	if found == nil {
		return nil
	}
	l := enrollmentLayout{profileUUID: found.UUID, accessRights: enrollmentAccessRights}
	seen := make(map[string]bool)
	for _, p := range found.Payloads {
		if seen[p.Identifier] || p.UUID == "" {
			return nil
		}
		seen[p.Identifier] = true
		switch p.Identifier {
		case prefix + ".mdm":
			if p.Type != "com.apple.mdm" || l.mdmUUID != "" {
				return nil
			}
			l.mdmUUID = p.UUID
		case prefix + ".identity":
			if (p.Type != "com.apple.security.scep" && p.Type != "com.apple.security.pkcs12") || l.identityUUID != "" {
				return nil
			}
			l.identityUUID, l.identityType = p.UUID, p.Type
		case prefix + ".ca":
			if p.Type != "com.apple.security.root" || l.caUUID != "" {
				return nil
			}
			l.caUUID = p.UUID
		default:
			// An unknown extra payload must not disappear during renewal.
			return nil
		}
	}
	// Older SCEP enrollments shipped without a separate root payload. A new one
	// can be added while retaining the installed MDM and top-level identifiers.
	if l.identityType == "com.apple.security.scep" && l.caUUID == "" {
		l.caUUID = uuid.NewString()
	}
	if err := tx.QueryRowContext(ctx, `SELECT public_url,topic FROM mdm_apple_settings WHERE tenant_id=$1`, d.TenantID).Scan(&l.publicURL, &l.topic); err != nil {
		return err
	}
	if l.validate() != nil {
		return nil
	}
	if err := saveEnrollmentLayout(ctx, tx, d.TenantID, d.ID, l); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE mdm_apple_devices SET next_identity_renewal_at=clock_timestamp(),identity_renewal_error='' WHERE id=$1`, d.ID); err != nil {
		return err
	}
	return audit(ctx, tx, d.TenantID, "device:"+d.ID, "apple.identity.layout.recover", d.ID)
}

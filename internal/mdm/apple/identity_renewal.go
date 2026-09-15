package apple

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
)

// ScheduleIdentityRenewals starts renewal thirty days before expiry. Each device
// has its own durable retry cursor so an offline or incomplete enrollment cannot
// starve the rest of the organization. This schedules only; it never retires a key.
func (s *Store) ScheduleIdentityRenewals(ctx context.Context) error {
	for range 25 {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		d, err := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM mdm_apple_devices WHERE status='enrolled' AND certificate_expires_at<=clock_timestamp()+interval '30 days' AND next_identity_renewal_at<=clock_timestamp() ORDER BY next_identity_renewal_at,id LIMIT 1 FOR UPDATE SKIP LOCKED`))
		if errors.Is(err, ErrNotFound) {
			tx.Rollback()
			return nil
		}
		if err != nil {
			tx.Rollback()
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_devices SET next_identity_renewal_at=clock_timestamp()+interval '6 hours' WHERE id=$1`, d.ID); err == nil {
			err = s.scheduleIdentityRenewal(ctx, tx, d)
		}
		if err != nil {
			tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func identityRenewalError(ctx context.Context, tx *sql.Tx, d *Device, code string) error {
	_, err := tx.ExecContext(ctx, `UPDATE mdm_apple_devices SET identity_renewal_error=$2 WHERE id=$1`, d.ID, code)
	return err
}

func (s *Store) scheduleIdentityRenewal(ctx context.Context, tx *sql.Tx, d *Device) error {
	var pending bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mdm_apple_identity_renewals WHERE device_id=$1 AND status IN ('queued','issued'))`, d.ID).Scan(&pending); err != nil {
		return err
	}
	if pending {
		return nil
	}
	if !time.Now().Before(d.CertificateExpiresAt) {
		return identityRenewalError(ctx, tx, d, "identity_expired")
	}
	layout, err := loadEnrollmentLayout(ctx, tx, d.ID)
	if errors.Is(err, ErrNotFound) {
		var queued bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mdm_apple_commands WHERE device_id=$1 AND request_type='ProfileList' AND status IN ('queued','sent','not_now') AND expires_at>clock_timestamp())`, d.ID).Scan(&queued); err != nil {
			return err
		}
		if !queued {
			if _, err = s.enqueue(ctx, tx, d, "ProfileList", nil, nil, nil); err != nil {
				return err
			}
		}
		return identityRenewalError(ctx, tx, d, "profile_inventory_required")
	}
	if errors.Is(err, ErrConflict) {
		return identityRenewalError(ctx, tx, d, "profile_metadata_invalid")
	}
	if err != nil {
		return err
	}
	// Match the enrollment lock order: device first, then organization settings.
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684627902,$1::integer)`, d.TenantID); err != nil {
		return err
	}
	c := &Settings{TenantID: d.TenantID}
	if err = tx.QueryRowContext(ctx, `SELECT public_url,organization,topic,push_expires_at,ca_certificate,ca_key FROM mdm_apple_settings WHERE tenant_id=$1`, d.TenantID).Scan(&c.PublicURL, &c.Organization, &c.Topic, &c.PushExpiresAt, &c.CACertificate, &c.CAKey); err != nil {
		return err
	}
	if !time.Now().Before(c.PushExpiresAt) {
		return identityRenewalError(ctx, tx, d, "push_certificate_expired")
	}
	if layout.publicURL != c.PublicURL || layout.topic != c.Topic {
		return identityRenewalError(ctx, tx, d, "enrollment_settings_changed")
	}
	c.CAKey, err = s.secrets.open(c.CAKey, secretPurpose(d.TenantID, "settings", "ca_key"))
	if err != nil {
		return identityRenewalError(ctx, tx, d, "authority_unavailable")
	}
	ca, _, err := enrollmentCA(c, time.Now())
	if err != nil {
		return identityRenewalError(ctx, tx, d, "authority_unavailable")
	}
	if !d.CertificateExpiresAt.Add(24 * time.Hour).Before(ca.NotAfter) {
		return identityRenewalError(ctx, tx, d, "authority_expiring")
	}
	authority, err := s.ensureSCEPAuthority(ctx, tx, c)
	if errors.Is(err, errSCEPAuthority) {
		return identityRenewalError(ctx, tx, d, "authority_unavailable")
	}
	if err != nil {
		return err
	}
	var fingerprint string
	if err = tx.QueryRowContext(ctx, `SELECT certificate_fingerprint FROM mdm_apple_devices WHERE id=$1`, d.ID).Scan(&fingerprint); err != nil {
		return err
	}
	id := uuid.NewString()
	challenge, err := randomToken()
	if err != nil {
		return err
	}
	next := *layout
	next.identityUUID, next.identityType = uuid.NewString(), "com.apple.security.scep"
	if next.caUUID == "" {
		next.caUUID = uuid.NewString()
	}
	profile, err := scepEnrollmentProfile(c, d.ID, challenge, "/mdm/apple/"+d.ID+"/scep/"+id, next)
	if err != nil {
		return err
	}
	commandID, err := s.enqueue(ctx, tx, d, "InstallProfile", map[string]any{"Payload": profile}, nil, nil)
	if err != nil {
		return err
	}
	expires := time.Now().Add(7 * 24 * time.Hour)
	if d.CertificateExpiresAt.Before(expires) {
		expires = d.CertificateExpiresAt
	}
	if !time.Now().Before(expires) {
		return ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET expires_at=$2 WHERE id=$1`, commandID, expires); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_identity_renewals(id,tenant_id,device_id,command_id,authority_id,base_fingerprint,base_expires_at,identity_uuid,ca_uuid,challenge_hash,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, id, d.TenantID, d.ID, commandID, authority.id, fingerprint, d.CertificateExpiresAt, next.identityUUID, next.caUUID, digest([]byte(challenge)), expires); err != nil {
		return err
	}
	if err = identityRenewalError(ctx, tx, d, ""); err != nil {
		return err
	}
	return audit(ctx, tx, d.TenantID, "identity-renewal-service", "apple.identity.renewal.schedule", id)
}

type IdentityRenewal struct {
	ID                     string     `json:"id"`
	Status                 string     `json:"status"`
	CommandID              string     `json:"command_id"`
	PreviousFingerprint    string     `json:"previous_fingerprint"`
	Fingerprint            string     `json:"fingerprint"`
	CreatedAt              time.Time  `json:"created_at"`
	AuthorizationExpiresAt time.Time  `json:"authorization_expires_at"`
	CertificateExpiresAt   *time.Time `json:"certificate_expires_at"`
	TokenUpdatedAt         *time.Time `json:"token_updated_at"`
	ConfirmedAt            *time.Time `json:"confirmed_at"`
	Error                  string     `json:"error"`
}

func (s *Store) IdentityRenewals(ctx context.Context, scope Scope, deviceID string) ([]IdentityRenewal, error) {
	if _, err := s.Device(ctx, scope, deviceID); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,status,command_id,base_fingerprint,COALESCE(certificate_fingerprint,''),created_at,expires_at,certificate_expires_at,token_updated_at,confirmed_at,error FROM mdm_apple_identity_renewals WHERE device_id=$1 AND tenant_id=$2 ORDER BY created_at DESC,id LIMIT 10`, deviceID, scope.TenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []IdentityRenewal{}
	for rows.Next() {
		var r IdentityRenewal
		if err = rows.Scan(&r.ID, &r.Status, &r.CommandID, &r.PreviousFingerprint, &r.Fingerprint, &r.CreatedAt, &r.AuthorizationExpiresAt, &r.CertificateExpiresAt, &r.TokenUpdatedAt, &r.ConfirmedAt, &r.Error); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

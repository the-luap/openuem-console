package apple

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
	"howett.net/plist"
)

var ErrACMEHistory = errors.New("invalid ACME historical profile review")

// Archive contents and client references never enter the listing model.
type ACMELegacyProfile struct {
	ID, DeviceID, ProfileID, Identifier, Scope, State string
	ReviewedBy, Reason                                string
	Revision                                          int
	CreatedAt                                         time.Time
	ReviewedAt                                        *time.Time
}

func (s *Store) ACMELegacyProfiles(ctx context.Context, tenant int, after, state string) ([]ACMELegacyProfile, string, error) {
	if tenant <= 0 || after != "" && !profileRevisionUUID(after) || state != "unresolved" && state != "reviewed" {
		return nil, "", ErrACMEHistory
	}
	var cursor any
	if after != "" {
		var exists bool
		if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mdm_apple_acme_legacy_profiles WHERE tenant_id=$1 AND id=$2)`, tenant, after).Scan(&exists); err != nil {
			return nil, "", err
		}
		if !exists {
			return nil, "", ErrNotFound
		}
		cursor = after
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,device_id,profile_id,revision,identifier,payload_scope,state,reviewed_by,review_reason,created_at,reviewed_at FROM mdm_apple_acme_legacy_profiles WHERE tenant_id=$1 AND (state=$2 OR ($2='unresolved' AND state='pending')) AND ($3::uuid IS NULL OR id>$3) ORDER BY id LIMIT 101`, tenant, state, cursor)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	items := []ACMELegacyProfile{}
	for rows.Next() {
		var item ACMELegacyProfile
		if err = rows.Scan(&item.ID, &item.DeviceID, &item.ProfileID, &item.Revision, &item.Identifier, &item.Scope, &item.State, &item.ReviewedBy, &item.Reason, &item.CreatedAt, &item.ReviewedAt); err != nil {
			return nil, "", err
		}
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(items) > 100 {
		next = items[99].ID
		items = items[:100]
	}
	return items, next, nil
}

func (s *Store) ReviewACMELegacyProfile(ctx context.Context, tenant int, id string, expected int, data []byte, reason, actor string, permissions *access.Store) error {
	return s.reviewACMELegacyProfile(ctx, tenant, id, expected, data, reason, actor, func(ctx context.Context, tx *sql.Tx) error {
		if permissions == nil {
			return access.ErrDenied
		}
		for _, capability := range []access.Capability{access.ManageProfiles, access.AssignProfiles} {
			if err := permissions.AuthorizeTransaction(ctx, tx, actor, capability, access.Scope{TenantID: tenant}); err != nil {
				return err
			}
		}
		return nil
	})
}

// This is an attributed administrative reconstruction of a missing archive,
// not cryptographic proof of what an older device installed. The original
// snapshot remains unchanged; the submitted archive is kept as separate evidence.
func (s *Store) reviewACMELegacyProfile(ctx context.Context, tenant int, id string, expected int, data []byte, reason, actor string, authorize func(context.Context, *sql.Tx) error) error {
	reason = strings.TrimSpace(reason)
	if tenant <= 0 || !profileRevisionUUID(id) || expected <= 0 || actor == "" || !validMacAppText(reason, 1000) {
		return ErrACMEHistory
	}
	clients, err := acmeLegacyClients(data)
	if err != nil {
		return ErrACMEHistory
	}
	var root map[string]any
	if _, err = plist.Unmarshal(data, &root); err != nil || stringValue(root, "PayloadType") != "Configuration" || numberValue(root["PayloadVersion"]) != 1 || !certificateText(root["PayloadIdentifier"], 255, false) || !profileRevisionUUID(strings.ToLower(stringValue(root, "PayloadUUID"))) {
		return ErrACMEHistory
	}
	scope := "System"
	if value, exists := root["PayloadScope"]; exists {
		if value != "System" && value != "User" {
			return ErrACMEHistory
		}
		scope = value.(string)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if authorize != nil {
		if err = authorize(ctx, tx); err != nil {
			return err
		}
	}
	var device, identifier, storedScope, state string
	var revision int
	if err = tx.QueryRowContext(ctx, `SELECT device_id,revision,identifier,payload_scope,state FROM mdm_apple_acme_legacy_profiles WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, id).Scan(&device, &revision, &identifier, &storedScope, &state); err != nil {
		return notFound(err)
	}
	if revision != expected || state != "unresolved" {
		return ErrConflict
	}
	if storedScope != scope || identifier != "" && identifier != stringValue(root, "PayloadIdentifier") {
		return ErrACMEHistory
	}
	if err = s.recordACMEClients(ctx, tx, tenant, device, clients, true); err != nil {
		return err
	}
	encrypted, err := s.secrets.seal(data, secretPurpose(tenant, "acme-legacy/"+id, "reviewed_profile"))
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_acme_legacy_profiles SET state='reviewed',reviewed_payload=$2,reviewed_by=$3,review_reason=$4,reviewed_at=clock_timestamp() WHERE id=$1 AND tenant_id=$5`, id, encrypted, actor, reason, tenant); err != nil {
		return err
	}
	if err = audit(ctx, tx, tenant, actor, "apple.acme.history.review", id); err != nil {
		return err
	}
	return tx.Commit()
}

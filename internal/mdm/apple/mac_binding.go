package apple

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
	"howett.net/plist"
)

var ErrMacBinding = errors.New("Mac channel verification is unavailable")

// MacBinding contains only public lifecycle metadata. Tokens, hashes and
// command/profile bytes must never enter view models or administrator responses.
type MacBinding struct {
	ID              string
	DeviceID        string
	Status          string
	CommandID       string
	CreatedAt       time.Time
	ExpiresAt       time.Time
	InstalledAt     *time.Time
	CompletedAt     *time.Time
	CleanupAt       *time.Time
	CleanupAttempts int
	CleanupStatus   string
}

func (b *MacBinding) CleanupRetryable() bool {
	return b != nil && b.CompletedAt != nil && b.CleanupAt == nil &&
		(b.CleanupStatus == "failed" || b.CleanupStatus == "expired" || b.CleanupStatus == "cancelled")
}

func macBindingProfile(proof enrollment.MacBindingProof, identifier, profileUUID string) ([]byte, error) {
	if !proof.Valid() || identifier != enrollment.MacBindingDomain+"."+proof.ChallengeID || profileUUID != proof.ChallengeID {
		return nil, ErrMacBinding
	}
	settings := map[string]any{"ChallengeID": proof.ChallengeID, "DeviceID": proof.DeviceID, "Token": proof.Token}
	payload := map[string]any{
		"PayloadType": "com.apple.ManagedClient.preferences", "PayloadVersion": 1,
		"PayloadIdentifier": identifier + ".preferences", "PayloadUUID": uuid.NewString(),
		"PayloadDisplayName": "OpenUEM management channel verification",
		"PayloadContent":     map[string]any{enrollment.MacBindingDomain: map[string]any{"Forced": []any{map[string]any{"mcx_preference_settings": settings}}}},
	}
	return plist.Marshal(map[string]any{
		"PayloadType": "Configuration", "PayloadVersion": 1, "PayloadScope": "System",
		"PayloadIdentifier": identifier, "PayloadUUID": profileUUID,
		"PayloadDisplayName": "OpenUEM management channel verification",
		"PayloadDescription": "Temporarily verifies the OpenUEM agent and MDM channels on this Mac.",
		"PayloadContent":     []any{payload},
	}, plist.XMLFormat)
}

func reservedMacBindingIdentifier(value string) bool {
	// Managed preference filenames may reside on a case-insensitive Mac volume.
	value = strings.ToLower(value)
	return value == enrollment.MacBindingDomain || strings.HasPrefix(value, enrollment.MacBindingDomain+".")
}

func (s *Store) MacBinding(ctx context.Context, scope Scope, id string) (*MacBinding, error) {
	if _, err := s.Device(ctx, scope, id); err != nil {
		return nil, err
	}
	b := &MacBinding{}
	err := s.db.QueryRowContext(ctx, `SELECT b.id,b.device_id,b.status,b.command_id,b.created_at,b.expires_at,b.installed_at,b.completed_at,b.cleanup_at,b.cleanup_attempts,COALESCE(c.status,'') FROM mdm_apple_mac_bindings b LEFT JOIN mdm_apple_commands c ON c.id=b.cleanup_command_id WHERE b.device_id=$1 AND b.tenant_id=$2 AND ($3=0 OR b.site_id=$3) ORDER BY b.created_at DESC,b.id DESC LIMIT 1`, id, scope.TenantID, scope.SiteID).Scan(&b.ID, &b.DeviceID, &b.Status, &b.CommandID, &b.CreatedAt, &b.ExpiresAt, &b.InstalledAt, &b.CompletedAt, &b.CleanupAt, &b.CleanupAttempts, &b.CleanupStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return b, err
}

// RequestMacBinding is idempotent while an unexpired challenge is pending.
// A new challenge waits for removal of all earlier verification profiles.
func (s *Store) RequestMacBinding(ctx context.Context, scope Scope, id, actor string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if scope.Validate() != nil || !enrollment.ValidDeviceID(id) || actor == "" || len(actor) > 255 {
		return ErrMacBinding
	}
	if !s.MacLinksReady(ctx) {
		return ErrMacBinding
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	d, err := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM mdm_apple_devices WHERE id=$1 AND tenant_id=$2 AND ($3=0 OR site_id=$3) FOR UPDATE`, id, scope.TenantID, scope.SiteID))
	if err != nil {
		return err
	}
	var ready bool
	var siteID int
	if err = tx.QueryRowContext(ctx, `SELECT id FROM sites WHERE id=$1 AND tenant_sites=$2 FOR SHARE`, d.SiteID, d.TenantID).Scan(&siteID); err != nil {
		return ErrMacBinding
	}
	if err = tx.QueryRowContext(ctx, `SELECT to_regclass('uem_agent_hardware') IS NOT NULL AND EXISTS(SELECT 1 FROM sites WHERE id=$1 AND tenant_sites=$2) AND $3::timestamptz>clock_timestamp()`, d.SiteID, d.TenantID, d.CertificateExpiresAt).Scan(&ready); err != nil {
		return err
	}
	if !ready || d.Status != "enrolled" || d.Family() != PlatformMacOS || !d.Capabilities().Profiles {
		return ErrMacBinding
	}
	if err = s.reconcileMacBindingsForDevice(ctx, tx, d); err != nil {
		return err
	}
	var active, unclean bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mdm_apple_mac_bindings WHERE device_id=$1 AND status IN ('queued','installed')),EXISTS(SELECT 1 FROM mdm_apple_mac_bindings WHERE device_id=$1 AND cleanup_at IS NULL)`, id).Scan(&active, &unclean); err != nil {
		return err
	}
	if active {
		return tx.Commit()
	}
	if unclean {
		// A deliberate retry can resume bounded cleanup after device errors.
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_mac_bindings b SET cleanup_attempts=CASE WHEN b.cleanup_attempts=5 THEN 0 ELSE b.cleanup_attempts END,next_cleanup_at=clock_timestamp() FROM mdm_apple_commands c WHERE b.device_id=$1 AND b.cleanup_at IS NULL AND c.id=b.cleanup_command_id AND c.status IN ('failed','expired','cancelled')`, id); err != nil {
			return err
		}
		if err = s.reconcileMacBindingsForDevice(ctx, tx, d); err != nil {
			return err
		}
		if err = audit(ctx, tx, d.TenantID, actor, "apple.mac.binding.cleanup.request", id); err != nil {
			return err
		}
		return tx.Commit()
	}
	challenge := uuid.NewString()
	token, err := randomToken()
	if err != nil {
		return err
	}
	proof := enrollment.MacBindingProof{ChallengeID: challenge, DeviceID: id, Token: token}
	identifier := enrollment.MacBindingDomain + "." + challenge
	profile, err := macBindingProfile(proof, identifier, challenge)
	if err != nil {
		return err
	}
	defer clear(profile)
	command, err := s.enqueue(ctx, tx, d, "InstallProfile", map[string]any{"Payload": profile}, nil, nil)
	if err != nil {
		return err
	}
	expires := time.Now().Add(24 * time.Hour)
	if d.CertificateExpiresAt.Before(expires) {
		expires = d.CertificateExpiresAt
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET expires_at=$2,mac_binding=true WHERE id=$1`, command, expires); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_mac_bindings(id,tenant_id,site_id,device_id,command_id,profile_identifier,profile_uuid,token_hash,expires_at) VALUES($1,$2,$3,$4,$5,$6,$1,$7,$8)`, challenge, d.TenantID, d.SiteID, id, command, identifier, digest([]byte(token)), expires); err != nil {
		return err
	}
	if err = audit(ctx, tx, d.TenantID, actor, "apple.mac.binding.request", challenge); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) CancelMacBinding(ctx context.Context, scope Scope, id, actor string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if scope.Validate() != nil || !enrollment.ValidDeviceID(id) || actor == "" || len(actor) > 255 {
		return ErrMacBinding
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	d, err := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM mdm_apple_devices WHERE id=$1 AND tenant_id=$2 AND ($3=0 OR site_id=$3) FOR UPDATE`, id, scope.TenantID, scope.SiteID))
	if err != nil {
		return err
	}
	if d.Family() != PlatformMacOS {
		return ErrMacBinding
	}
	if err = s.cancelMacBindings(ctx, tx, d); err != nil {
		return err
	}
	if err = s.reconcileMacBindingsForDevice(ctx, tx, d); err != nil {
		return err
	}
	if err = audit(ctx, tx, d.TenantID, actor, "apple.mac.binding.cancel", id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) cancelMacBindings(ctx context.Context, tx *sql.Tx, d *Device) error {
	_, err := tx.ExecContext(ctx, `UPDATE mdm_apple_mac_bindings SET status='cancelled',completed_at=clock_timestamp() WHERE device_id=$1 AND status IN ('queued','installed')`, d.ID)
	return err
}

// Device row locks serialize lifecycle changes with enrollment, delivery and
// association. Each cleanup targets its own unique profile identifier.
func (s *Store) reconcileMacBindingsForDevice(ctx context.Context, tx *sql.Tx, d *Device) error {
	_, err := tx.ExecContext(ctx, `UPDATE mdm_apple_mac_bindings SET status=CASE WHEN $2<>'enrolled' THEN 'cancelled' ELSE 'expired' END,completed_at=clock_timestamp() WHERE device_id=$1 AND status IN ('queued','installed') AND ($2<>'enrolled' OR expires_at<=clock_timestamp() OR $3::timestamptz<=clock_timestamp())`, d.ID, d.Status, d.CertificateExpiresAt)
	if err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT b.id,b.command_id,b.profile_identifier,COALESCE(b.cleanup_command_id::text,''),COALESCE(c.status,''),b.cleanup_attempts,b.next_cleanup_at,source.attempts FROM mdm_apple_mac_bindings b JOIN mdm_apple_commands source ON source.id=b.command_id LEFT JOIN mdm_apple_commands c ON c.id=b.cleanup_command_id WHERE b.device_id=$1 AND b.status NOT IN ('queued','installed') AND b.cleanup_at IS NULL ORDER BY b.created_at LIMIT 10`, d.ID)
	if err != nil {
		return err
	}
	type cleanup struct {
		deliveries                                     int
		id, command, identifier, cleanupCommand, state string
		attempts                                       int
		next                                           time.Time
	}
	pending := []cleanup{}
	for rows.Next() {
		var c cleanup
		if err = rows.Scan(&c.id, &c.command, &c.identifier, &c.cleanupCommand, &c.state, &c.attempts, &c.next, &c.deliveries); err != nil {
			rows.Close()
			return err
		}
		pending = append(pending, c)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, c := range pending {
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET payload=''::bytea,status=CASE WHEN status IN ('queued','sent','not_now') THEN 'cancelled' ELSE status END,completed_at=COALESCE(completed_at,clock_timestamp()) WHERE id=$1`, c.command); err != nil {
			return err
		}
		if c.deliveries == 0 {
			if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_mac_bindings SET cleanup_at=clock_timestamp() WHERE id=$1`, c.id); err != nil {
				return err
			}
			continue
		}
		if d.Status != "enrolled" || !time.Now().Before(d.CertificateExpiresAt) {
			// A withdrawn channel cannot remove a profile; retain that distinction.
			continue
		}
		if c.state == "acknowledged" {
			if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_mac_bindings SET cleanup_at=clock_timestamp() WHERE id=$1`, c.id); err != nil {
				return err
			}
			continue
		}
		if c.state == "queued" || c.state == "sent" || c.state == "not_now" || c.attempts >= 5 || time.Now().Before(c.next) {
			continue
		}
		command, err := s.enqueue(ctx, tx, d, "RemoveProfile", map[string]any{"Identifier": c.identifier}, nil, nil)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET mac_binding=true WHERE id=$1`, command); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_mac_bindings SET cleanup_command_id=$2,cleanup_attempts=cleanup_attempts+1,next_cleanup_at=clock_timestamp()+interval '6 hours' WHERE id=$1`, c.id, command); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) macBindingCommandResult(ctx context.Context, tx *sql.Tx, d *Device, command, state string) error {
	if state == "acknowledged" {
		if _, err := tx.ExecContext(ctx, `UPDATE mdm_apple_mac_bindings SET status='installed',installed_at=clock_timestamp() WHERE command_id=$1 AND device_id=$2 AND status='queued' AND expires_at>clock_timestamp()`, command, d.ID); err != nil {
			return err
		}
	} else if state == "failed" {
		if _, err := tx.ExecContext(ctx, `UPDATE mdm_apple_mac_bindings SET status='failed',completed_at=clock_timestamp() WHERE command_id=$1 AND device_id=$2 AND status IN ('queued','installed')`, command, d.ID); err != nil {
			return err
		}
	}
	return s.reconcileMacBindingsForDevice(ctx, tx, d)
}

func (s *Store) ReconcileMacBindings(ctx context.Context) error {
	// Bound each sweep and revisit offline cleanup at a durable cursor.
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT device_id FROM mdm_apple_mac_bindings WHERE (status IN ('queued','installed') AND expires_at<=clock_timestamp()) OR (status NOT IN ('queued','installed') AND cleanup_at IS NULL AND next_cleanup_at<=clock_timestamp()) ORDER BY device_id LIMIT 25`)
	if err != nil {
		return err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		d, err := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM mdm_apple_devices WHERE id=$1 FOR UPDATE SKIP LOCKED`, id))
		if errors.Is(err, ErrNotFound) {
			tx.Rollback()
			continue
		}
		if err == nil {
			err = s.reconcileMacBindingsForDevice(ctx, tx, d)
		}
		if err == nil {
			_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_mac_bindings SET next_cleanup_at=GREATEST(next_cleanup_at,clock_timestamp()+interval '15 minutes') WHERE device_id=$1 AND status NOT IN ('queued','installed') AND cleanup_at IS NULL`, id)
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

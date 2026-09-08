package apple

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
)

//go:embed maclink_migrations/001_mac_devices.sql
var macLinkSchema string

// MigrateMacLinks is deliberately separate from native MDM migrations: Apple
// installations without an agent registry remain fully usable.
func (s *Store) MigrateMacLinks(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684627925)`); err != nil {
		return err
	}
	var ready, applied bool
	if err = tx.QueryRowContext(ctx, `SELECT to_regclass('uem_agent_hardware') IS NOT NULL,EXISTS(SELECT 1 FROM mdm_apple_migrations WHERE name='maclink_migrations/001_mac_devices.sql')`).Scan(&ready, &applied); err != nil {
		return err
	}
	if !ready {
		return ErrMacBinding
	}
	if !applied {
		if _, err = tx.ExecContext(ctx, macLinkSchema); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_migrations(name) VALUES('maclink_migrations/001_mac_devices.sql')`); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) MacLinksReady(ctx context.Context) bool {
	var ready bool
	err := s.db.QueryRowContext(ctx, `SELECT to_regclass('uem_mac_devices') IS NOT NULL AND to_regclass('uem_mac_agent_channels') IS NOT NULL AND to_regclass('uem_mac_mdm_channels') IS NOT NULL`).Scan(&ready)
	return err == nil && ready
}

func macHardwareMatches(d *Device, h enrollment.HardwareInventory, now time.Time) bool {
	h, err := enrollment.NormalizeHardware(h)
	if err != nil || d.Family() != PlatformMacOS || d.Status != "enrolled" || !now.Before(d.CertificateExpiresAt) || d.InventoryAt == nil || now.Sub(*d.InventoryAt) > 24*time.Hour || d.InventoryAt.After(now.Add(time.Minute)) {
		return false
	}
	if d.Model != h.Model || strings.ToUpper(strings.TrimSpace(d.SerialNumber)) != h.Serial {
		return false
	}
	provision := strings.ToUpper(strings.TrimSpace(stringValue(d.Inventory, "ProvisioningUDID")))
	if provision != "" {
		return h.ProvisioningUDID != "" && provision == h.ProvisioningUDID
	}
	// Legacy Intel fallback requires explicit non-silicon inventory evidence.
	// Never equate an Apple-silicon MDM UDID with a hardware platform UUID.
	return d.AppleSilicon != nil && !*d.AppleSilicon && strings.ToUpper(strings.TrimSpace(d.UDID)) == h.PlatformUUID
}

// ReconcileMacLinks never correlates by serial alone. Only an installed, live
// challenge returned by an active, scoped agent can attach management channels.
func (s *Store) ReconcileMacLinks(ctx context.Context) error {
	if !s.MacLinksReady(ctx) {
		return nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT b.device_id,b.tenant_id,b.site_id FROM mdm_apple_mac_bindings b WHERE b.status='installed' AND b.expires_at>clock_timestamp() AND EXISTS(SELECT 1 FROM uem_agent_hardware h JOIN uem_agent_identities i ON i.id=h.device_id JOIN sites site ON site.id=i.site_id AND site.tenant_sites=i.tenant_id WHERE i.tenant_id=b.tenant_id AND i.site_id=b.site_id AND i.platform='macos' AND i.revoked_at IS NULL AND i.certificate_expires_at>clock_timestamp() AND h.binding_challenge_id=b.id AND h.binding_device_id=b.device_id AND h.binding_token_hash=b.token_hash AND h.tenant_id=b.tenant_id AND h.site_id=b.site_id AND h.observed_at>=b.created_at AND h.observed_at>clock_timestamp()-interval '24 hours') ORDER BY b.created_at,b.id LIMIT 25`)
	if err != nil {
		return err
	}
	type candidate struct {
		id    string
		scope Scope
	}
	list := []candidate{}
	for rows.Next() {
		var c candidate
		if err = rows.Scan(&c.id, &c.scope.TenantID, &c.scope.SiteID); err != nil {
			rows.Close()
			return err
		}
		list = append(list, c)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, c := range list {
		if err = s.reconcileMacLink(ctx, c.scope, c.id); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) reconcileMacLink(ctx context.Context, scope Scope, deviceID string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Serializes competing association/reenrollment decisions in this site.
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684627926,$1::integer)`, scope.SiteID); err != nil {
		return err
	}
	d, err := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM mdm_apple_devices WHERE id=$1 AND tenant_id=$2 AND site_id=$3 FOR UPDATE`, deviceID, scope.TenantID, scope.SiteID))
	if err != nil {
		return err
	}
	var challenge string
	err = tx.QueryRowContext(ctx, `SELECT id FROM mdm_apple_mac_bindings WHERE device_id=$1 AND tenant_id=$2 AND site_id=$3 AND status='installed' AND expires_at>clock_timestamp() FOR UPDATE`, deviceID, scope.TenantID, scope.SiteID).Scan(&challenge)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT i.id FROM uem_agent_identities i JOIN uem_agent_hardware h ON h.device_id=i.id JOIN mdm_apple_mac_bindings b ON b.id=h.binding_challenge_id WHERE b.id=$1 AND h.binding_device_id=b.device_id AND h.binding_token_hash=b.token_hash AND h.tenant_id=b.tenant_id AND h.site_id=b.site_id AND h.observed_at>=b.created_at AND h.observed_at>clock_timestamp()-interval '24 hours' AND i.tenant_id=b.tenant_id AND i.site_id=b.site_id AND i.platform='macos' AND i.revoked_at IS NULL AND i.certificate_expires_at>clock_timestamp() ORDER BY i.id FOR UPDATE OF i LIMIT 3`, challenge)
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
	var siteID int
	if err = tx.QueryRowContext(ctx, `SELECT id FROM sites WHERE id=$1 AND tenant_sites=$2 FOR SHARE`, scope.SiteID, scope.TenantID).Scan(&siteID); errors.Is(err, sql.ErrNoRows) {
		return nil
	} else if err != nil {
		return err
	}
	// Recheck every candidate after acquiring identity locks, including before
	// declaring a conflict. A worker may have cleared an old proof while this
	// transaction was waiting. It locks the identity before its hardware row.
	proofs := []enrollment.HardwareInventory{}
	for _, id := range ids {
		h := enrollment.HardwareInventory{Version: enrollment.HardwareInventoryVersion, AgentID: id}
		err = tx.QueryRowContext(ctx, `SELECT h.model,h.serial,h.platform_uuid,h.provisioning_udid FROM uem_agent_hardware h JOIN uem_agent_identities i ON i.id=h.device_id JOIN mdm_apple_mac_bindings b ON b.id=h.binding_challenge_id WHERE i.id=$1 AND b.id=$2 AND b.status='installed' AND b.expires_at>clock_timestamp() AND h.binding_device_id=b.device_id AND h.binding_token_hash=b.token_hash AND h.tenant_id=b.tenant_id AND h.site_id=b.site_id AND i.tenant_id=b.tenant_id AND i.site_id=b.site_id AND i.platform='macos' AND h.observed_at>=b.created_at AND h.observed_at>clock_timestamp()-interval '24 hours' AND i.certificate_expires_at>clock_timestamp() AND i.revoked_at IS NULL FOR UPDATE OF h`, id, challenge).Scan(&h.Model, &h.Serial, &h.PlatformUUID, &h.ProvisioningUDID)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		proofs = append(proofs, h)
	}
	if len(proofs) == 0 {
		return nil
	}
	if len(proofs) != 1 {
		return s.macLinkConflict(ctx, tx, d, challenge)
	}
	h := proofs[0]
	id := h.AgentID
	if !macHardwareMatches(d, h, time.Now()) {
		return s.macLinkConflict(ctx, tx, d, challenge)
	}
	// Existing legacy inventory must also agree. Missing inventory is allowed:
	// channel metadata comes from the authenticated registry, never an alias row.
	var legacyReady bool
	if err = tx.QueryRowContext(ctx, `SELECT to_regclass('agents') IS NOT NULL AND to_regclass('site_agents') IS NOT NULL`).Scan(&legacyReady); err != nil {
		return err
	}
	if legacyReady {
		var compatible bool
		if err = tx.QueryRowContext(ctx, `SELECT NOT EXISTS(SELECT 1 FROM agents WHERE oid=$1) OR ((SELECT count(*) FROM site_agents WHERE agent_id=$1)=1 AND EXISTS(SELECT 1 FROM site_agents WHERE agent_id=$1 AND site_id=$2))`, id, scope.SiteID).Scan(&compatible); err != nil {
			return err
		}
		if !compatible {
			return s.macLinkConflict(ctx, tx, d, challenge)
		}
	}
	if _, err = tx.ExecContext(ctx, `SAVEPOINT mac_attachment`); err != nil {
		return err
	}
	entity, err := s.attachMacChannels(ctx, tx, d, id, h)
	if errors.Is(err, ErrConflict) {
		if _, err = tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT mac_attachment`); err != nil {
			return err
		}
		return s.macLinkConflict(ctx, tx, d, challenge)
	}
	if err != nil {
		return err
	}
	var active bool
	if err = tx.QueryRowContext(ctx, `SELECT d.status='enrolled' AND d.certificate_expires_at>clock_timestamp() AND i.revoked_at IS NULL AND i.certificate_expires_at>clock_timestamp() AND b.expires_at>clock_timestamp() FROM mdm_apple_devices d JOIN mdm_apple_mac_bindings b ON b.device_id=d.id JOIN uem_agent_identities i ON i.id=$2 WHERE b.id=$1`, challenge, id).Scan(&active); err != nil {
		return err
	}
	if !active {
		return nil
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_mac_bindings SET status='consumed',agent_id=$2,completed_at=clock_timestamp() WHERE id=$1`, challenge, id); err != nil {
		return err
	}
	if err = s.reconcileMacBindingsForDevice(ctx, tx, d); err != nil {
		return err
	}
	if err = audit(ctx, tx, d.TenantID, "mac-link-service", "apple.mac.channels.link", entity); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) macLinkConflict(ctx context.Context, tx *sql.Tx, d *Device, challenge string) error {
	if _, err := tx.ExecContext(ctx, `UPDATE mdm_apple_mac_bindings SET status='conflict',completed_at=clock_timestamp() WHERE id=$1`, challenge); err != nil {
		return err
	}
	if err := s.reconcileMacBindingsForDevice(ctx, tx, d); err != nil {
		return err
	}
	if err := auditOutcome(ctx, tx, d.TenantID, "mac-link-service", "apple.mac.channels.conflict", challenge, "denied"); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) attachMacChannels(ctx context.Context, tx *sql.Tx, d *Device, agentID string, h enrollment.HardwareInventory) (string, error) {
	var nativeEntity, agentEntity string
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT entity_id::text FROM uem_mac_mdm_channels WHERE device_id=$1),''),COALESCE((SELECT entity_id::text FROM uem_mac_agent_channels WHERE device_id=$2),'')`, d.ID, agentID).Scan(&nativeEntity, &agentEntity); err != nil {
		return "", err
	}
	if nativeEntity != "" && agentEntity != "" && nativeEntity != agentEntity {
		return "", ErrConflict
	}
	entity := nativeEntity
	if entity == "" {
		entity = agentEntity
	}
	if entity == "" {
		// Re-enrollment of both channels may have no source ID in common. Match a
		// complete hardware record only after fresh two-channel proof, and still
		// require every previous channel to have been explicitly withdrawn.
		rows, err := tx.QueryContext(ctx, `SELECT id FROM uem_mac_devices WHERE tenant_id=$1 AND site_id=$2 AND platform_uuid=$3 ORDER BY id LIMIT 2 FOR UPDATE`, d.TenantID, d.SiteID, h.PlatformUUID)
		if err != nil {
			return "", err
		}
		matches := []string{}
		for rows.Next() {
			var match string
			if err = rows.Scan(&match); err != nil {
				rows.Close()
				return "", err
			}
			matches = append(matches, match)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return "", err
		}
		if len(matches) > 1 {
			return "", ErrConflict
		}
		if len(matches) == 1 {
			entity = matches[0]
		}
	}
	if entity == "" {
		entity = uuid.NewString()
		if _, err := tx.ExecContext(ctx, `INSERT INTO uem_mac_devices(id,tenant_id,site_id,model,serial,platform_uuid,provisioning_udid) VALUES($1,$2,$3,$4,$5,$6,$7)`, entity, d.TenantID, d.SiteID, h.Model, h.Serial, h.PlatformUUID, h.ProvisioningUDID); err != nil {
			return "", err
		}
	} else {
		var valid bool
		if err := tx.QueryRowContext(ctx, `SELECT model=$4 AND serial=$5 AND platform_uuid=$6 AND provisioning_udid=$7 FROM uem_mac_devices WHERE id=$1 AND tenant_id=$2 AND site_id=$3 FOR UPDATE`, entity, d.TenantID, d.SiteID, h.Model, h.Serial, h.PlatformUUID, h.ProvisioningUDID).Scan(&valid); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return "", ErrConflict
			}
			return "", err
		}
		if !valid {
			return "", ErrConflict
		}
	}
	var currentMDM, currentAgent string
	var mdmLive, agentLive bool
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT device_id::text FROM uem_mac_mdm_channels WHERE entity_id=$1 AND retired_at IS NULL),''),COALESCE((SELECT device_id::text FROM uem_mac_agent_channels WHERE entity_id=$1 AND retired_at IS NULL),'')`, entity).Scan(&currentMDM, &currentAgent); err != nil {
		return "", err
	}
	if currentMDM != "" && currentMDM != d.ID {
		if err := tx.QueryRowContext(ctx, `SELECT status IN ('authenticating','enrolled') FROM mdm_apple_devices WHERE id=$1 FOR UPDATE`, currentMDM).Scan(&mdmLive); err != nil {
			return "", err
		}
		if mdmLive {
			return "", ErrConflict
		}
	}
	if currentAgent != "" && currentAgent != agentID {
		if err := tx.QueryRowContext(ctx, `SELECT revoked_at IS NULL FROM uem_agent_identities WHERE id=$1 FOR UPDATE`, currentAgent).Scan(&agentLive); err != nil {
			return "", err
		}
		if agentLive {
			return "", ErrConflict
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE uem_mac_mdm_channels SET retired_at=clock_timestamp() WHERE entity_id=$1 AND retired_at IS NULL AND device_id<>$2`, entity, d.ID); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE uem_mac_agent_channels SET retired_at=clock_timestamp() WHERE entity_id=$1 AND retired_at IS NULL AND device_id<>$2`, entity, agentID); err != nil {
		return "", err
	}
	// A previously retired source is never revived implicitly.
	var retired bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_mac_mdm_channels WHERE device_id=$1 AND retired_at IS NOT NULL) OR EXISTS(SELECT 1 FROM uem_mac_agent_channels WHERE device_id=$2 AND retired_at IS NOT NULL)`, d.ID, agentID).Scan(&retired); err != nil {
		return "", err
	}
	if retired {
		return "", ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO uem_mac_mdm_channels(device_id,entity_id,tenant_id,site_id) VALUES($1,$2,$3,$4) ON CONFLICT(device_id) DO NOTHING`, d.ID, entity, d.TenantID, d.SiteID); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO uem_mac_agent_channels(device_id,entity_id,tenant_id,site_id) VALUES($1,$2,$3,$4) ON CONFLICT(device_id) DO NOTHING`, agentID, entity, d.TenantID, d.SiteID); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE uem_mac_devices SET updated_at=clock_timestamp() WHERE id=$1`, entity); err != nil {
		return "", err
	}
	return entity, nil
}

package apple

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// ScheduleInventory keeps inventory current even if an administrator never opens
// a device page. The next-at cursor avoids starvation behind offline devices.
func (s *Store) ScheduleInventory(ctx context.Context) error {
	for i := 0; i < 25; i++ {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		d, err := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM mdm_apple_devices WHERE status='enrolled' AND next_inventory_at<=now() ORDER BY next_inventory_at,id LIMIT 1 FOR UPDATE SKIP LOCKED`))
		if errors.Is(err, ErrNotFound) {
			tx.Rollback()
			return nil
		}
		if err != nil {
			tx.Rollback()
			return err
		}
		if err = s.queueInventory(ctx, tx, d); err != nil {
			tx.Rollback()
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_devices SET next_inventory_at=now()+interval '6 hours' WHERE id=$1`, d.ID); err != nil {
			tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) expireCommands(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET status='expired',error='Command expired before completion',completed_at=now() WHERE expires_at<=now() AND status IN ('queued','sent','not_now')`)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_profile_assignments a SET status='failed',error='Command expired before completion',updated_at=now() WHERE status IN ('pending','deferred') AND EXISTS(SELECT 1 FROM mdm_apple_commands c WHERE c.device_id=a.device_id AND c.profile_id=a.profile_id AND c.profile_revision=a.revision AND c.status='expired') AND NOT EXISTS(SELECT 1 FROM mdm_apple_commands c WHERE c.device_id=a.device_id AND c.profile_id=a.profile_id AND c.profile_revision=a.revision AND c.status IN ('queued','sent','not_now'))`)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET payload='\x' WHERE (filevault OR recovery_lock OR mac_admin) AND status NOT IN ('queued','sent','not_now') AND octet_length(payload)>0`); err != nil {
		return err
	}
	return tx.Commit()
}

// ReconcileUpdateAvailability withdraws releases Apple no longer offers and
// restores the declaration if they become available again. Desired policy data
// stays in the console so administrators can choose a replacement release.
func (s *Store) ReconcileUpdateAvailability(ctx context.Context) error {
	catalog, fetched, err := s.Catalog(ctx)
	if err != nil {
		return err
	}
	if fetched == nil || time.Since(*fetched) > 48*time.Hour {
		catalog = nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT device_id,tenant_id FROM mdm_apple_update_policies ORDER BY device_id`)
	if err != nil {
		return err
	}
	type target struct {
		id     string
		tenant int
	}
	targets := []target{}
	for rows.Next() {
		var t target
		if err = rows.Scan(&t.id, &t.tenant); err != nil {
			rows.Close()
			return err
		}
		targets = append(targets, t)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, t := range targets {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		err = s.reconcileUpdate(ctx, tx, catalog, t.id, t.tenant)
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

func (s *Store) reconcileUpdate(ctx context.Context, tx *sql.Tx, catalog *SoftwareCatalog, id string, tenant int) error {
	d, err := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM mdm_apple_devices WHERE id=$1 AND tenant_id=$2 FOR UPDATE`, id, tenant))
	if err != nil {
		return err
	}
	if d.Status != "enrolled" {
		return nil
	}
	p, err := scanPolicy(tx.QueryRowContext(ctx, `SELECT `+policyColumns+` FROM mdm_apple_update_policies WHERE device_id=$1 FOR UPDATE`, id))
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	capabilities := d.Capabilities()
	ready := capabilities.SpecificOSUpdate && capabilities.UpdateReason == ""
	// Stale catalog data cannot restore a withdrawn policy, but must not
	// prevent withdrawal when device authorization becomes unavailable.
	if catalog == nil && ready {
		return nil
	}
	available := ready && catalog != nil && catalog.Supports(*d, *p, time.Now())
	if available && p.Status != "unavailable" {
		return nil
	}
	status, detail := "pending", ""
	if !available {
		status = "unavailable"
		detail = "Apple no longer offers the selected release for this model. Choose another release."
		if reason := d.Capabilities().UpdateReason; reason != "" {
			detail = reason
		}
	}
	if p.Status == status && p.Error == detail {
		return nil
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_update_policies SET status=$1,error=$2,updated_at=now() WHERE device_id=$3`, status, detail, id); err != nil {
		return err
	}
	p.Status = status
	return s.queueDeclarations(ctx, tx, d, p)
}

// Capability changes reconcile in the same transaction as inventory or escrow.
// A lost token must not wait for a catalog refresh to withdraw authorization.
func (s *Store) reconcileDeviceUpdate(ctx context.Context, tx *sql.Tx, d *Device) error {
	var assigned bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mdm_apple_update_policies WHERE device_id=$1 AND tenant_id=$2)`, d.ID, d.TenantID).Scan(&assigned); err != nil {
		return err
	}
	if !assigned {
		return nil
	}
	var data []byte
	var fetched *time.Time
	if err := tx.QueryRowContext(ctx, `SELECT document,fetched_at FROM mdm_apple_software_catalog WHERE singleton=true`).Scan(&data, &fetched); err != nil {
		return err
	}
	var catalog *SoftwareCatalog
	if fetched != nil && time.Since(*fetched) <= 48*time.Hour {
		if err := json.Unmarshal(data, &catalog); err != nil {
			return err
		}
	}
	return s.reconcileUpdate(ctx, tx, catalog, d.ID, d.TenantID)
}

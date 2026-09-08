package apple

import "context"

// RevokeEnrollment immediately invalidates an invitation or device identity and
// stops queued work. It does not remove the on-device MDM profile or erase data.
// A new enrollment uses a new identity and retains this record as history.
func (s *Store) RevokeEnrollment(ctx context.Context, scope Scope, id, actor string) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var state string
	if err = tx.QueryRowContext(ctx, `SELECT status FROM mdm_apple_devices WHERE id=$1 AND tenant_id=$2 AND ($3=0 OR site_id=$3) FOR UPDATE`, id, scope.TenantID, scope.SiteID).Scan(&state); err != nil {
		return notFound(err)
	}
	if state == "revoked" {
		return tx.Commit()
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_devices SET status='revoked',invite_hash=NULL,push_token=NULL,push_magic=NULL,push_status='cancelled',push_error='' WHERE id=$1`, id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET status='cancelled',completed_at=now() WHERE device_id=$1 AND status IN ('queued','sent','not_now')`, id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_profile_assignments SET status='not_managed',updated_at=now() WHERE device_id=$1`, id); err != nil {
		return err
	}
	if err = s.cancelDeviceRenewal(ctx, tx, &Device{ID: id, TenantID: scope.TenantID}); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM mdm_apple_bootstrap_tokens WHERE device_id=$1`, id); err != nil {
		return err
	}
	if err = s.withdrawUserChannels(ctx, tx, &Device{ID: id, TenantID: scope.TenantID}); err != nil {
		return err
	}
	if err = s.reconcileMacBindingsForDevice(ctx, tx, &Device{ID: id, TenantID: scope.TenantID, Status: "revoked"}); err != nil {
		return err
	}
	if err = s.reconcileFileVault(ctx, tx, &Device{ID: id, TenantID: scope.TenantID, Status: "revoked"}); err != nil {
		return err
	}
	if err = s.reconcileRecoveryLock(ctx, tx, &Device{ID: id, TenantID: scope.TenantID}, false); err != nil {
		return err
	}
	if err = audit(ctx, tx, scope.TenantID, actor, "apple.enrollment.revoke", id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_enrollment_claims SET profile=NULL WHERE device_id=$1`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// ScopeInUse protects the console's existing organization/site deletion flows
// from orphaning Apple identities, profiles and inventory.
func (s *Store) ScopeInUse(ctx context.Context, scope Scope) (bool, error) {
	if err := scope.Validate(); err != nil {
		return false, err
	}
	var exists bool
	if scope.SiteID == 0 {
		err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mdm_apple_settings WHERE tenant_id=$1)`, scope.TenantID).Scan(&exists)
		return exists, err
	}
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mdm_apple_devices WHERE tenant_id=$1 AND site_id=$2)`, scope.TenantID, scope.SiteID).Scan(&exists)
	return exists, err
}

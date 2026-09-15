package apple

import (
	"context"
	"errors"
)

func (s *Store) PauseUserManagement(ctx context.Context, scope Scope, deviceID, userID, actor string) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, u, err := s.lockScopedUser(ctx, tx, scope, deviceID, userID)
	if err != nil {
		return err
	}
	if u.Status == "not_managed" {
		return errors.New("user enrollment has ended")
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_users SET status='blocked',push_token=NULL,push_magic=NULL,push_status='cancelled',push_error='' WHERE id=$1`, u.ID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_user_commands SET status='cancelled',payload=''::bytea,completed_at=clock_timestamp() WHERE user_channel_id=$1 AND status IN ('queued','sent','not_now')`, u.ID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM mdm_apple_user_renewal_tokens WHERE user_channel_id=$1`, u.ID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_user_assignments SET status='not_managed',error='',updated_at=clock_timestamp() WHERE user_channel_id=$1`, u.ID); err != nil {
		return err
	}
	if err = audit(ctx, tx, u.TenantID, actor, "apple.user.pause", u.ID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ResumeUserManagement(ctx context.Context, scope Scope, deviceID, userID, actor string) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	u, err := s.User(ctx, scope, deviceID, userID)
	if err != nil {
		return err
	}
	if u.Status != "blocked" {
		return errors.New("only a paused user channel can be resumed")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// While blocked, new assignments are rejected. Catalog revisions can still
	// change, so lock and reload each desired profile before locking the parent.
	rows, err := tx.QueryContext(ctx, `SELECT profile_id,desired FROM mdm_apple_user_assignments WHERE user_channel_id=$1 ORDER BY profile_id`, u.ID)
	if err != nil {
		return err
	}
	type assignment struct {
		id, desired string
		profile     *Profile
	}
	assignments := []assignment{}
	for rows.Next() {
		var a assignment
		if err = rows.Scan(&a.id, &a.desired); err != nil {
			rows.Close()
			return err
		}
		assignments = append(assignments, a)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for i := range assignments {
		assignments[i].profile, err = s.scanProfile(tx.QueryRowContext(ctx, `SELECT `+profileColumns+` FROM mdm_apple_profiles WHERE id=$1 AND tenant_id=$2 FOR UPDATE`, assignments[i].id, scope.TenantID))
		if err != nil {
			return err
		}
	}
	d, u, err := s.lockScopedUser(ctx, tx, scope, deviceID, userID)
	if err != nil {
		return err
	}
	if u.Status != "blocked" {
		return ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_users SET status='pending',push_status='pending',push_error='' WHERE id=$1`, u.ID); err != nil {
		return err
	}
	for _, a := range assignments {
		if err = s.assignUserProfile(ctx, tx, d, u, a.profile, a.desired); err != nil {
			return err
		}
	}
	if err = audit(ctx, tx, u.TenantID, actor, "apple.user.resume", u.ID); err != nil {
		return err
	}
	return tx.Commit()
}

package apple

import (
	"context"
	"database/sql"
	"errors"
)

// Profile writers take the catalog row before the native enrollment and user
// rows. Protocol and maintenance transactions never lock the catalog row.
func (s *Store) lockScopedUser(ctx context.Context, tx *sql.Tx, scope Scope, deviceID, userID string) (*Device, *UserChannel, error) {
	d, err := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM mdm_apple_devices WHERE tenant_id=$1 AND ($2=0 OR site_id=$2) AND id=$3 FOR UPDATE`, scope.TenantID, scope.SiteID, deviceID))
	if err != nil {
		return nil, nil, err
	}
	if d.Status != "enrolled" || !d.Capabilities().UserChannel {
		return nil, nil, errors.New("user management requires an enrolled Mac with per-user connections")
	}
	var site int
	if err = tx.QueryRowContext(ctx, `SELECT id FROM sites WHERE id=$1 AND tenant_sites=$2 FOR SHARE`, d.SiteID, d.TenantID).Scan(&site); err != nil {
		return nil, nil, notFound(err)
	}
	u, err := scanUser(tx.QueryRowContext(ctx, `SELECT `+userColumns+` FROM mdm_apple_users WHERE id=$1 AND device_id=$2 AND tenant_id=$3 FOR UPDATE`, userID, d.ID, d.TenantID))
	if err != nil {
		return nil, nil, err
	}
	return d, u, nil
}

func (s *Store) lockManagedUser(ctx context.Context, tx *sql.Tx, scope Scope, deviceID, userID string) (*Device, *UserChannel, error) {
	d, u, err := s.lockScopedUser(ctx, tx, scope, deviceID, userID)
	if err != nil {
		return nil, nil, err
	}
	if u.Status != "enrolled" {
		return nil, nil, errors.New("user channel is not enrolled")
	}
	return d, u, nil
}

func (s *Store) assignUserProfile(ctx context.Context, tx *sql.Tx, d *Device, u *UserChannel, p *Profile, desired string) error {
	if p.Scope != "User" {
		return errors.New("select a User profile for this user channel")
	}
	if desired == "installed" {
		if err := validateUserProfile(p, d); err != nil {
			return err
		}
	}
	if desired == "installed" {
		if err := s.reserveACMEClients(ctx, tx, d, p); err != nil {
			return err
		}
		if err := s.reserveSSORoutes(ctx, tx, d, u.ID, p); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE mdm_apple_user_commands SET status='cancelled',payload=''::bytea,completed_at=clock_timestamp() WHERE user_channel_id=$1 AND profile_id=$2 AND status IN ('queued','sent','not_now')`, u.ID, p.ID); err != nil {
		return err
	}
	kind, args := "InstallProfile", map[string]any{"Payload": p.Payload}
	if desired == "removed" {
		kind, args = "RemoveProfile", map[string]any{"Identifier": p.Identifier}
	}
	commandID, err := s.enqueueUserCommand(ctx, tx, u, kind, args, p.ID, p.Revision)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_user_assignments(tenant_id,device_id,user_channel_id,profile_id,command_id,revision,desired) VALUES($1,$2,$3,$4,$5,$6,$7)
 ON CONFLICT(user_channel_id,profile_id) DO UPDATE SET command_id=excluded.command_id,revision=excluded.revision,desired=excluded.desired,status='pending',error='',updated_at=clock_timestamp()`, u.TenantID, u.DeviceID, u.ID, p.ID, commandID, p.Revision, desired)
	if err != nil {
		return err
	}
	return s.resetUserProfileInventory(ctx, tx, u)
}

func (s *Store) AssignUserProfile(ctx context.Context, scope Scope, deviceID, userID, profileID, desired, actor string) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	if desired != "installed" && desired != "removed" {
		return errors.New("invalid user profile assignment")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	p, err := s.scanProfile(tx.QueryRowContext(ctx, `SELECT `+profileColumns+` FROM mdm_apple_profiles WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, scope.TenantID, profileID))
	if err != nil {
		return err
	}
	d, u, err := s.lockManagedUser(ctx, tx, scope, deviceID, userID)
	if err != nil {
		return err
	}
	if err = s.assignUserProfile(ctx, tx, d, u, p, desired); err != nil {
		return err
	}
	if err = audit(ctx, tx, u.TenantID, actor, "apple.user.profile."+desired, u.ID+"/"+p.ID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) updateUserProfileAssignments(ctx context.Context, tx *sql.Tx, p *Profile) error {
	rows, err := tx.QueryContext(ctx, `SELECT u.device_id,u.id,u.site_id FROM mdm_apple_user_assignments a JOIN mdm_apple_users u ON u.id=a.user_channel_id JOIN mdm_apple_devices d ON d.id=u.device_id WHERE a.profile_id=$1 AND a.desired='installed' AND u.status='enrolled' AND d.status='enrolled' ORDER BY u.device_id,u.id`, p.ID)
	if err != nil {
		return err
	}
	type target struct {
		device, user string
		site         int
	}
	targets := []target{}
	for rows.Next() {
		var t target
		if err = rows.Scan(&t.device, &t.user, &t.site); err != nil {
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
		d, u, err := s.lockManagedUser(ctx, tx, Scope{TenantID: p.TenantID, SiteID: t.site}, t.device, t.user)
		if err != nil {
			return err
		}
		if err = s.assignUserProfile(ctx, tx, d, u, p, "installed"); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) UserAssignments(ctx context.Context, scope Scope, deviceID, userID string) ([]Assignment, error) {
	u, err := s.User(ctx, scope, deviceID, userID)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT a.profile_id,a.device_id,p.name,a.revision,a.desired,a.status,a.error,a.updated_at FROM mdm_apple_user_assignments a JOIN mdm_apple_profiles p ON p.id=a.profile_id WHERE a.tenant_id=$1 AND a.user_channel_id=$2 AND a.device_id=$3 ORDER BY p.name,p.id`, u.TenantID, u.ID, u.DeviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []Assignment{}
	for rows.Next() {
		var a Assignment
		if err = rows.Scan(&a.ProfileID, &a.DeviceID, &a.Name, &a.Revision, &a.Desired, &a.Status, &a.Error, &a.UpdatedAt); err != nil {
			return nil, err
		}
		list = append(list, a)
	}
	return list, rows.Err()
}

// A retry creates a new UUID from current desired state; it never reuses a
// terminal command's erased payload or replays a superseded profile revision.
func (s *Store) RetryUserCommand(ctx context.Context, scope Scope, deviceID, userID, commandID, actor string) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	if _, err := s.User(ctx, scope, deviceID, userID); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var profileID sql.NullString
	if err = tx.QueryRowContext(ctx, `SELECT profile_id FROM mdm_apple_user_commands WHERE id=$1 AND tenant_id=$2 AND device_id=$3 AND user_channel_id=$4`, commandID, scope.TenantID, deviceID, userID).Scan(&profileID); err != nil {
		return notFound(err)
	}
	var p *Profile
	if profileID.Valid {
		p, err = s.scanProfile(tx.QueryRowContext(ctx, `SELECT `+profileColumns+` FROM mdm_apple_profiles WHERE id=$1 AND tenant_id=$2 FOR UPDATE`, profileID.String, scope.TenantID))
		if err != nil {
			return err
		}
	}
	d, u, err := s.lockManagedUser(ctx, tx, scope, deviceID, userID)
	if err != nil {
		return err
	}
	var status, kind string
	if err = tx.QueryRowContext(ctx, `SELECT status,request_type FROM mdm_apple_user_commands WHERE id=$1 AND user_channel_id=$2 FOR UPDATE`, commandID, u.ID).Scan(&status, &kind); err != nil {
		return notFound(err)
	}
	if status != "failed" && status != "expired" {
		return errors.New("only failed or expired user commands can be retried")
	}
	if p != nil {
		var desired string
		if err = tx.QueryRowContext(ctx, `SELECT desired FROM mdm_apple_user_assignments WHERE user_channel_id=$1 AND profile_id=$2 AND command_id=$3 AND revision=$4`, u.ID, p.ID, commandID, p.Revision).Scan(&desired); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return errors.New("user command was superseded by a newer assignment")
			}
			return err
		}
		if err = s.assignUserProfile(ctx, tx, d, u, p, desired); err != nil {
			return err
		}
	} else if kind == "ProfileList" {
		if err = s.resetUserProfileInventory(ctx, tx, u); err != nil {
			return err
		}
	} else {
		return errors.New("user command no longer has an assigned profile")
	}
	if err = audit(ctx, tx, u.TenantID, actor, "apple.user.command.retry", commandID); err != nil {
		return err
	}
	return tx.Commit()
}

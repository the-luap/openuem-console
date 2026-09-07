package apple

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
)

const profileColumns = `id,tenant_id,name,identifier,payload_uuid,revision,payload_types,payload,updated_at`

func (s *Store) scanProfile(row scanner) (*Profile, error) {
	var p Profile
	var types []byte
	err := row.Scan(&p.ID, &p.TenantID, &p.Name, &p.Identifier, &p.UUID, &p.Revision, &types, &p.Payload, &p.UpdatedAt)
	if err != nil {
		return nil, notFound(err)
	}
	if err = json.Unmarshal(types, &p.PayloadTypes); err != nil {
		return nil, err
	}
	p.Payload, err = s.secrets.open(p.Payload, secretPurpose(p.TenantID, p.ID, "profile"))
	return &p, err
}

func (s *Store) Profile(ctx context.Context, tenant int, id string) (*Profile, error) {
	return s.scanProfile(s.db.QueryRowContext(ctx, `SELECT `+profileColumns+` FROM mdm_apple_profiles WHERE tenant_id=$1 AND id=$2`, tenant, id))
}

func (s *Store) Profiles(ctx context.Context, tenant int) ([]Profile, error) {
	if tenant <= 0 {
		return nil, errors.New("select an organization")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+profileColumns+` FROM mdm_apple_profiles WHERE tenant_id=$1 ORDER BY name,id`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	profiles := []Profile{}
	for rows.Next() {
		p, err := s.scanProfile(rows)
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, *p)
	}
	return profiles, rows.Err()
}

// SaveProfile updates all existing installed assignments atomically. The expected
// revision prevents one browser tab from overwriting another administrator's edit.
func (s *Store) SaveProfile(ctx context.Context, tenant int, id string, expectedRevision int, data []byte, actor string) (*Profile, error) {
	if tenant <= 0 {
		return nil, errors.New("select an organization")
	}
	p, err := ParseProfile(data)
	if err != nil {
		return nil, err
	}
	p.TenantID = tenant
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if id != "" {
		old, err := s.scanProfile(tx.QueryRowContext(ctx, `SELECT `+profileColumns+` FROM mdm_apple_profiles WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, id))
		if err != nil {
			return nil, err
		}
		if old.Revision != expectedRevision {
			return nil, ErrConflict
		}
		if old.Identifier != p.Identifier {
			return nil, errors.New("profile identifier cannot change; create a new profile instead")
		}
		p.ID = id
		p.Revision = old.Revision + 1
	}
	encrypted, err := s.secrets.seal(p.Payload, secretPurpose(tenant, p.ID, "profile"))
	if err != nil {
		return nil, err
	}
	types, err := json.Marshal(p.PayloadTypes)
	if err != nil {
		return nil, err
	}
	if id == "" {
		err = tx.QueryRowContext(ctx, `INSERT INTO mdm_apple_profiles(id,tenant_id,name,identifier,payload_uuid,revision,payload_types,payload) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING updated_at`, p.ID, tenant, p.Name, p.Identifier, p.UUID, p.Revision, types, encrypted).Scan(&p.UpdatedAt)
	} else {
		err = tx.QueryRowContext(ctx, `UPDATE mdm_apple_profiles SET name=$1,payload_uuid=$2,revision=$3,payload_types=$4,payload=$5,updated_at=now() WHERE tenant_id=$6 AND id=$7 RETURNING updated_at`, p.Name, p.UUID, p.Revision, types, encrypted, tenant, p.ID).Scan(&p.UpdatedAt)
	}
	if err != nil {
		return nil, err
	}
	if id != "" {
		rows, err := tx.QueryContext(ctx, `SELECT d.id,d.site_id FROM mdm_apple_devices d JOIN mdm_apple_profile_assignments a ON a.device_id=d.id WHERE a.profile_id=$1 AND a.desired='installed' AND d.status='enrolled' ORDER BY d.id`, p.ID)
		if err != nil {
			return nil, err
		}
		devices := []Device{}
		for rows.Next() {
			d := Device{TenantID: tenant}
			if err = rows.Scan(&d.ID, &d.SiteID); err != nil {
				rows.Close()
				return nil, err
			}
			devices = append(devices, d)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
		for i := range devices {
			if err = s.assign(ctx, tx, &devices[i], p, "installed"); err != nil {
				return nil, err
			}
		}
	}
	if err = audit(ctx, tx, tenant, actor, "apple.profile.save", p.ID); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return p, nil
}

func (s *Store) assign(ctx context.Context, tx *sql.Tx, d *Device, p *Profile, desired string) error {
	var state string
	if err := tx.QueryRowContext(ctx, `SELECT status FROM mdm_apple_devices WHERE id=$1 AND tenant_id=$2 FOR UPDATE`, d.ID, d.TenantID).Scan(&state); err != nil {
		return notFound(err)
	}
	if state != "enrolled" {
		return errors.New("device is no longer enrolled")
	}
	// Cancel previous queued/sent work so stale responses cannot reverse the new
	// desired state. A new assignment always replaces all commands for this pair.
	if _, err := tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET status='cancelled',completed_at=now() WHERE device_id=$1 AND profile_id=$2 AND status IN ('queued','sent','not_now')`, d.ID, p.ID); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO mdm_apple_profile_assignments(tenant_id,profile_id,device_id,revision,desired) VALUES($1,$2,$3,$4,$5) ON CONFLICT(profile_id,device_id) DO UPDATE SET revision=excluded.revision,desired=excluded.desired,status='pending',error='',updated_at=now()`, d.TenantID, p.ID, d.ID, p.Revision, desired)
	if err != nil {
		return err
	}
	kind := "InstallProfile"
	args := map[string]any{"Payload": p.Payload}
	if desired == "removed" {
		kind = "RemoveProfile"
		args = map[string]any{"Identifier": p.Identifier}
	}
	_, err = s.enqueue(ctx, tx, d, kind, args, p.ID, p.Revision)
	return err
}

func (s *Store) AssignProfile(ctx context.Context, scope Scope, id string, deviceIDs []string, desired, actor string) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	if len(deviceIDs) == 0 || len(deviceIDs) > 1000 {
		return errors.New("select between 1 and 1000 devices")
	}
	if desired != "installed" && desired != "removed" {
		return errors.New("invalid profile assignment")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	p, err := s.scanProfile(tx.QueryRowContext(ctx, `SELECT `+profileColumns+` FROM mdm_apple_profiles WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, scope.TenantID, id))
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	deviceIDs = slices.Clone(deviceIDs)
	slices.Sort(deviceIDs)
	for _, deviceID := range deviceIDs {
		if seen[deviceID] {
			continue
		}
		seen[deviceID] = true
		d, err := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM mdm_apple_devices WHERE tenant_id=$1 AND ($2=0 OR site_id=$2) AND id=$3 FOR UPDATE`, scope.TenantID, scope.SiteID, deviceID))
		if err != nil {
			return err
		}
		if d.Status != "enrolled" {
			return errors.New("all selected devices must be enrolled")
		}
		if err = s.assign(ctx, tx, d, p, desired); err != nil {
			return err
		}
		if err = audit(ctx, tx, scope.TenantID, actor, "apple.profile."+desired, id+"/"+deviceID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) Assignments(ctx context.Context, scope Scope, id string) ([]Assignment, error) {
	if _, err := s.Device(ctx, scope, id); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT a.profile_id,a.device_id,p.name,a.revision,a.desired,a.status,a.error,a.updated_at FROM mdm_apple_profile_assignments a JOIN mdm_apple_profiles p ON p.id=a.profile_id WHERE a.tenant_id=$1 AND a.device_id=$2 ORDER BY p.name`, scope.TenantID, id)
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

func (s *Store) DeleteProfile(ctx context.Context, tenant int, id, actor string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var found string
	if err = tx.QueryRowContext(ctx, `SELECT id FROM mdm_apple_profiles WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, id).Scan(&found); err != nil {
		return notFound(err)
	}
	var assigned bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mdm_apple_profile_assignments a JOIN mdm_apple_devices d ON d.id=a.device_id WHERE a.profile_id=$1 AND d.status='enrolled' AND (a.desired<>'removed' OR a.status<>'verified'))`, id).Scan(&assigned); err != nil {
		return err
	}
	if assigned {
		return errors.New("remove and verify this profile on all devices before deleting it")
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM mdm_apple_profile_assignments WHERE profile_id=$1`, id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET profile_id=NULL,profile_revision=NULL WHERE profile_id=$1`, id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM mdm_apple_profiles WHERE id=$1 AND tenant_id=$2`, id, tenant); err != nil {
		return err
	}
	if err = audit(ctx, tx, tenant, actor, "apple.profile.delete", id); err != nil {
		return err
	}
	return tx.Commit()
}

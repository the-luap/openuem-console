package apple

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
)

func scanPolicy(row scanner) (*UpdatePolicy, error) {
	var p UpdatePolicy
	err := row.Scan(&p.DeviceID, &p.TargetVersion, &p.TargetBuild, &p.Deadline, &p.DetailsURL, &p.Status, &p.Error, &p.UpdatedAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &p, nil
}

const policyColumns = `device_id,target_version,target_build,deadline,details_url,status,error,updated_at`

func (s *Store) UpdatePolicy(ctx context.Context, scope Scope, id string) (*UpdatePolicy, error) {
	if _, err := s.Device(ctx, scope, id); err != nil {
		return nil, err
	}
	return scanPolicy(s.db.QueryRowContext(ctx, `SELECT `+policyColumns+` FROM mdm_apple_update_policies WHERE tenant_id=$1 AND device_id=$2`, scope.TenantID, id))
}

func (s *Store) SetUpdatePolicy(ctx context.Context, scope Scope, ids []string, p *UpdatePolicy, actor string) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	if len(ids) == 0 || len(ids) > 1000 {
		return errors.New("select between 1 and 1000 devices")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// A consistent lock order avoids deadlocks between overlapping bulk actions.
	ids = slices.Clone(ids)
	slices.Sort(ids)
	for _, id := range slices.Compact(ids) {
		d, err := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM mdm_apple_devices WHERE tenant_id=$1 AND ($2=0 OR site_id=$2) AND id=$3 FOR UPDATE`, scope.TenantID, scope.SiteID, id))
		if err != nil {
			return err
		}
		if d.Status != "enrolled" {
			return errors.New("device must be enrolled")
		}
		if p != nil {
			if err = ValidateUpdatePolicy(*d, *p); err != nil {
				return err
			}
			if err = s.validateCatalogPolicy(ctx, tx, d, p); err != nil {
				return err
			}
			_, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_update_policies(tenant_id,device_id,target_version,target_build,deadline,details_url) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(device_id) DO UPDATE SET target_version=excluded.target_version,target_build=excluded.target_build,deadline=excluded.deadline,details_url=excluded.details_url,status='pending',error='',updated_at=now()`, scope.TenantID, id, p.TargetVersion, p.TargetBuild, p.Deadline, p.DetailsURL)
		} else {
			_, err = tx.ExecContext(ctx, `DELETE FROM mdm_apple_update_policies WHERE tenant_id=$1 AND device_id=$2`, scope.TenantID, id)
		}
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET status='cancelled',completed_at=now() WHERE device_id=$1 AND request_type='DeclarativeManagement' AND status IN ('queued','sent','not_now')`, id); err != nil {
			return err
		}
		data, err := json.Marshal(Tokens(Declarations(*d, p)))
		if err != nil {
			return err
		}
		if _, err = s.enqueue(ctx, tx, d, "DeclarativeManagement", map[string]any{"Data": data}, nil, nil); err != nil {
			return err
		}
		if err = audit(ctx, tx, scope.TenantID, actor, "apple.update.policy", id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) DeclarativeManagement(ctx context.Context, d *Device, message map[string]any) (any, error) {
	if d.Status != "enrolled" || d.UDID == "" || stringValue(message, "UDID") != d.UDID {
		return nil, ErrUnauthorized
	}
	endpoint := stringValue(message, "Endpoint")
	if endpoint == "status" {
		data, ok := message["Data"].([]byte)
		if !ok {
			return nil, errors.New("DDM status requires JSON Data")
		}
		report, err := ParseStatus(data)
		if err != nil {
			return nil, err
		}
		return nil, s.saveStatus(ctx, d, report)
	}
	p, err := s.UpdatePolicy(ctx, Scope{TenantID: d.TenantID, SiteID: d.SiteID}, d.ID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	return DeclarationResponse(Declarations(*d, p), endpoint)
}

func (s *Store) saveStatus(ctx context.Context, d *Device, report *StatusReport) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var old []byte
	var state string
	if err = tx.QueryRowContext(ctx, `SELECT ddm_status,status FROM mdm_apple_devices WHERE id=$1 FOR UPDATE`, d.ID).Scan(&old, &state); err != nil {
		return err
	}
	if state != "enrolled" {
		return ErrUnauthorized
	}
	var previous map[string]any
	if err = json.Unmarshal(old, &previous); err != nil {
		return err
	}
	items := MergeStatus(previous, *report)
	data, err := json.Marshal(items)
	if err != nil {
		return err
	}
	version := statusString(items, "device", "operating-system", "version")
	build := statusString(items, "device", "operating-system", "build-version")
	// Only a version included in this report refreshes OS evidence. An unrelated
	// incremental status message must not make an old OS observation look current.
	freshVersion := statusString(report.StatusItems, "device", "operating-system", "version") != ""
	_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_devices SET ddm_status=$1,os_version=COALESCE(NULLIF($2,''),os_version),build_version=COALESCE(NULLIF($3,''),build_version),inventory_at=CASE WHEN $4 THEN now() ELSE inventory_at END,last_seen=now() WHERE id=$5`, data, version, build, freshVersion, d.ID)
	if err != nil {
		return err
	}
	installState := statusString(items, "softwareupdate", "install-state")
	if installState != "" {
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_update_policies SET status=$1,updated_at=now() WHERE device_id=$2 AND status<>'unavailable'`, installState, d.ID); err != nil {
			return err
		}
	}
	if failure, ok := items["softwareupdate"].(map[string]any); ok {
		if reason, exists := failure["failure-reason"].(map[string]any); exists {
			detail, err := json.Marshal(reason)
			if err != nil {
				return err
			}
			if numberValue(reason["count"]) > 0 {
				if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_update_policies SET status='failed',error=$1,updated_at=now() WHERE device_id=$2 AND status<>'unavailable'`, string(detail), d.ID); err != nil {
					return err
				}
			} else {
				if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_update_policies SET error='',status=CASE WHEN status='failed' THEN 'pending' ELSE status END WHERE device_id=$1 AND status<>'unavailable'`, d.ID); err != nil {
					return err
				}
			}
		}
	}
	if err = s.updateDeclarationState(ctx, tx, d, report.StatusItems); err != nil {
		return err
	}
	// Keep protocol-level status errors visible; never translate a missing status
	// item or an invalid declaration into successful update enforcement.
	if len(report.Errors) > 0 {
		detail, err := json.Marshal(report.Errors)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_update_policies SET error=$1,updated_at=now() WHERE device_id=$2 AND status<>'unavailable'`, string(detail), d.ID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) updateDeclarationState(ctx context.Context, tx *sql.Tx, d *Device, items map[string]any) error {
	management, _ := items["management"].(map[string]any)
	declarations, _ := management["declarations"].(map[string]any)
	configurations, _ := declarations["configurations"].([]any)
	if len(configurations) == 0 {
		return nil
	}
	p, err := scanPolicy(tx.QueryRowContext(ctx, `SELECT `+policyColumns+` FROM mdm_apple_update_policies WHERE device_id=$1`, d.ID))
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if p.Status == "unavailable" {
		return nil
	}
	var target Declaration
	for _, declaration := range Declarations(*d, p) {
		if declaration.Type == "com.apple.configuration.softwareupdate.enforcement.specific" {
			target = declaration
		}
	}
	for _, value := range configurations {
		entry, ok := value.(map[string]any)
		if !ok {
			continue
		}
		if stringValue(entry, "identifier") != target.Identifier || stringValue(entry, "server-token") != target.ServerToken {
			continue
		}
		switch stringValue(entry, "valid") {
		case "invalid":
			reasons, err := json.Marshal(entry["reasons"])
			if err != nil {
				return err
			}
			_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_update_policies SET status='failed',error=$1,updated_at=now() WHERE device_id=$2`, string(reasons), d.ID)
			return err
		case "valid":
			if active, _ := entry["active"].(bool); active {
				_, err = tx.ExecContext(ctx, `UPDATE mdm_apple_update_policies SET status=CASE WHEN status='pending' THEN 'enforced' ELSE status END,updated_at=now() WHERE device_id=$1`, d.ID)
				return err
			}
		}
	}
	return nil
}

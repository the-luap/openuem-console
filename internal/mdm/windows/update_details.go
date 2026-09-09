package windows

import (
	"context"
	"database/sql"

	"github.com/open-uem/openuem-console/internal/security/access"
)

type UpdateRunDetail struct {
	Run      UpdateRun              `json:"-" xml:"-"`
	Name     string                 `json:"-" xml:"-"`
	Policy   UpdatePolicy           `json:"-" xml:"-"`
	Platform UpdatePlatform         `json:"-" xml:"-"`
	Steps    [3]CSPCommand          `json:"-" xml:"-"`
	Outcomes []UpdateSettingOutcome `json:"-" xml:"-"`
	Phase    string                 `json:"-" xml:"-"`
	Reason   string                 `json:"-" xml:"-"`
}

func (UpdateRunDetail) String() string     { return "[protected Windows update run details]" }
func (v UpdateRunDetail) GoString() string { return v.String() }

func (s *Store) UpdateRunDetails(ctx context.Context, actor string, scope access.Scope, deviceID, runID string) (*UpdateRunDetail, error) {
	if s == nil || s.db == nil {
		return nil, ErrStore
	}
	if s.secrets == nil {
		return nil, ErrMasterKey
	}
	if !canonicalInvitationID(runID) {
		return nil, ErrUpdatePolicy
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := s.authorizeWindowsConsole(ctx, tx, actor, access.ManageUpdates, scope, deviceID, false); err != nil {
		return nil, err
	}
	run, err := scanUpdateRun(tx.QueryRowContext(ctx, `SELECT `+updateRunColumns+` FROM mdm_windows_update_runs WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4 FOR SHARE`, runID, deviceID, scope.TenantID, scope.SiteID))
	if err != nil {
		return nil, err
	}
	detail, err := s.readUpdateRunDetails(ctx, tx, actor, run)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return detail, nil
}

func (s *Store) readUpdateRunDetails(ctx context.Context, tx *sql.Tx, actor string, run *updateStoredRun) (*UpdateRunDetail, error) {
	intent, err := s.openUpdateRun(run)
	if err != nil {
		return nil, err
	}
	detail := &UpdateRunDetail{Run: run.UpdateRun, Name: intent.Name, Policy: intent.Policy, Outcomes: []UpdateSettingOutcome{}}
	var results [3]*cspStoredResult
	for step := range detail.Steps {
		command, result, err := s.updateRunStep(ctx, tx, run, step)
		if err != nil {
			return nil, err
		}
		detail.Steps[step] = command.CSPCommand
		results[step] = result
	}
	detail.Platform = assessUpdatePlatform(intent.Policy, results[0].Exchange)
	for step, command := range detail.Steps {
		names := [3]string{"preflight", "configuration", "verification"}
		detail.Reason = results[step].Reason
		switch command.Phase {
		case "queued", "blocked", "sent":
			detail.Phase = names[step] + "_pending"
		case "unknown", "abandoned", "canceled", "expired":
			detail.Phase = command.Phase
		case "failed":
			detail.Phase = names[step] + "_failed"
		case "acknowledged":
			if step == 0 && !detail.Platform.Compatible {
				detail.Phase, detail.Reason = "unsupported", detail.Platform.Reason
			} else if step != 2 {
				continue
			}
		default:
			return nil, ErrAuthoritySecret
		}
		if step == 2 && (command.Phase == "acknowledged" || command.Phase == "failed") {
			detail.Outcomes, detail.Phase, err = evaluateUpdateReadback(intent.Policy, run.Mode == "remove", results[step].Exchange)
			if err != nil {
				return nil, err
			}
		}
		break
	}
	if err := auditUpdateRun(ctx, tx, run, actor, "run.read"); err != nil {
		return nil, err
	}
	return detail, nil
}

func (s *Store) UpdateRuns(ctx context.Context, actor string, scope access.Scope, deviceID string, offset, limit int) ([]*UpdateRunDetail, error) {
	if s == nil || s.db == nil {
		return nil, ErrStore
	}
	if s.secrets == nil {
		return nil, ErrMasterKey
	}
	if offset < 0 || offset > 100000 || limit < 1 || limit > 100 {
		return nil, ErrUpdatePolicy
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := s.authorizeWindowsConsole(ctx, tx, actor, access.ManageUpdates, scope, deviceID, false); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+updateRunColumns+` FROM mdm_windows_update_runs WHERE device_id=$1 AND tenant_id=$2 AND site_id=$3 ORDER BY created_at DESC,id LIMIT $4 OFFSET $5 FOR SHARE`, deviceID, scope.TenantID, scope.SiteID, limit, offset)
	if err != nil {
		return nil, err
	}
	runs := []*updateStoredRun{}
	for rows.Next() {
		run, err := scanUpdateRun(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		runs = append(runs, run)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	details := []*UpdateRunDetail{}
	for _, run := range runs {
		detail, err := s.readUpdateRunDetails(ctx, tx, actor, run)
		if err != nil {
			return nil, err
		}
		details = append(details, detail)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return details, nil
}

// Cancellation retires only undelivered remaining steps. A sent/uncertain step
// requires actual evidence or an administrator's explicit uncertainty resolution.
func (s *Store) CancelUpdateRun(ctx context.Context, actor string, scope access.Scope, deviceID, runID string) error {
	if s == nil || s.db == nil {
		return ErrStore
	}
	if s.secrets == nil {
		return ErrMasterKey
	}
	if !canonicalInvitationID(runID) {
		return ErrUpdatePolicy
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.authorizeWindowsConsole(ctx, tx, actor, access.ManageUpdates, scope, deviceID, true); err != nil {
		return err
	}
	run, err := scanUpdateRun(tx.QueryRowContext(ctx, `SELECT `+updateRunColumns+` FROM mdm_windows_update_runs WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4 FOR SHARE`, runID, deviceID, scope.TenantID, scope.SiteID))
	if err != nil {
		return err
	}
	if _, err := s.openUpdateRun(run); err != nil {
		return err
	}
	changed := false
	for step := 0; step < 3; step++ {
		c, result, err := s.updateRunStep(ctx, tx, run, step)
		if err != nil {
			return err
		}
		if c.Phase == "sent" || c.Phase == "unknown" {
			return ErrCSPAlreadySent
		}
		if c.Phase != "queued" && c.Phase != "blocked" {
			continue
		}
		if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&c.UpdatedAt); err != nil {
			return err
		}
		c.Revision++
		c.Phase = "canceled"
		c.CompletedAt = &c.UpdatedAt
		result.Reason = "update_run_canceled"
		if err := s.writeCSPResult(ctx, tx, c, *result); err != nil {
			return err
		}
		if err := auditCSP(ctx, tx, c, actor, "command.canceled"); err != nil {
			return err
		}
		changed = true
	}
	if !changed {
		return ErrCSPAlreadySent
	}
	if err := auditUpdateRun(ctx, tx, run, actor, "run.canceled"); err != nil {
		return err
	}
	return tx.Commit()
}

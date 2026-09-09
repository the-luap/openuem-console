package apple

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func adeRequiredApplicationIDs(ids []string) ([]string, error) {
	if len(ids) > 16 {
		return nil, ErrADEProfile
	}
	result := append([]string(nil), ids...)
	slices.Sort(result)
	for i, value := range result {
		id, err := uuid.Parse(value)
		if err != nil || id == uuid.Nil || id.String() != value || i > 0 && result[i-1] == value {
			return nil, ErrADEProfile
		}
	}
	return result, nil
}

func (s *Store) approvedADEApplications(ctx context.Context, tx *sql.Tx, tenant int, ids []string) ([]SoftwareVersion, error) {
	result := []SoftwareVersion{}
	packages := map[string]bool{}
	for _, id := range ids {
		v, err := scanSoftwareVersion(tx.QueryRowContext(ctx, `SELECT `+softwareVersionColumns+softwareVersionFrom+`WHERE v.tenant_id=$1 AND v.id=$2 AND p.platform='macos' AND v.kind='macos-pkg' AND v.withdrawn_at IS NULL FOR SHARE OF v`, tenant, id))
		if err != nil {
			return nil, err
		}
		if packages[v.PackageID] {
			return nil, ErrADEProfile
		}
		packages[v.PackageID] = true
		result = append(result, *v)
	}
	return result, nil
}

type ADEApplication struct {
	ID, OriginalVersionID, Error string
	Version                      SoftwareVersion
	Assignment                   *MacAppAssignment
}

func (r ADEApplication) Ready(now time.Time) bool {
	return adeApplicationVerified(r.Assignment, r.Version, now)
}

const adeApplicationColumns = `r.id,r.original_version_id,r.error,` + softwareVersionColumns
const adeApplicationFrom = ` FROM mdm_apple_ade_device_apps r JOIN uem_software_versions v ON v.tenant_id=r.tenant_id AND v.id=r.version_id JOIN uem_software_packages p ON p.id=v.package_id AND p.tenant_id=v.tenant_id `

func scanADEApplication(row scanner) (*ADEApplication, error) {
	var a ADEApplication
	v := &a.Version
	err := row.Scan(&a.ID, &a.OriginalVersionID, &a.Error, &v.ID, &v.PackageID, &v.Platform, &v.Name, &v.Identifier, &v.Version, &v.Architecture, &v.MinimumOS, &v.SHA256, &v.SingleApp, &v.ApprovedBy, &v.ApprovedAt, &v.WithdrawnAt)
	return &a, notFound(err)
}

func (s *Store) ADEApplications(ctx context.Context, scope Scope, device string) ([]ADEApplication, error) {
	if _, err := s.Device(ctx, scope, device); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+adeApplicationColumns+adeApplicationFrom+`WHERE r.tenant_id=$1 AND r.device_id=$2 ORDER BY r.id LIMIT 17`, scope.TenantID, device)
	if err != nil {
		return nil, err
	}
	items := []ADEApplication{}
	for rows.Next() {
		a, e := scanADEApplication(rows)
		if e != nil {
			rows.Close()
			return nil, e
		}
		items = append(items, *a)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(items) > 16 {
		return nil, ErrADEProfile
	}
	for i := range items {
		a, e := scanMacApp(s.db.QueryRowContext(ctx, `SELECT `+macAppColumns+macAppFrom+`WHERE a.tenant_id=$1 AND a.device_id=$2 AND a.package_id=$3 AND ($4=0 OR d.site_id=$4)`, scope.TenantID, device, items[i].Version.PackageID, scope.SiteID))
		if e != nil && !errors.Is(e, ErrNotFound) {
			return nil, e
		}
		if e == nil {
			items[i].Assignment = a
		}
	}
	return items, nil
}

func adeApplicationVerified(a *MacAppAssignment, version SoftwareVersion, now time.Time) bool {
	if a == nil || a.Version.ID != version.ID || a.Operation != "install" || a.Status != "verified" || a.ManagedState != "managed" || a.InstalledState != "installed" || a.InstalledVersion != version.Version || a.AcceptedAt == nil {
		return false
	}
	for _, observed := range []*time.Time{a.ManagedAt, a.InstalledAt} {
		if observed == nil || observed.After(now) || observed.Before(now.Add(-24*time.Hour)) || observed.Before(*a.AcceptedAt) {
			return false
		}
	}
	return true
}

func (s *Store) adeApplicationState(ctx context.Context, tx *sql.Tx, tenant int, requirement, state string) error {
	result, err := tx.ExecContext(ctx, `UPDATE mdm_apple_ade_device_apps SET error=$2,updated_at=clock_timestamp() WHERE id=$1 AND error<>$2`, requirement, state)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil || count == 0 {
		return err
	}
	outcome := "failure"
	action := state
	if state == "" {
		action = "ready"
		outcome = "success"
	}
	if state == "application_pending" {
		outcome = "deferred"
	}
	return auditOutcome(ctx, tx, tenant, "enrollment-service", "apple.ade.application."+action, requirement, outcome)
}

// Only the absence of an assignment permits an automatic first installation.
// Failed, cancelled and unresolved attempts always need an explicit operator
// action; polling the Setup Assistant hold never reruns an installer.
func (s *Store) reconcileADEApplications(ctx context.Context, tx *sql.Tx, d *Device) (bool, error) {
	rows, err := tx.QueryContext(ctx, `SELECT `+adeApplicationColumns+adeApplicationFrom+`WHERE r.tenant_id=$1 AND r.device_id=$2 ORDER BY r.id LIMIT 17`, d.TenantID, d.ID)
	if err != nil {
		return false, err
	}
	requirements := []ADEApplication{}
	for rows.Next() {
		a, e := scanADEApplication(rows)
		if e != nil {
			rows.Close()
			return false, e
		}
		requirements = append(requirements, *a)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return false, err
	}
	if len(requirements) == 0 {
		return true, nil
	}
	if len(requirements) > 16 {
		return false, ErrADEProfile
	}
	// The command handler may have just ingested the first OS report. Reload
	// readiness within the held device transaction instead of using that snapshot.
	current, err := s.lockMacAppDevice(ctx, tx, Scope{TenantID: d.TenantID, SiteID: d.SiteID}, d.ID)
	if err != nil && !errors.Is(err, ErrConflict) && !errors.Is(err, ErrNotFound) {
		return false, err
	}
	deviceReady := err == nil
	ready := deviceReady
	for _, r := range requirements {
		state := "application_pending"
		a, e := scanMacApp(tx.QueryRowContext(ctx, `SELECT `+macAppColumns+macAppFrom+`WHERE a.tenant_id=$1 AND a.device_id=$2 AND a.package_id=$3`, d.TenantID, d.ID, r.Version.PackageID))
		if e != nil && !errors.Is(e, ErrNotFound) {
			return false, e
		}
		if !deviceReady {
			state = "inventory_required"
		} else if e == nil {
			if adeApplicationVerified(a, r.Version, time.Now()) {
				state = ""
			} else if a.Version.ID != r.Version.ID {
				state = "revision_mismatch"
			} else if a.Status == "failed" || a.Status == "cancelled" || a.Status == "expired" || a.Status == "uncertain" {
				state = "operator_action_required"
			}
		} else if r.Version.WithdrawnAt != nil {
			state = "approval_withdrawn"
		} else if !macAppCompatible(*current, r.Version) {
			state = "device_incompatible"
		} else {
			// Pin the approval until enqueue commits, exactly as a console request.
			if _, err = tx.ExecContext(ctx, `SAVEPOINT ade_app_enqueue`); err != nil {
				return false, err
			}
			if err = s.installMacAppTx(ctx, tx, current, r.Version.ID, "enrollment-service", MacAppInstallOptions{}); err != nil {
				if _, rollbackErr := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT ade_app_enqueue`); rollbackErr != nil {
					return false, rollbackErr
				}
				if !errors.Is(err, ErrConflict) && !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrMacApp) && !errors.Is(err, ErrMacAppPriorEnrollment) {
					return false, err
				}
				state = "approved_artifact_unavailable"
				if errors.Is(err, ErrMacAppPriorEnrollment) {
					state = "previous_enrollment_unresolved"
				}
			}
			if _, err = tx.ExecContext(ctx, `RELEASE SAVEPOINT ade_app_enqueue`); err != nil {
				return false, err
			}
		}
		if state != "" {
			ready = false
		}
		if err = s.adeApplicationState(ctx, tx, d.TenantID, r.ID, state); err != nil {
			return false, err
		}
	}
	return ready, nil
}

func (s *Store) ReplaceADEApplication(ctx context.Context, scope Scope, device, requirement, version, reason, actor string, permissions *access.Store) error {
	if permissions == nil {
		return access.ErrDenied
	}
	return s.replaceADEApplication(ctx, scope, device, requirement, version, reason, actor, adeEnrollmentPermission(permissions, scope.TenantID, scope.SiteID, actor, false, true))
}

func (s *Store) replaceADEApplication(ctx context.Context, scope Scope, device, requirement, version, reason, actor string, authorize func(context.Context, *sql.Tx) error) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	reason = strings.TrimSpace(reason)
	if !validMacAppText(reason, 1000) || actor == "" {
		return ErrADEProfile
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
	d, err := s.lockMacAppDevice(ctx, tx, scope, device)
	if err != nil {
		return err
	}
	var state, command string
	var awaiting bool
	var sent int
	// Retrying setup clears its current command pointer. Earlier release
	// dispatches still prohibit changes to this admission's prerequisites.
	if err = tx.QueryRowContext(ctx, `SELECT a.setup_state,COALESCE(a.awaiting_configuration,false),COALESCE(a.setup_command_id::text,''),(SELECT count(*) FROM mdm_apple_commands c WHERE c.tenant_id=a.tenant_id AND c.device_id=a.device_id AND c.ade_setup AND c.attempts>0) FROM mdm_apple_ade_admissions a WHERE a.tenant_id=$1 AND a.device_id=$2 FOR UPDATE OF a`, scope.TenantID, device).Scan(&state, &awaiting, &command, &sent); err != nil {
		return notFound(err)
	}
	if !awaiting || state != "awaiting" && state != "releasing" || sent != 0 {
		return ErrConflict
	}
	r, err := scanADEApplication(tx.QueryRowContext(ctx, `SELECT `+adeApplicationColumns+adeApplicationFrom+`WHERE r.tenant_id=$1 AND r.device_id=$2 AND r.id=$3 FOR UPDATE OF r`, scope.TenantID, device, requirement))
	if err != nil {
		return err
	}
	if r.Version.ID == version {
		return ErrConflict
	}
	versions, err := s.approvedADEApplications(ctx, tx, scope.TenantID, []string{version})
	if err != nil {
		return err
	}
	if len(versions) != 1 || versions[0].PackageID != r.Version.PackageID || !macAppCompatible(*d, versions[0]) {
		return ErrConflict
	}
	a, err := scanMacApp(tx.QueryRowContext(ctx, `SELECT `+macAppColumns+macAppFrom+`WHERE a.tenant_id=$1 AND a.device_id=$2 AND a.package_id=$3`, scope.TenantID, device, r.Version.PackageID))
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if err == nil && activeMacApp(a.Status) {
		if !a.CanCancel() {
			return ErrConflict
		}
		if err = s.finishMacApp(ctx, tx, a.AttemptID, "cancelled", "ade_revision_replaced"); err != nil {
			return err
		}
		if err = auditOutcome(ctx, tx, scope.TenantID, actor, "apple.software.cancel", a.AttemptID, "cancelled"); err != nil {
			return err
		}
	}
	change := uuid.NewString()
	if _, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_ade_app_changes(id,tenant_id,device_id,package_id,requirement_id,previous_version_id,version_id,actor,reason) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, change, scope.TenantID, device, r.Version.PackageID, r.ID, r.Version.ID, version, actor, reason); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_ade_device_apps SET version_id=$2,current_change_id=$3,error='application_pending',updated_at=clock_timestamp() WHERE id=$1`, r.ID, version, change); err != nil {
		return err
	}
	if command != "" {
		if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_commands SET status='cancelled',payload='\x',completed_at=clock_timestamp() WHERE id=$1 AND attempts=0`, command); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_ade_admissions SET setup_state='awaiting',setup_command_id=NULL,setup_error='application_pending',setup_verify_after=clock_timestamp(),setup_updated_at=clock_timestamp(),next_setup_at=clock_timestamp() WHERE device_id=$1`, device); err != nil {
		return err
	}
	if err = s.installMacAppTx(ctx, tx, d, version, actor, MacAppInstallOptions{}); err != nil {
		return err
	}
	if _, err = s.enqueue(ctx, tx, d, "DeviceInformation", map[string]any{"Queries": inventoryQueriesFor(*d)}, nil, nil); err != nil {
		return err
	}
	if err = audit(ctx, tx, scope.TenantID, actor, "apple.ade.application.replace", change); err != nil {
		return err
	}
	return tx.Commit()
}

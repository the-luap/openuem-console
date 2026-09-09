package apple

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

type MacAppAssignment struct {
	TenantID                                              int
	ID, AttemptID, DeviceID, Status, Operation            string
	Version                                               SoftwareVersion
	Options                                               MacAppInstallOptions
	ManagedState, InstalledState, InstalledVersion, Error string
	CreatedAt                                             time.Time
	DispatchedAt, AcceptedAt, ManagedAt, InstalledAt      *time.Time
}

func activeMacApp(status string) bool {
	return status == "queued" || status == "sent" || status == "not_now" || status == "verifying" || status == "uncertain"
}

const macAppColumns = `a.tenant_id,a.id,t.id,a.device_id,a.status,t.operation,t.options,t.managed_state,t.installed_state,t.installed_version,t.error,t.created_at,t.dispatched_at,t.accepted_at,t.managed_at,t.installed_at,` + softwareVersionColumns
const macAppFrom = ` FROM mdm_apple_app_assignments a JOIN mdm_apple_app_attempts t ON t.id=a.current_attempt_id AND t.assignment_id=a.id JOIN uem_software_versions v ON v.id=t.version_id AND v.tenant_id=t.tenant_id JOIN uem_software_packages p ON p.id=v.package_id AND p.tenant_id=v.tenant_id JOIN mdm_apple_devices d ON d.id=a.device_id AND d.tenant_id=a.tenant_id `

func scanMacApp(row scanner) (*MacAppAssignment, error) {
	var a MacAppAssignment
	var options []byte
	v := &a.Version
	err := row.Scan(&a.TenantID, &a.ID, &a.AttemptID, &a.DeviceID, &a.Status, &a.Operation, &options, &a.ManagedState, &a.InstalledState, &a.InstalledVersion, &a.Error, &a.CreatedAt, &a.DispatchedAt, &a.AcceptedAt, &a.ManagedAt, &a.InstalledAt, &v.ID, &v.PackageID, &v.Platform, &v.Name, &v.Identifier, &v.Version, &v.Architecture, &v.MinimumOS, &v.SHA256, &v.SingleApp, &v.ApprovedBy, &v.ApprovedAt, &v.WithdrawnAt)
	if err != nil {
		return nil, notFound(err)
	}
	if err = json.Unmarshal(options, &a.Options); err != nil {
		return nil, ErrMacApp
	}
	return &a, nil
}

func (s *Store) MacApps(ctx context.Context, scope Scope, device, after string) ([]MacAppAssignment, string, error) {
	if _, err := s.Device(ctx, scope, device); err != nil {
		return nil, "", err
	}
	var cursor any
	if after != "" {
		id, err := uuid.Parse(after)
		if err != nil || id == uuid.Nil || id.String() != after {
			return nil, "", ErrMacApp
		}
		cursor = after
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+macAppColumns+macAppFrom+`WHERE a.tenant_id=$1 AND a.device_id=$2 AND ($3=0 OR d.site_id=$3) AND ($4::uuid IS NULL OR a.id>$4) ORDER BY a.id LIMIT 101`, scope.TenantID, device, scope.SiteID, cursor)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	items := []MacAppAssignment{}
	for rows.Next() {
		a, err := scanMacApp(rows)
		if err != nil {
			return nil, "", err
		}
		items = append(items, *a)
	}
	if err = rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(items) > 100 {
		items = items[:100]
		next = items[len(items)-1].ID
	}
	return items, next, nil
}

func macAppDeviceReady(d Device, now time.Time) bool {
	return d.Status == "enrolled" && d.Family() == PlatformMacOS && (d.EnrollmentMethod == "manual_device" || d.EnrollmentMethod == "automated_device") && macAppOSPattern.MatchString(d.OSVersion) && CompareVersions(d.OSVersion, "11.0") >= 0 && d.InventoryAt != nil && !d.InventoryAt.After(now) && d.InventoryAt.After(now.Add(-24*time.Hour)) && d.CertificateExpiresAt != nil && d.CertificateExpiresAt.After(now.Add(time.Minute))
}

func macAppCompatible(d Device, v SoftwareVersion) bool {
	if v.Platform != "macos" || CompareVersions(d.OSVersion, v.MinimumOS) < 0 || (!v.SingleApp && CompareVersions(d.OSVersion, "14.0") < 0) {
		return false
	}
	return v.Architecture == "universal" || (d.AppleSilicon != nil && ((v.Architecture == "arm64" && *d.AppleSilicon) || (v.Architecture == "x86_64" && !*d.AppleSilicon)))
}

func (s *Store) lockMacAppDevice(ctx context.Context, tx *sql.Tx, scope Scope, device string) (*Device, error) {
	d, err := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM mdm_apple_devices WHERE tenant_id=$1 AND id=$2 AND ($3=0 OR site_id=$3) FOR UPDATE`, scope.TenantID, device, scope.SiteID))
	if err != nil {
		return nil, err
	}
	if !macAppDeviceReady(*d, time.Now()) {
		return nil, ErrConflict
	}
	var rights int64
	if err = tx.QueryRowContext(ctx, `SELECT access_rights FROM mdm_apple_enrollment_layouts WHERE tenant_id=$1 AND device_id=$2`, scope.TenantID, device).Scan(&rights); err != nil {
		return nil, notFound(err)
	}
	// Apple: 256 permits application inventory; 4096 permits app management.
	if rights&(256|4096) != 256|4096 {
		return nil, ErrConflict
	}
	return d, nil
}

func (s *Store) InstallMacApp(ctx context.Context, scope Scope, device, version, actor string, options MacAppInstallOptions, permissions *access.Store) error {
	if permissions == nil {
		return access.ErrDenied
	}
	return s.installMacApp(ctx, scope, device, version, actor, options, permissions)
}

func (s *Store) installMacApp(ctx context.Context, scope Scope, device, version, actor string, options MacAppInstallOptions, permissions *access.Store) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if permissions != nil {
		if err = permissions.AuthorizeTransaction(ctx, tx, actor, access.AssignSoftware, access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID}); err != nil {
			return err
		}
	}
	d, err := s.lockMacAppDevice(ctx, tx, scope, device)
	if err != nil {
		return err
	}
	if err = s.reconcileMacAppExpiry(ctx, tx, d); err != nil {
		return err
	}
	v, input, err := s.macAppArtifactTx(ctx, tx, scope.TenantID, version)
	if err != nil {
		return err
	}
	if !macAppCompatible(*d, *v) {
		return ErrConflict
	}
	args, err := macAppInstallArguments(input, options)
	if err != nil {
		return err
	}
	var assignment, state string
	err = tx.QueryRowContext(ctx, `SELECT id,status FROM mdm_apple_app_assignments WHERE device_id=$1 AND package_id=$2`, device, v.PackageID).Scan(&assignment, &state)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if activeMacApp(state) {
		return ErrConflict
	}
	if assignment == "" {
		assignment = uuid.NewString()
		if _, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_app_assignments(id,tenant_id,device_id,package_id,version_id,desired,status) VALUES($1,$2,$3,$4,$5,'present','queued')`, assignment, scope.TenantID, device, v.PackageID, version); err != nil {
			return err
		}
	}
	if err = s.createMacAppAttempt(ctx, tx, d, assignment, *v, "install", options, args, actor); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) createMacAppAttempt(ctx context.Context, tx *sql.Tx, d *Device, assignment string, v SoftwareVersion, operation string, options MacAppInstallOptions, args map[string]any, actor string) error {
	// A new approved intent supersedes only read-only probes of older attempts.
	// An unresolved mutation was rejected by the caller while holding the device.
	if _, err := tx.ExecContext(ctx, `UPDATE mdm_apple_commands c SET status='cancelled',payload='\x',completed_at=clock_timestamp() FROM mdm_apple_app_commands m JOIN mdm_apple_app_attempts t ON t.id=m.attempt_id WHERE m.command_id=c.id AND t.assignment_id=$1 AND m.kind IN ('managed','installed') AND c.status IN ('queued','sent','not_now')`, assignment); err != nil {
		return err
	}
	id := uuid.NewString()
	data, err := json.Marshal(options)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_app_attempts(id,tenant_id,device_id,package_id,assignment_id,version_id,operation,options,status,requested_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'queued',$9)`, id, d.TenantID, d.ID, v.PackageID, assignment, v.ID, operation, data, actor)
	if err != nil {
		return err
	}
	desired := "present"
	if operation == "remove" {
		desired = "absent"
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_app_assignments SET version_id=$2,current_attempt_id=$3,desired=$4,status='queued',updated_at=clock_timestamp(),next_check_at=clock_timestamp() WHERE id=$1`, assignment, v.ID, id, desired); err != nil {
		return err
	}
	if _, err = s.enqueueMacApp(ctx, tx, d, id, operation, args); err != nil {
		return err
	}
	return audit(ctx, tx, d.TenantID, actor, "apple.software."+operation, id)
}

func (s *Store) ChangeMacApp(ctx context.Context, scope Scope, device, assignment, operation, actor string, permissions *access.Store) error {
	if permissions == nil {
		return access.ErrDenied
	}
	return s.changeMacApp(ctx, scope, device, assignment, operation, actor, permissions)
}

func (s *Store) changeMacApp(ctx context.Context, scope Scope, device, assignment, operation, actor string, permissions *access.Store) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	if operation != "remove" && operation != "refresh" && operation != "cancel" {
		return ErrMacApp
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if permissions != nil {
		if err = permissions.AuthorizeTransaction(ctx, tx, actor, access.AssignSoftware, access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID}); err != nil {
			return err
		}
	}
	d, err := s.lockMacAppDevice(ctx, tx, scope, device)
	if err != nil {
		return err
	}
	if err = s.reconcileMacAppExpiry(ctx, tx, d); err != nil {
		return err
	}
	a, err := scanMacApp(tx.QueryRowContext(ctx, `SELECT `+macAppColumns+macAppFrom+`WHERE a.tenant_id=$1 AND a.device_id=$2 AND a.id=$3`, scope.TenantID, device, assignment))
	if err != nil {
		return err
	}
	switch operation {
	case "cancel":
		if a.Status != "queued" && a.Status != "not_now" {
			return ErrConflict
		}
		err = s.finishMacApp(ctx, tx, a.AttemptID, "cancelled", "cancelled_by_operator")
	case "refresh":
		if a.DispatchedAt == nil {
			return ErrConflict
		}
		err = s.queueMacAppObservation(ctx, tx, d, a)
	case "remove":
		now := time.Now()
		if activeMacApp(a.Status) || a.ManagedState != "managed" || a.ManagedAt == nil || a.ManagedAt.After(now) || a.ManagedAt.Before(now.Add(-24*time.Hour)) {
			return ErrConflict
		}
		err = s.createMacAppAttempt(ctx, tx, d, a.ID, a.Version, "remove", a.Options, map[string]any{"Identifier": a.Version.Identifier}, actor)
	}
	if err != nil {
		return err
	}
	if operation != "remove" {
		if err = audit(ctx, tx, d.TenantID, actor, "apple.software."+operation, a.AttemptID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

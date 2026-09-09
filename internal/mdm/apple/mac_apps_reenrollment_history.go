package apple

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

const macAppPriorColumns = `a.id,old.id,old.name,old.status,a.operation,a.status,a.created_at,a.dispatched_at,` + softwareVersionColumns + `,COALESCE(r.id::text,''),COALESCE(r.device_id::text,''),COALESCE(r.evidence,''),COALESCE(r.reason,''),COALESCE(r.actor,''),r.created_at`
const macAppPriorFrom = ` FROM mdm_apple_app_attempts a JOIN mdm_apple_devices old ON old.id=a.device_id AND old.tenant_id=a.tenant_id JOIN uem_software_versions v ON v.id=a.version_id AND v.tenant_id=a.tenant_id JOIN uem_software_packages p ON p.id=v.package_id AND p.tenant_id=v.tenant_id LEFT JOIN mdm_apple_app_recoveries r ON r.attempt_id=a.id `

func scanMacAppPriorAttempt(row scanner) (MacAppPriorAttempt, error) {
	var a MacAppPriorAttempt
	v := &a.Version
	var r MacAppRecovery
	var recorded sql.NullTime
	err := row.Scan(&a.ID, &a.PreviousDeviceID, &a.PreviousName, &a.PreviousStatus, &a.Operation, &a.Status, &a.CreatedAt, &a.DispatchedAt, &v.ID, &v.PackageID, &v.Platform, &v.Name, &v.Identifier, &v.Version, &v.Architecture, &v.MinimumOS, &v.SHA256, &v.SingleApp, &v.ApprovedBy, &v.ApprovedAt, &v.WithdrawnAt, &r.ID, &r.DeviceID, &r.Evidence, &r.Reason, &r.Actor, &recorded)
	if r.ID != "" {
		r.CreatedAt = recorded.Time
		a.Recovery = &r
	}
	return a, notFound(err)
}

func (s *Store) MacAppPriorAttempts(ctx context.Context, scope Scope, device, before, actor string, permissions *access.Store) (*Device, MacAppEnrollmentRisk, []MacAppPriorAttempt, string, error) {
	return s.macAppPriorAttempts(ctx, scope, device, before, macAppRecoveryPermission(permissions, scope, actor))
}

func (s *Store) macAppPriorAttempts(ctx context.Context, scope Scope, device, before string, authorize func(context.Context, *sql.Tx) error) (*Device, MacAppEnrollmentRisk, []MacAppPriorAttempt, string, error) {
	var risk MacAppEnrollmentRisk
	if err := scope.Validate(); err != nil {
		return nil, risk, nil, "", err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, risk, nil, "", err
	}
	defer tx.Rollback()
	if authorize != nil {
		if err = authorize(ctx, tx); err != nil {
			return nil, risk, nil, "", err
		}
	}
	d, err := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM mdm_apple_devices WHERE tenant_id=$1 AND id=$2 AND ($3=0 OR site_id=$3)`, scope.TenantID, device, scope.SiteID))
	if err != nil {
		return nil, risk, nil, "", err
	}
	if d.Family() != PlatformMacOS {
		return nil, risk, nil, "", ErrMacApp
	}
	risk, err = macAppEnrollmentRisk(ctx, tx, d, "")
	if err != nil {
		return nil, risk, nil, "", err
	}
	var stamp, cursor any
	if before != "" {
		id, err := uuid.Parse(before)
		if err != nil || id == uuid.Nil || id.String() != before {
			return nil, risk, nil, "", ErrMacApp
		}
		var at time.Time
		if err = tx.QueryRowContext(ctx, `SELECT a.created_at FROM mdm_apple_app_attempts a JOIN mdm_apple_devices old ON old.tenant_id=a.tenant_id AND old.id=a.device_id WHERE a.tenant_id=$1 AND old.udid<>'' AND upper(old.udid)=upper($2) AND old.id<>$3 AND a.id=$4`, scope.TenantID, d.UDID, d.ID, before).Scan(&at); err != nil {
			return nil, risk, nil, "", notFound(err)
		}
		stamp, cursor = at, before
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+macAppPriorColumns+macAppPriorFrom+`WHERE a.tenant_id=$1 AND old.udid<>'' AND upper(old.udid)=upper($2) AND old.id<>$3 AND (a.status IN ('queued','sent','not_now','verifying','uncertain') OR r.id IS NOT NULL) AND ($4::timestamptz IS NULL OR (a.created_at,a.id)<($4,$5::uuid)) ORDER BY a.created_at DESC,a.id DESC LIMIT 101`, scope.TenantID, d.UDID, d.ID, stamp, cursor)
	if err != nil {
		return nil, risk, nil, "", err
	}
	items := []MacAppPriorAttempt{}
	for rows.Next() {
		a, err := scanMacAppPriorAttempt(rows)
		if err != nil {
			rows.Close()
			return nil, risk, nil, "", err
		}
		items = append(items, a)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, risk, nil, "", err
	}
	next := ""
	if len(items) > 100 {
		items = items[:100]
		next = items[99].ID
	}
	if err = tx.Commit(); err != nil {
		return nil, risk, nil, "", err
	}
	return d, risk, items, next, nil
}

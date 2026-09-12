package apple

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

var ErrMacAppPriorEnrollment = errors.New("application management requires review of an earlier enrollment")

type MacAppEnrollmentRisk struct{ ActiveIdentity, Unresolved bool }

func (r MacAppEnrollmentRisk) Blocked() bool { return r.ActiveIdentity || r.Unresolved }

// Only a folded nonempty UDID identifies a physical Mac across enrollment rows.
// The lock also serializes legacy case-variant identities without requiring a
// migration to discard existing enrollment records or their history.
func (s *Store) lockMacAppIdentity(ctx context.Context, tx *sql.Tx, d *Device) error {
	if d.UDID == "" {
		return nil
	}
	_, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('mac-app:' || $1::bigint::text || ':' || upper($2::text),0))`, d.TenantID, d.UDID)
	return err
}

type macAppRiskReader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func macAppEnrollmentRisk(ctx context.Context, q macAppRiskReader, d *Device, packageID string) (MacAppEnrollmentRisk, error) {
	var risk MacAppEnrollmentRisk
	if d.UDID == "" {
		return risk, nil
	}
	var pkg any
	if packageID != "" {
		pkg = packageID
	}
	err := q.QueryRowContext(ctx, `SELECT
 EXISTS(SELECT 1 FROM mdm_apple_devices old WHERE old.tenant_id=$1 AND old.id<>$2 AND old.udid<>'' AND upper(old.udid)=upper($3) AND old.status IN ('authenticating','enrolled')),
 EXISTS(SELECT 1 FROM mdm_apple_devices old JOIN mdm_apple_app_attempts a ON a.tenant_id=old.tenant_id AND a.device_id=old.id
  WHERE old.tenant_id=$1 AND old.id<>$2 AND old.udid<>'' AND upper(old.udid)=upper($3)
  AND ($4::uuid IS NULL OR a.package_id=$4) AND a.status IN ('queued','sent','not_now','verifying','uncertain')
  AND NOT EXISTS(SELECT 1 FROM mdm_apple_app_recoveries r WHERE r.attempt_id=a.id))`, d.TenantID, d.ID, d.UDID, pkg).Scan(&risk.ActiveIdentity, &risk.Unresolved)
	return risk, err
}

func (s *Store) guardMacAppEnrollment(ctx context.Context, tx *sql.Tx, d *Device, packageID string) error {
	if err := s.lockMacAppIdentity(ctx, tx, d); err != nil {
		return err
	}
	risk, err := macAppEnrollmentRisk(ctx, tx, d, packageID)
	if err != nil {
		return err
	}
	if risk.Blocked() {
		return ErrMacAppPriorEnrollment
	}
	return nil
}

// This summary contains no names, operation identifiers or actors from other
// sites. Detailed history requires organization-wide software authority.
func (s *Store) MacAppEnrollmentRisk(ctx context.Context, scope Scope, device string) (MacAppEnrollmentRisk, error) {
	d, err := s.Device(ctx, scope, device)
	if err != nil {
		return MacAppEnrollmentRisk{}, err
	}
	if d.Status != "enrolled" || d.Family() != PlatformMacOS {
		return MacAppEnrollmentRisk{}, nil
	}
	return macAppEnrollmentRisk(ctx, s.db, d, "")
}

type MacAppRecovery struct {
	ID, DeviceID, Evidence, Reason, Actor string
	CreatedAt                             time.Time
}

type MacAppPriorAttempt struct {
	ID, PreviousDeviceID, PreviousName, PreviousStatus, Operation, Status string
	Version                                                               SoftwareVersion
	CreatedAt                                                             time.Time
	DispatchedAt                                                          *time.Time
	Recovery                                                              *MacAppRecovery
}

func (a MacAppPriorAttempt) CanRecordEvidence() bool {
	return a.Recovery == nil && a.Status == "uncertain" && a.DispatchedAt != nil && (a.PreviousStatus == "unenrolled" || a.PreviousStatus == "revoked")
}

func macAppRecoveryPermission(permissions *access.Store, scope Scope, actor string) func(context.Context, *sql.Tx) error {
	return func(ctx context.Context, tx *sql.Tx) error {
		if permissions == nil {
			return access.ErrDenied
		}
		for _, capability := range []access.Capability{access.ManageCertificates, access.ManageSoftware} {
			if err := permissions.AuthorizeTransaction(ctx, tx, actor, capability, access.Scope{TenantID: scope.TenantID}); err != nil {
				return err
			}
		}
		for _, capability := range []access.Capability{access.EnrollDevices, access.AssignSoftware} {
			if err := permissions.AuthorizeTransaction(ctx, tx, actor, capability, access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID}); err != nil {
				return err
			}
		}
		return nil
	}
}

func (s *Store) RecordMacAppStoppingEvidence(ctx context.Context, scope Scope, device, attempt, evidence, reason, actor string, permissions *access.Store) error {
	return s.recordMacAppStoppingEvidence(ctx, scope, device, attempt, evidence, reason, actor, macAppRecoveryPermission(permissions, scope, actor))
}

func (s *Store) recordMacAppStoppingEvidence(ctx context.Context, scope Scope, device, attempt, evidence, reason, actor string, authorize func(context.Context, *sql.Tx) error) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	reason = strings.TrimSpace(reason)
	if (evidence != "installer_stopped" && evidence != "device_erased") || !validMacAppText(reason, 1000) || actor == "" {
		return ErrMacApp
	}
	id, err := uuid.Parse(attempt)
	if err != nil || id == uuid.Nil || id.String() != attempt {
		return ErrMacApp
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
	if err = s.lockMacAppIdentity(ctx, tx, d); err != nil {
		return err
	}
	risk, err := macAppEnrollmentRisk(ctx, tx, d, "")
	if err != nil {
		return err
	}
	if risk.ActiveIdentity {
		return ErrMacAppPriorEnrollment
	}
	var previous string
	err = tx.QueryRowContext(ctx, `SELECT a.device_id FROM mdm_apple_app_attempts a JOIN mdm_apple_devices old ON old.tenant_id=a.tenant_id AND old.id=a.device_id
 WHERE a.tenant_id=$1 AND a.id=$2 AND old.id<>$3 AND old.udid<>'' AND upper(old.udid)=upper($4)
 AND old.status IN ('unenrolled','revoked') AND a.status='uncertain' AND a.dispatched_at IS NOT NULL
 AND NOT EXISTS(SELECT 1 FROM mdm_apple_app_recoveries r WHERE r.attempt_id=a.id)`, scope.TenantID, attempt, d.ID, d.UDID).Scan(&previous)
	if err != nil {
		return notFound(err)
	}
	receipt := uuid.NewString()
	if _, err = tx.ExecContext(ctx, `INSERT INTO mdm_apple_app_recoveries(id,tenant_id,device_id,previous_device_id,attempt_id,evidence,reason,actor) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, receipt, scope.TenantID, d.ID, previous, attempt, evidence, reason, actor); err != nil {
		return err
	}
	// Recording the evidence permits the already authorized ADE prerequisite to
	// be reconsidered. It does not enqueue a replacement mutation by itself.
	if _, err = tx.ExecContext(ctx, `UPDATE mdm_apple_ade_admissions SET next_setup_at=clock_timestamp() WHERE device_id=$1 AND setup_state='awaiting'`, d.ID); err != nil {
		return err
	}
	if err = audit(ctx, tx, scope.TenantID, actor, "apple.software.reenrollment.resolve", receipt); err != nil {
		return err
	}
	return tx.Commit()
}

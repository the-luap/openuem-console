package inventory

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"io/fs"
	"log/slog"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
)

var (
	ErrRefreshInvalid  = errors.New("invalid inventory refresh request")
	ErrRefreshConflict = errors.New("inventory refresh request changed or is already pending")
	ErrRefreshRecent   = errors.New("inventory refresh was requested recently")
	ErrRefreshNotReady = errors.New("inventory refresh is not available for this device")
)

// ReportPublisher returns nil only after the broker acknowledges the exact
// device command and request ID. It must honor cancellation and never log payloads.
type ReportPublisher func(context.Context, string, string) error

type RefreshStore struct {
	db          *sql.DB
	permissions *access.Store
	individual  bool
	publish     ReportPublisher
	wake        chan struct{}
}

func NewRefreshStore(db *sql.DB, permissions *access.Store, individual bool, publish ReportPublisher) (*RefreshStore, error) {
	if db == nil || permissions == nil || publish == nil || db.Stats().MaxOpenConnections == 1 {
		return nil, errors.New("inventory refresh requires access control, a publisher and at least two database connections")
	}
	return &RefreshStore{db: db, permissions: permissions, individual: individual, publish: publish, wake: make(chan struct{}, 1)}, nil
}

//go:embed migrations/*.sql
var refreshMigrations embed.FS

func (s *RefreshStore) Migrate(ctx context.Context) error { return Migrate(ctx, s.db) }

// Migrate installs shared inventory state without starting the refresh worker.
func Migrate(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684629901)`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS uem_inventory_migrations(name TEXT PRIMARY KEY,applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())`); err != nil {
		return err
	}
	names, err := fs.Glob(refreshMigrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		var applied bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_inventory_migrations WHERE name=$1)`, name).Scan(&applied); err != nil {
			return err
		}
		if applied {
			continue
		}
		body, err := refreshMigrations.ReadFile(name)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, string(body)); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO uem_inventory_migrations(name) VALUES($1)`, name); err != nil {
			return err
		}
	}
	var tagGuard bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid=pg_catalog.to_regclass('tags') AND tgname='uem_tag_revision' AND tgtype=23 AND tgenabled IN ('O','A') AND tgfoid=pg_catalog.to_regprocedure('uem_tag_revision()')) AND EXISTS(SELECT 1 FROM pg_catalog.pg_attribute WHERE attrelid=pg_catalog.to_regclass('tags') AND attname='uem_revision' AND attnotnull AND NOT attisdropped AND atttypid='uuid'::regtype)`).Scan(&tagGuard); err != nil {
		return err
	}
	if !tagGuard {
		return errors.New("tag revision protection is incomplete")
	}
	for _, guard := range []struct {
		table, name string
		kind        int
	}{
		{"agents", "uem_netbird_agent_binding", 21},
		{"site_agents", "uem_netbird_scope_binding", 29},
		{"sites", "uem_netbird_site_binding", 17},
		{"netbirds", "uem_netbird_installation_binding", 29},
		{"uem_netbird_operation_attempts", "uem_netbird_attempt_immutable", 27},
		{"uem_netbird_operations", "uem_netbird_operation_immutable", 27},
		{"uem_netbird_operations", "uem_netbird_wire_receipt", 23},
		{"uem_netbird_resolution_retries", "uem_netbird_resolution_retry_immutable", 27},
		{"uem_netbird_resolution_retries", "uem_netbird_resolution_retry_valid", 7},
		{"uem_netbird_cleanup_retries", "uem_netbird_cleanup_retry_immutable", 27},
		{"uem_netbird_cleanup_retries", "uem_netbird_cleanup_retry_valid", 7},
		{"uem_netbird_peer_bindings", "uem_netbird_peer_binding_immutable", 27},
		{"uem_netbird_peer_bindings", "uem_netbird_peer_binding_valid", 7},
		{"uem_netbird_peer_removals", "uem_netbird_peer_removal_immutable", 27},
		{"uem_netbird_peer_removals", "uem_netbird_peer_removal_valid", 7},
		{"uem_netbird_peer_absence", "uem_netbird_peer_absence_immutable", 27},
		{"uem_netbird_peer_absence", "uem_netbird_peer_absence_valid", 7},
		{"uem_netbird_packages", "uem_netbird_package_immutable", 27},
		{"uem_netbird_package_revocations", "uem_netbird_package_revocation_immutable", 27},
		{"uem_netbird_package_revocations", "uem_netbird_package_revocation_valid", 7},
		{"uem_netbird_installations", "uem_netbird_installation_immutable", 27},
		{"uem_netbird_installations", "uem_netbird_installation_approval_valid", 7},
		{"uem_netbird_installations", "uem_netbird_registration_admission", 7},
		{"uem_netbird_installations", "uem_netbird_installation_completion_valid", 23},
		{"uem_netbird_installations", "uem_netbird_installation_release_required", 23},
		{"uem_netbird_installation_attempts", "uem_netbird_installation_attempt_immutable", 27},
		{"uem_netbird_installation_attempts", "uem_netbird_installation_attempt_valid", 7},
		{"uem_netbird_installation_results", "uem_netbird_installation_result_immutable", 27},
		{"uem_netbird_installation_results", "uem_netbird_installation_result_valid", 7},
		{"uem_netbird_installation_observations", "uem_netbird_installation_observation_immutable", 27},
		{"uem_netbird_installation_observations", "uem_netbird_installation_observation_valid", 7},
		{"uem_netbird_installation_reviews", "uem_netbird_installation_review_immutable", 27},
		{"uem_netbird_installation_reviews", "uem_netbird_installation_review_valid", 7},
		{"uem_netbird_installation_resolutions", "uem_netbird_installation_resolution_immutable", 27},
		{"uem_netbird_installation_resolutions", "uem_netbird_installation_resolution_valid", 7},
		{"uem_netbird_installation_controls", "uem_netbird_installation_control_immutable", 27},
		{"uem_netbird_installation_controls", "uem_netbird_installation_control_valid", 7},
		{"uem_netbird_installation_control_results", "uem_netbird_installation_control_result_immutable", 27},
		{"uem_netbird_installation_control_results", "uem_netbird_installation_control_result_valid", 7},
		{"uem_netbird_installation_release_proofs", "uem_netbird_installation_release_proof_immutable", 27},
		{"uem_netbird_installation_release_proofs", "uem_netbird_installation_release_proof_valid", 7},
		{"uem_netbird_removals", "uem_netbird_removal_immutable", 27},
		{"uem_netbird_removals", "uem_netbird_removal_initial", 7},
		{"uem_netbird_removals", "uem_netbird_registration_admission", 7},
		{"uem_netbird_removals", "uem_netbird_removal_completion_valid", 23},
		{"uem_netbird_removals", "uem_netbird_removal_release_required", 23},
		{"uem_netbird_removal_attempts", "uem_netbird_removal_attempt_immutable", 27},
		{"uem_netbird_removal_attempts", "uem_netbird_removal_attempt_valid", 7},
		{"uem_netbird_removal_results", "uem_netbird_removal_result_immutable", 27},
		{"uem_netbird_removal_results", "uem_netbird_removal_result_valid", 7},
		{"uem_netbird_removal_observations", "uem_netbird_removal_observation_immutable", 27},
		{"uem_netbird_removal_observations", "uem_netbird_removal_observation_valid", 7},
		{"uem_netbird_removal_reviews", "uem_netbird_removal_review_immutable", 27},
		{"uem_netbird_removal_reviews", "uem_netbird_removal_review_valid", 7},
		{"uem_netbird_removal_resolutions", "uem_netbird_removal_resolution_immutable", 27},
		{"uem_netbird_removal_resolutions", "uem_netbird_removal_resolution_valid", 7},
		{"uem_netbird_removal_controls", "uem_netbird_removal_control_immutable", 27},
		{"uem_netbird_removal_controls", "uem_netbird_removal_control_valid", 7},
		{"uem_netbird_removal_control_results", "uem_netbird_removal_control_result_immutable", 27},
		{"uem_netbird_removal_control_results", "uem_netbird_removal_control_result_valid", 7},
		{"uem_netbird_removal_release_proofs", "uem_netbird_removal_release_proof_immutable", 27},
		{"uem_netbird_removal_release_proofs", "uem_netbird_removal_release_proof_valid", 7},
		{"uem_netbird_installation_dispatch_stops", "uem_netbird_installation_dispatch_stop_immutable", 27},
		{"uem_netbird_installation_dispatch_stops", "uem_netbird_installation_dispatch_stop_valid", 7},
		{"uem_netbird_preparations", "uem_netbird_installation_dispatch_required", 7},
		{"uem_netbird_installation_attempts", "uem_netbird_installation_dispatch_required", 7},
		{"uem_netbird_removal_dispatch_stops", "uem_netbird_removal_dispatch_stop_immutable", 27},
		{"uem_netbird_removal_dispatch_stops", "uem_netbird_removal_dispatch_stop_valid", 7},
		{"uem_netbird_removal_attempts", "uem_netbird_removal_dispatch_required", 7},
		{"uem_netbird_removal_recoveries", "uem_netbird_removal_recovery_initial", 7},
		{"uem_netbird_removal_recoveries", "uem_netbird_removal_recovery_immutable", 27},
		{"uem_netbird_removal_recoveries", "uem_netbird_registration_admission", 7},
		{"uem_netbird_removal_recovery_attempts", "uem_netbird_removal_recovery_attempt_immutable", 27},
		{"uem_netbird_removal_recovery_attempts", "uem_netbird_removal_recovery_attempt_valid", 7},
		{"uem_netbird_removal_recovery_results", "uem_netbird_removal_recovery_result_immutable", 27},
		{"uem_netbird_removal_recovery_results", "uem_netbird_removal_recovery_result_valid", 7},
		{"uem_netbird_removal_recovery_observations", "uem_netbird_removal_recovery_observation_immutable", 27},
		{"uem_netbird_removal_recovery_observations", "uem_netbird_removal_recovery_observation_valid", 7},
		{"uem_netbird_removal_recoveries", "uem_netbird_removal_recovery_completion_valid", 23},
		{"uem_netbird_removal_recoveries", "uem_netbird_removal_recovery_release_required", 23},
		{"uem_netbird_removal_recovery_dispatch_stops", "uem_netbird_removal_recovery_dispatch_stop_immutable", 27},
		{"uem_netbird_removal_recovery_dispatch_stops", "uem_netbird_removal_recovery_dispatch_stop_valid", 7},
		{"uem_netbird_removal_recovery_attempts", "uem_netbird_removal_recovery_dispatch_required", 7},
		{"uem_netbird_removal_recovery_reviews", "uem_netbird_removal_recovery_review_immutable", 27},
		{"uem_netbird_removal_recovery_reviews", "uem_netbird_removal_recovery_review_valid", 7},
		{"uem_netbird_removal_recovery_resolutions", "uem_netbird_removal_recovery_resolution_immutable", 27},
		{"uem_netbird_removal_recovery_resolutions", "uem_netbird_removal_recovery_resolution_valid", 7},
		{"uem_netbird_removal_recovery_controls", "uem_netbird_removal_recovery_control_immutable", 27},
		{"uem_netbird_removal_recovery_controls", "uem_netbird_removal_recovery_control_valid", 7},
		{"uem_netbird_removal_recovery_control_results", "uem_netbird_removal_recovery_control_result_immutable", 27},
		{"uem_netbird_removal_recovery_control_results", "uem_netbird_removal_recovery_control_result_valid", 7},
		{"uem_netbird_removal_recovery_release_proofs", "uem_netbird_removal_recovery_release_proof_immutable", 27},
		{"uem_netbird_removal_recovery_release_proofs", "uem_netbird_removal_recovery_release_proof_valid", 7},
		{"uem_netbird_removal_absences", "uem_netbird_removal_absence_initial", 7},
		{"uem_netbird_removal_absences", "uem_netbird_removal_absence_immutable", 27},
		{"uem_netbird_removal_absences", "uem_netbird_registration_admission", 7},
		{"uem_netbird_removal_absence_attempts", "uem_netbird_removal_absence_attempt_immutable", 27},
		{"uem_netbird_removal_absence_attempts", "uem_netbird_removal_absence_attempt_valid", 7},
		{"uem_netbird_removal_absence_results", "uem_netbird_removal_absence_result_immutable", 27},
		{"uem_netbird_removal_absence_results", "uem_netbird_removal_absence_result_valid", 7},
		{"uem_netbird_removal_absence_observations", "uem_netbird_removal_absence_observation_immutable", 27},
		{"uem_netbird_removal_absence_observations", "uem_netbird_removal_absence_observation_valid", 7},
		{"uem_netbird_removal_absences", "uem_netbird_removal_absence_completion_valid", 23},
		{"uem_netbird_removal_absences", "uem_netbird_removal_absence_release_required", 23},
		{"uem_netbird_removal_absence_dispatch_stops", "uem_netbird_removal_absence_dispatch_stop_immutable", 27},
		{"uem_netbird_removal_absence_dispatch_stops", "uem_netbird_removal_absence_dispatch_stop_valid", 7},
		{"uem_netbird_removal_absence_attempts", "uem_netbird_removal_absence_dispatch_required", 7},
		{"uem_netbird_removal_absence_reviews", "uem_netbird_removal_absence_review_immutable", 27},
		{"uem_netbird_removal_absence_reviews", "uem_netbird_removal_absence_review_valid", 7},
		{"uem_netbird_removal_absence_resolutions", "uem_netbird_removal_absence_resolution_immutable", 27},
		{"uem_netbird_removal_absence_resolutions", "uem_netbird_removal_absence_resolution_valid", 7},
		{"uem_netbird_removal_absence_controls", "uem_netbird_removal_absence_control_immutable", 27},
		{"uem_netbird_removal_absence_controls", "uem_netbird_removal_absence_control_valid", 7},
		{"uem_netbird_removal_absence_control_results", "uem_netbird_removal_absence_control_result_immutable", 27},
		{"uem_netbird_removal_absence_control_results", "uem_netbird_removal_absence_control_result_valid", 7},
		{"uem_netbird_removal_absence_release_proofs", "uem_netbird_removal_absence_release_proof_immutable", 27},
		{"uem_netbird_removal_absence_release_proofs", "uem_netbird_removal_absence_release_proof_valid", 7},
		{"uem_netbird_preparations", "uem_netbird_preparation_immutable", 27},
		{"uem_netbird_preparations", "uem_netbird_preparation_valid", 7},
		{"uem_netbird_preparation_results", "uem_netbird_preparation_result_immutable", 27},
		{"uem_netbird_preparation_results", "uem_netbird_preparation_result_valid", 7},
		{"uem_netbird_resolutions", "uem_netbird_resolution_immutable", 27},
		{"uem_netbird_resolutions", "uem_netbird_resolution_intent_valid", 7},
		{"uem_netbird_resolution_evidence", "uem_netbird_resolution_evidence_immutable", 27},
		{"uem_netbird_resolution_evidence", "uem_netbird_resolution_evidence_valid", 7},
		{"uem_netbird_operations", "uem_netbird_resolution_required", 23},
		{"uem_netbird_registrations", "uem_netbird_registration_immutable", 27},
		{"uem_netbird_registration_attempts", "uem_netbird_registration_attempt_immutable", 27},
		{"uem_netbird_registration_attempts", "uem_netbird_registration_attempt_valid", 7},
		{"uem_netbird_registration_evidence", "uem_netbird_registration_evidence_immutable", 27},
		{"uem_netbird_registration_evidence", "uem_netbird_registration_evidence_valid", 7},
		{"uem_netbird_registrations", "uem_netbird_registration_admission", 7},
		{"uem_netbird_operations", "uem_netbird_registration_admission", 7},
		{"uem_netbird_registration_resolutions", "uem_netbird_registration_intent_immutable", 27},
		{"uem_netbird_registration_resolutions", "uem_netbird_registration_resolution_valid", 7},
		{"uem_netbird_registration_resolution_attempts", "uem_netbird_registration_control_immutable", 27},
		{"uem_netbird_registration_resolution_attempts", "uem_netbird_registration_control_valid", 7},
		{"uem_netbird_registration_resolution_evidence", "uem_netbird_registration_proof_immutable", 27},
		{"uem_netbird_registration_resolution_evidence", "uem_netbird_registration_proof_valid", 7},
		{"uem_netbird_registrations", "uem_netbird_registration_release_required", 23},
	} {
		var valid bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid=pg_catalog.to_regclass($1) AND tgname=$2 AND tgtype=$3 AND tgenabled IN ('O','A') AND tgfoid=pg_catalog.to_regprocedure($2||'()'))`, guard.table, guard.name, guard.kind).Scan(&valid); err != nil {
			return err
		}
		if !valid {
			return errors.New("NetBird operation protection is incomplete")
		}
	}
	return tx.Commit()
}

func ValidReportDeviceID(id string) bool {
	if len(id) == 0 || len(id) > 255 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func canonicalRequestID(id string) bool {
	parsed, err := uuid.Parse(id)
	return err == nil && parsed != uuid.Nil && parsed.String() == id
}

type RefreshRequest struct {
	ID, DeviceID, Actor, Status           string
	TenantID, SiteID                      int
	Individual                            bool
	RequestedAt, ExpiresAt, NextAttemptAt time.Time
	FinishedAt                            *time.Time
	Attempts                              int
}

const refreshColumns = `r.id,r.device_id,r.tenant_id,r.site_id,r.actor,r.individual,r.status,r.requested_at,r.expires_at,r.next_attempt_at,r.finished_at,
 (SELECT count(*) FROM uem_inventory_refresh_audit e WHERE e.request_id=r.id AND e.action='inventory.refresh.attempt')`

func scanRefresh(row *sql.Row) (*RefreshRequest, error) {
	var r RefreshRequest
	var finished sql.NullTime
	err := row.Scan(&r.ID, &r.DeviceID, &r.TenantID, &r.SiteID, &r.Actor, &r.Individual, &r.Status, &r.RequestedAt, &r.ExpiresAt, &r.NextAttemptAt, &finished, &r.Attempts)
	if err != nil {
		return nil, err
	}
	if finished.Valid {
		r.FinishedAt = &finished.Time
	}
	return &r, nil
}

// target holds membership writes and the device/site rows until dispatch ends.
// The table lock also prevents a new hidden edge being inserted after validation.
// Network handoff is separately bounded to two seconds; readers remain available.
func (s *RefreshStore) target(ctx context.Context, tx *sql.Tx, scope access.Scope, id string) (access.Scope, error) {
	if scope.TenantID <= 0 || scope.SiteID < 0 || !ValidReportDeviceID(id) {
		return access.Scope{}, ErrRefreshInvalid
	}
	if _, err := tx.ExecContext(ctx, `LOCK TABLE site_agents IN SHARE MODE`); err != nil {
		return access.Scope{}, err
	}
	var actual access.Scope
	var status string
	err := tx.QueryRowContext(ctx, `SELECT s.tenant_sites,s.id,a.agent_status FROM agents a JOIN site_agents sa ON sa.agent_id=a.oid JOIN sites s ON s.id=sa.site_id
 WHERE a.oid=$1 AND s.tenant_sites=$2 AND ($3::bigint=0 OR s.id=$3) AND (SELECT count(*) FROM site_agents WHERE agent_id=a.oid)=1 FOR SHARE OF a,s`, id, scope.TenantID, scope.SiteID).Scan(&actual.TenantID, &actual.SiteID, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return actual, ErrNotFound
	}
	if err != nil {
		return actual, err
	}
	if status != "Enabled" && status != "No contact" {
		return actual, ErrRefreshNotReady
	}
	if s.individual {
		if !canonicalRequestID(id) {
			return actual, ErrRefreshNotReady
		}
		var active bool
		err = tx.QueryRowContext(ctx, `SELECT i.revoked_at IS NULL AND i.certificate_expires_at>clock_timestamp() AND q.desired_active AND q.completed_revision=q.revision
 FROM uem_agent_identities i JOIN uem_agent_command_consumers q ON q.device_id=i.id
 WHERE i.id=$1 AND i.tenant_id=$2 AND i.site_id=$3 FOR SHARE OF i,q`, id, actual.TenantID, actual.SiteID).Scan(&active)
		if errors.Is(err, sql.ErrNoRows) || err == nil && !active {
			return actual, ErrRefreshNotReady
		}
		if err != nil {
			return actual, err
		}
	}
	return actual, nil
}

type refreshExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func refreshAudit(ctx context.Context, db refreshExecutor, r *RefreshRequest, action, result string) error {
	_, err := db.ExecContext(ctx, `INSERT INTO uem_inventory_refresh_audit(request_id,tenant_id,site_id,actor,action,resource_id,result) VALUES($1,$2,$3,$4,$5,$6,$7)`, r.ID, r.TenantID, r.SiteID, r.Actor, "inventory.refresh."+action, r.DeviceID, result)
	return err
}

func (s *RefreshStore) Request(ctx context.Context, actor string, scope access.Scope, deviceID, requestID string) (*RefreshRequest, error) {
	if !canonicalRequestID(requestID) || !ValidReportDeviceID(deviceID) {
		return nil, ErrRefreshInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = s.permissions.AuthorizeTransaction(ctx, tx, actor, access.RefreshDevices, scope); err != nil {
		return nil, err
	}
	actual, err := s.target(ctx, tx, scope, deviceID)
	if err != nil {
		return nil, err
	}
	// Serialize admission across different request IDs, accounts and replicas.
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684629902,hashtext($1))`, deviceID); err != nil {
		return nil, err
	}
	r, err := scanRefresh(tx.QueryRowContext(ctx, `SELECT `+refreshColumns+` FROM uem_inventory_refresh r WHERE r.id=$1`, requestID))
	if err == nil {
		if r.Actor != actor || r.DeviceID != deviceID || r.TenantID != actual.TenantID || r.SiteID != actual.SiteID || r.Individual != s.individual {
			return nil, ErrRefreshConflict
		}
		return r, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	var pending, recent bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_inventory_refresh WHERE device_id=$1 AND status='queued'),EXISTS(SELECT 1 FROM uem_inventory_refresh WHERE device_id=$1 AND requested_at>clock_timestamp()-interval '1 minute')`, deviceID).Scan(&pending, &recent)
	if err != nil {
		return nil, err
	}
	if pending {
		return nil, ErrRefreshConflict
	}
	if recent {
		return nil, ErrRefreshRecent
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_inventory_refresh(id,device_id,tenant_id,site_id,actor,individual) VALUES($1,$2,$3,$4,$5,$6)`, requestID, deviceID, actual.TenantID, actual.SiteID, actor, s.individual); err != nil {
		return nil, err
	}
	r, err = scanRefresh(tx.QueryRowContext(ctx, `SELECT `+refreshColumns+` FROM uem_inventory_refresh r WHERE r.id=$1`, requestID))
	if err != nil {
		return nil, err
	}
	if err = refreshAudit(ctx, tx, r, "request", "recorded"); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
	return r, nil
}

func (s *RefreshStore) Latest(ctx context.Context, actor string, scope access.Scope, deviceID string) (*RefreshRequest, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = s.permissions.AuthorizeTransaction(ctx, tx, actor, access.ReadDevices, scope); err != nil {
		return nil, err
	}
	r, err := scanRefresh(tx.QueryRowContext(ctx, `SELECT `+refreshColumns+` FROM uem_inventory_refresh r
 WHERE r.device_id=$1 AND r.tenant_id=$2 AND ($3::bigint=0 OR r.site_id=$3)
 AND EXISTS(SELECT 1 FROM agents a JOIN site_agents sa ON sa.agent_id=a.oid JOIN sites s ON s.id=sa.site_id WHERE a.oid=r.device_id AND s.id=r.site_id AND s.tenant_sites=r.tenant_id AND a.agent_status<>'WaitingForAdmission' AND (SELECT count(*) FROM site_agents WHERE agent_id=a.oid)=1)
 ORDER BY r.requested_at DESC,r.id DESC LIMIT 1`, deviceID, scope.TenantID, scope.SiteID))
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	return r, tx.Commit()
}

func finishRefresh(ctx context.Context, tx *sql.Tx, r *RefreshRequest, status string) error {
	if _, err := tx.ExecContext(ctx, `UPDATE uem_inventory_refresh SET status=$2,finished_at=clock_timestamp() WHERE id=$1`, r.ID, status); err != nil {
		return err
	}
	result := "cancelled"
	if status == "accepted" {
		result = "success"
	} else if status == "unconfirmed" {
		result = "failure"
	}
	if err := refreshAudit(ctx, tx, r, status, result); err != nil {
		return err
	}
	return tx.Commit()
}

// DispatchOne commits attempt evidence before contacting the broker, while the
// authorization transaction holds grants, topology and request ownership. Lost
// acknowledgements are retried with the same broker message ID. Duplicate report
// collection remains possible beyond the broker's deduplication window; no state
// ever claims that the device completed its report merely because it was queued.
func (s *RefreshStore) DispatchOne(ctx context.Context) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock_shared(684627902)`); err != nil {
		return false, err
	}
	r, err := scanRefresh(tx.QueryRowContext(ctx, `SELECT `+refreshColumns+` FROM uem_inventory_refresh r WHERE r.status='queued' AND r.next_attempt_at<=clock_timestamp() ORDER BY r.next_attempt_at,r.id FOR UPDATE OF r SKIP LOCKED LIMIT 1`))
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	stop := func() (bool, error) {
		status := "stopped"
		if r.Attempts > 0 {
			status = "unconfirmed"
		}
		return true, finishRefresh(ctx, tx, r, status)
	}
	if r.Individual != s.individual || !time.Now().Before(r.ExpiresAt) || r.Attempts >= 5 {
		return stop()
	}
	scope := access.Scope{TenantID: r.TenantID, SiteID: r.SiteID}
	err = s.permissions.AuthorizeTransaction(ctx, tx, r.Actor, access.RefreshDevices, scope)
	if errors.Is(err, access.ErrDenied) {
		return stop()
	}
	if err != nil {
		return true, err
	}
	if _, err = s.target(ctx, tx, scope, r.DeviceID); err != nil {
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrRefreshNotReady) || errors.Is(err, ErrRefreshInvalid) {
			return stop()
		}
		return true, err
	}
	// This independent commit is intentional. It uses a second connection and
	// survives rollback/loss of this dispatch transaction after external delivery.
	if err = refreshAudit(ctx, s.db, r, "attempt", "recorded"); err != nil {
		return true, err
	}
	r.Attempts++
	handoff, endHandoff := context.WithTimeout(ctx, 2*time.Second)
	err = s.publish(handoff, r.DeviceID, r.ID)
	endHandoff()
	if ctx.Err() != nil {
		return true, ctx.Err()
	}
	if err == nil {
		return true, finishRefresh(ctx, tx, r, "accepted")
	}
	if r.Attempts >= 5 {
		return stop()
	}
	delay := 5 * (1 << (r.Attempts - 1))
	if _, err = tx.ExecContext(ctx, `UPDATE uem_inventory_refresh SET next_attempt_at=clock_timestamp()+make_interval(secs=>$2) WHERE id=$1`, r.ID, delay); err != nil {
		return true, err
	}
	if err = refreshAudit(ctx, tx, r, "retry", "deferred"); err != nil {
		return true, err
	}
	return true, tx.Commit()
}

func (s *RefreshStore) Run(ctx context.Context, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for ctx.Err() == nil {
		for i := 0; i < 8 && ctx.Err() == nil; i++ {
			found, err := s.DispatchOne(ctx)
			if err != nil && ctx.Err() == nil {
				logger.Error("Inventory refresh dispatch failed; retained work will retry")
			}
			if err != nil || !found {
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
		case <-ticker.C:
		}
	}
}

package inventory

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

var (
	ErrNetbirdOperationInvalid  = errors.New("invalid NetBird operation")
	ErrNetbirdOperationChanged  = errors.New("NetBird operation source changed")
	ErrNetbirdOperationConflict = errors.New("NetBird operation conflicts with a recorded request")
)

// NetbirdOperationCommand is a single, expiring command. Revision binds the
// reviewed device generation, organization configuration and selected profile.
// It contains no provider token or setup key.
type NetbirdOperationCommand struct {
	RequestID, DeviceID, Revision, Operation, Profile string
	RequestedAt, ExpiresAt                            time.Time
}

// A successful result must correlate with the complete command identity. An
// empty broker acknowledgement is not execution evidence. Success describes
// this command, not the lasting connection state or provider peer ownership.
type NetbirdOperationResult struct {
	RequestID string `json:"request_id"`
	DeviceID  string `json:"device_id"`
	Revision  string `json:"revision"`
	Operation string `json:"operation"`
	Success   bool   `json:"success"`
}

// NetbirdOperationExecutor must honor cancellation, refuse expired commands,
// send at most once and verify a durable, correlated agent execution receipt.
// Legacy NetBird subjects and empty replies do not satisfy this contract.
type NetbirdOperationExecutor func(context.Context, NetbirdOperationCommand) (*NetbirdOperationResult, error)

type NetbirdOperationStore struct {
	db          *sql.DB
	permissions *access.Store
	individual  bool
	execute     NetbirdOperationExecutor
	wake        chan struct{}
}

func NewNetbirdOperationStore(db *sql.DB, permissions *access.Store, individual bool, execute NetbirdOperationExecutor) (*NetbirdOperationStore, error) {
	if db == nil || permissions == nil || execute == nil || db.Stats().MaxOpenConnections == 1 {
		return nil, ErrNetbirdOperationInvalid
	}
	return &NetbirdOperationStore{db: db, permissions: permissions, individual: individual, execute: execute, wake: make(chan struct{}, 1)}, nil
}

type NetbirdOperation struct {
	ID, DeviceID, Actor, Operation, Profile, Revision, Status, Reason string
	Scope                                                             access.Scope
	Individual                                                        bool
	RequestedAt, ExpiresAt                                            time.Time
	FinishedAt, AttemptedAt, ReleasedAt                               *time.Time
	ReleasedBy                                                        string
	Result                                                            *NetbirdOperationResult
}

const netbirdOperationColumns = `r.id,r.device_id,r.tenant_id,r.site_id,r.actor,r.individual,r.operation,r.profile,r.revision,r.status,r.reason,r.requested_at,r.expires_at,r.finished_at,r.released_at,r.released_by,r.result,(SELECT created_at FROM uem_netbird_operation_attempts WHERE request_id=r.id)`

func scanNetbirdOperation(row interface{ Scan(...any) error }) (*NetbirdOperation, error) {
	r := &NetbirdOperation{}
	var finished, attempted, released sql.NullTime
	var releasedBy sql.NullString
	var result []byte
	err := row.Scan(&r.ID, &r.DeviceID, &r.Scope.TenantID, &r.Scope.SiteID, &r.Actor, &r.Individual, &r.Operation, &r.Profile, &r.Revision, &r.Status, &r.Reason, &r.RequestedAt, &r.ExpiresAt, &finished, &released, &releasedBy, &result, &attempted)
	if err != nil {
		return nil, err
	}
	if finished.Valid {
		r.FinishedAt = &finished.Time
	}
	if attempted.Valid {
		r.AttemptedAt = &attempted.Time
	}
	if released.Valid {
		r.ReleasedAt = &released.Time
	}
	r.ReleasedBy = releasedBy.String
	if len(result) > 0 {
		if err = json.Unmarshal(result, &r.Result); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func netbirdOperationAudit(ctx context.Context, db refreshExecutor, r *NetbirdOperation, actor, action, result string) error {
	var id any
	if r.ID != "" {
		id = r.ID
	}
	resource := fmt.Sprintf("device/%s/%s", r.DeviceID, r.Operation)
	if r.ID != "" {
		resource = r.ID + "/" + resource
	}
	_, err := db.ExecContext(ctx, `INSERT INTO uem_netbird_operations_audit(request_id,tenant_id,site_id,actor,action,resource_id,result) VALUES($1,$2,$3,$4,$5,$6,$7)`, id, r.Scope.TenantID, r.Scope.SiteID, actor, "inventory.netbird."+action, resource, result)
	return err
}

func (s *NetbirdOperationStore) Review(parent context.Context, actor string, scope access.Scope, device, operation, profile string) (*NetbirdOperationReview, error) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := s.recordTx(ctx, actor, scope, access.ManageDeviceSecurity)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	review, err := s.source(ctx, tx, scope, device, operation, profile)
	if err != nil {
		return nil, err
	}
	if err = netbirdOperationAudit(ctx, tx, &NetbirdOperation{DeviceID: device, Scope: scope, Operation: operation}, actor, "review", "recorded"); err != nil {
		return nil, err
	}
	return review, tx.Commit()
}

func (s *NetbirdOperationStore) Request(parent context.Context, actor string, scope access.Scope, device, id, operation, profile, revision string) (*NetbirdOperation, error) {
	if !canonicalRequestID(id) || !ValidReportDeviceID(device) || !netbirdOperationInput(operation, profile) || !validManualRevision(revision) {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := s.recordTx(ctx, actor, scope, access.ManageDeviceSecurity)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684629914,hashtext($1))`, device); err != nil {
		return nil, err
	}
	existing, err := scanNetbirdOperation(tx.QueryRowContext(ctx, `SELECT `+netbirdOperationColumns+` FROM uem_netbird_operations r WHERE r.id=$1`, id))
	if err == nil {
		if existing.Actor != actor || existing.DeviceID != device || existing.Scope != scope || existing.Individual != s.individual || existing.Operation != operation || existing.Profile != profile || existing.Revision != revision {
			return nil, ErrNetbirdOperationConflict
		}
		if err = netbirdOperationAudit(ctx, tx, existing, actor, "read", "recorded"); err != nil {
			return nil, err
		}
		return existing, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	var pending bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_netbird_operations WHERE device_id=$1 AND (status='queued' OR (status='unconfirmed' AND released_at IS NULL)))`, device).Scan(&pending); err != nil {
		return nil, err
	}
	if pending {
		return nil, ErrNetbirdOperationConflict
	}
	review, err := s.source(ctx, tx, scope, device, operation, profile)
	if err != nil {
		return nil, err
	}
	if review.Revision != revision {
		return nil, ErrNetbirdOperationChanged
	}
	// A single timestamp gives the immutable command an exact two-minute life.
	_, err = tx.ExecContext(ctx, `WITH stamp AS (SELECT clock_timestamp() AS at) INSERT INTO uem_netbird_operations(id,device_id,tenant_id,site_id,actor,individual,operation,profile,revision,requested_at,expires_at) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,at,at+interval '2 minutes' FROM stamp`, id, device, scope.TenantID, scope.SiteID, actor, s.individual, operation, profile, revision)
	if err != nil {
		return nil, err
	}
	r, err := scanNetbirdOperation(tx.QueryRowContext(ctx, `SELECT `+netbirdOperationColumns+` FROM uem_netbird_operations r WHERE r.id=$1`, id))
	if err != nil {
		return nil, err
	}
	if err = netbirdOperationAudit(ctx, tx, r, actor, "request", "recorded"); err != nil {
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

func netbirdRecorded(ctx context.Context, tx *sql.Tx, scope access.Scope, device, id, lock string) (*NetbirdOperation, error) {
	r, err := scanNetbirdOperation(tx.QueryRowContext(ctx, `SELECT `+netbirdOperationColumns+` FROM uem_netbird_operations r WHERE r.id=$1 AND r.device_id=$2 AND r.tenant_id=$3 AND r.site_id=$4 `+lock, id, device, scope.TenantID, scope.SiteID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return r, err
}

func netbirdAttempt(ctx context.Context, tx *sql.Tx, r *NetbirdOperation) error {
	// Read after acquiring the request lock. A receipt committed while that lock
	// was being acquired may be newer than the locking SELECT's MVCC snapshot.
	var at time.Time
	err := tx.QueryRowContext(ctx, `SELECT created_at FROM uem_netbird_operation_attempts WHERE request_id=$1`, r.ID).Scan(&at)
	if errors.Is(err, sql.ErrNoRows) {
		r.AttemptedAt = nil
		return nil
	}
	if err == nil {
		r.AttemptedAt = &at
	}
	return err
}

// Read authorizes the recorded scope, preserving history after device removal.
func (s *NetbirdOperationStore) Read(parent context.Context, actor string, scope access.Scope, device, id string) (*NetbirdOperation, error) {
	if !canonicalRequestID(id) || !ValidReportDeviceID(device) {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := s.recordTx(ctx, actor, scope, access.ReadDevices)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	r, err := netbirdRecorded(ctx, tx, scope, device, id, "FOR SHARE OF r")
	if err != nil {
		return nil, err
	}
	if err = netbirdOperationAudit(ctx, tx, r, actor, "read", "recorded"); err != nil {
		return nil, err
	}
	return r, tx.Commit()
}

// History returns bounded, stable keyset pages for one recorded device/site.
// The cursor is the last request ID from the preceding page in this same scope.
func (s *NetbirdOperationStore) History(parent context.Context, actor string, scope access.Scope, device, after string) ([]NetbirdOperation, error) {
	if !ValidReportDeviceID(device) || after != "" && !canonicalRequestID(after) {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := s.recordTx(ctx, actor, scope, access.ReadDevices)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	at := time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
	id := "ffffffff-ffff-ffff-ffff-ffffffffffff"
	if after != "" {
		r, err := netbirdRecorded(ctx, tx, scope, device, after, "")
		if err != nil {
			return nil, err
		}
		at = r.RequestedAt
		id = r.ID
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+netbirdOperationColumns+` FROM uem_netbird_operations r WHERE r.device_id=$1 AND r.tenant_id=$2 AND r.site_id=$3 AND (r.requested_at,r.id)<($4,$5::uuid) ORDER BY r.requested_at DESC,r.id DESC LIMIT 50`, device, scope.TenantID, scope.SiteID, at, id)
	if err != nil {
		return nil, err
	}
	result := []NetbirdOperation{}
	for rows.Next() {
		r, scanErr := scanNetbirdOperation(rows)
		if scanErr != nil {
			rows.Close()
			return nil, scanErr
		}
		result = append(result, *r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if err = netbirdOperationAudit(ctx, tx, &NetbirdOperation{DeviceID: device, Scope: scope}, actor, "read", "recorded"); err != nil {
		return nil, err
	}
	return result, tx.Commit()
}

func finishNetbirdOperation(ctx context.Context, tx *sql.Tx, r *NetbirdOperation, actor, status, reason string, result *NetbirdOperationResult) error {
	var data any
	if result != nil {
		encoded, err := json.Marshal(result)
		if err != nil {
			return err
		}
		data = string(encoded)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE uem_netbird_operations SET status=$2,reason=$3,result=$4::jsonb,finished_at=clock_timestamp() WHERE id=$1`, r.ID, status, reason, data); err != nil {
		return err
	}
	outcome := "failure"
	if status == "completed" {
		outcome = "success"
	} else if status == "stopped" {
		outcome = "cancelled"
	}
	if err := netbirdOperationAudit(ctx, tx, r, actor, status, outcome); err != nil {
		return err
	}
	return tx.Commit()
}

// Cancel withdraws an unattempted request. It never promises to interrupt a
// remote command whose durable attempt receipt already exists.
func (s *NetbirdOperationStore) Cancel(parent context.Context, actor string, scope access.Scope, device, id string) error {
	if !canonicalRequestID(id) || !ValidReportDeviceID(device) {
		return ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := s.recordTx(ctx, actor, scope, access.ManageDeviceSecurity)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	r, err := netbirdRecorded(ctx, tx, scope, device, id, "FOR UPDATE OF r")
	if err != nil {
		return err
	}
	if err = netbirdAttempt(ctx, tx, r); err != nil {
		return err
	}
	if r.Status != "queued" || r.AttemptedAt != nil {
		return ErrNetbirdOperationConflict
	}
	return finishNetbirdOperation(ctx, tx, r, actor, "stopped", "cancelled", nil)
}

// Release explicitly acknowledges an uncertain outcome and opens the device
// barrier. Callers must present that uncertainty for operator review; release
// does not stop an old process, establish its result or resubmit its command.
func (s *NetbirdOperationStore) Release(parent context.Context, actor string, scope access.Scope, device, id string) error {
	if !canonicalRequestID(id) || !ValidReportDeviceID(device) {
		return ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := s.recordTx(ctx, actor, scope, access.ManageDeviceSecurity)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	r, err := netbirdRecorded(ctx, tx, scope, device, id, "FOR UPDATE OF r")
	if err != nil {
		return err
	}
	if r.Status != "unconfirmed" {
		return ErrNetbirdOperationConflict
	}
	if r.ReleasedAt != nil {
		return tx.Commit()
	}
	if _, err = tx.ExecContext(ctx, `UPDATE uem_netbird_operations SET released_at=clock_timestamp(),released_by=$2 WHERE id=$1`, id, actor); err != nil {
		return err
	}
	if err = netbirdOperationAudit(ctx, tx, r, actor, "release", "recorded"); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *NetbirdOperationStore) recordAttempt(ctx context.Context, r *NetbirdOperation) error {
	// No foreign key to the locked request: this transaction must commit before
	// any external side effect, even when the outer transaction later rolls back.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_netbird_operation_attempts(request_id,device_id,tenant_id,site_id,actor,operation,revision) VALUES($1,$2,$3,$4,$5,$6,$7)`, r.ID, r.DeviceID, r.Scope.TenantID, r.Scope.SiteID, r.Actor, r.Operation, r.Revision); err != nil {
		return err
	}
	if err = netbirdOperationAudit(ctx, tx, r, r.Actor, "attempt", "recorded"); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *NetbirdOperationStore) DispatchOne(parent context.Context) (bool, error) {
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute+5*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	r, err := scanNetbirdOperation(tx.QueryRowContext(ctx, `SELECT `+netbirdOperationColumns+` FROM uem_netbird_operations r WHERE r.status='queued' ORDER BY r.requested_at,r.id FOR UPDATE OF r SKIP LOCKED LIMIT 1`))
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err = netbirdAttempt(ctx, tx, r); err != nil {
		return true, err
	}
	stop := func(reason string) (bool, error) {
		return true, finishNetbirdOperation(ctx, tx, r, r.Actor, "stopped", reason, nil)
	}
	if r.AttemptedAt != nil {
		return true, finishNetbirdOperation(ctx, tx, r, r.Actor, "unconfirmed", "delivery_unconfirmed", nil)
	}
	if r.Individual != s.individual {
		return stop("mode_changed")
	}
	if !time.Now().Before(r.ExpiresAt) {
		return stop("expired")
	}
	err = s.permissions.AuthorizeTransaction(ctx, tx, r.Actor, access.ManageDeviceSecurity, r.Scope)
	if errors.Is(err, access.ErrDenied) {
		return stop("not_authorized")
	}
	if err != nil {
		return true, err
	}
	source, err := s.source(ctx, tx, r.Scope, r.DeviceID, r.Operation, r.Profile)
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrRefreshNotReady) || errors.Is(err, ErrManualUnsupported) || errors.Is(err, ErrNetbirdOperationChanged) {
		return stop("source_changed")
	}
	if err != nil {
		return true, err
	}
	if source.Revision != r.Revision {
		return stop("source_changed")
	}
	if !source.identityExpiresAt.IsZero() && !time.Now().Before(source.identityExpiresAt) {
		return stop("source_changed")
	}
	if !time.Now().Before(r.ExpiresAt) {
		return stop("expired")
	}
	if err = s.recordAttempt(ctx, r); err != nil {
		return true, err
	}
	expiresAt := r.ExpiresAt
	if !source.identityExpiresAt.IsZero() && source.identityExpiresAt.Before(expiresAt) {
		expiresAt = source.identityExpiresAt
	}
	commandCtx, cancelCommand := context.WithDeadline(ctx, expiresAt)
	command := NetbirdOperationCommand{RequestID: r.ID, DeviceID: r.DeviceID, Revision: r.Revision, Operation: r.Operation, Profile: r.Profile, RequestedAt: r.RequestedAt, ExpiresAt: expiresAt}
	var result *NetbirdOperationResult
	// Do not enter the executor after a slow receipt commit consumes its lifetime.
	if commandCtx.Err() == nil {
		result, err = s.execute(commandCtx, command)
	} else {
		err = commandCtx.Err()
	}
	commandErr := commandCtx.Err()
	cancelCommand()
	if ctx.Err() != nil {
		return true, ctx.Err()
	}
	if err == nil && commandErr == nil && result != nil && result.Success && result.RequestID == r.ID && result.DeviceID == r.DeviceID && result.Revision == r.Revision && result.Operation == r.Operation {
		return true, finishNetbirdOperation(ctx, tx, r, r.Actor, "completed", "", result)
	}
	return true, finishNetbirdOperation(ctx, tx, r, r.Actor, "unconfirmed", "delivery_unconfirmed", nil)
}

func (s *NetbirdOperationStore) Run(ctx context.Context, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
		case <-ticker.C:
		}
		for i := 0; i < 10; i++ {
			worked, err := s.DispatchOne(ctx)
			if err != nil {
				if ctx.Err() == nil {
					logger.Error("NetBird operation dispatch is unavailable")
				}
				break
			}
			if !worked {
				break
			}
		}
	}
}

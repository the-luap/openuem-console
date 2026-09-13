package inventory

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	openuem "github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/taskexecution"
)

var (
	ErrManualInvalid     = errors.New("invalid manual execution request")
	ErrManualChanged     = errors.New("manual execution source changed")
	ErrManualUnsupported = errors.New("manual execution source is unsupported")
	ErrManualConflict    = errors.New("another manual execution request is pending")
	ErrManualRejected    = errors.New("agent rejected the execution request")
)

// The publisher returns nil only for an empty agent acceptance reply. Acceptance
// is not execution. Non-idempotent commands must not be automatically retried.
type ManualPublisher func(context.Context, string, string, *taskexecution.Payload) error

type ManualExecutionStore struct {
	db          *sql.DB
	permissions *access.Store
	individual  bool
	masterKey   string
	publish     ManualPublisher
	wake        chan struct{}
}

func NewManualExecutionStore(db *sql.DB, permissions *access.Store, individual bool, masterKey string, publish ManualPublisher) (*ManualExecutionStore, error) {
	if db == nil || permissions == nil || publish == nil || db.Stats().MaxOpenConnections == 1 {
		return nil, ErrManualInvalid
	}
	return &ManualExecutionStore{db: db, permissions: permissions, individual: individual, masterKey: masterKey, publish: publish, wake: make(chan struct{}, 1)}, nil
}

type ManualRequest struct {
	ID, DeviceID, Actor, Kind, Revision, Status, Reason string
	Scope, SourceScope                                  access.Scope
	SourceID, ProfileID                                 int64
	Individual                                          bool
	RequestedAt, ExpiresAt                              time.Time
	FinishedAt, AttemptedAt                             *time.Time
}

const manualColumns = "r.id,r.device_id,r.tenant_id,r.site_id,r.actor,r.individual,r.kind,r.source_id,r.profile_id,r.source_tenant_id,r.source_site_id,r.revision,r.status,r.reason,r.requested_at,r.expires_at,r.finished_at,(SELECT max(created_at) FROM uem_manual_execution_audit WHERE request_id=r.id AND action='inventory.execution.attempt')"

func scanManual(row *sql.Row) (*ManualRequest, error) {
	r := &ManualRequest{}
	var finished, attempted sql.NullTime
	err := row.Scan(&r.ID, &r.DeviceID, &r.Scope.TenantID, &r.Scope.SiteID, &r.Actor, &r.Individual, &r.Kind, &r.SourceID, &r.ProfileID, &r.SourceScope.TenantID, &r.SourceScope.SiteID, &r.Revision, &r.Status, &r.Reason, &r.RequestedAt, &r.ExpiresAt, &finished, &attempted)
	if err != nil {
		return nil, err
	}
	if finished.Valid {
		r.FinishedAt = &finished.Time
	}
	if attempted.Valid {
		r.AttemptedAt = &attempted.Time
	}
	return r, nil
}

func validManualRevision(value string) bool {
	data, err := hex.DecodeString(value)
	return err == nil && len(data) == 32 && strings.ToLower(value) == value
}

func manualAudit(ctx context.Context, db refreshExecutor, r *ManualRequest, action, result string) error {
	resource := fmt.Sprintf("%s/device/%s/%s/%d/profile/%d", r.ID, r.DeviceID, r.Kind, r.SourceID, r.ProfileID)
	_, err := db.ExecContext(ctx, "INSERT INTO uem_manual_execution_audit(request_id,tenant_id,site_id,actor,action,resource_id,result) VALUES($1,$2,$3,$4,$5,$6,$7)", r.ID, r.Scope.TenantID, r.Scope.SiteID, r.Actor, "inventory.execution."+action, resource, result)
	return err
}

func (s *ManualExecutionStore) Review(parent context.Context, actor string, scope access.Scope, deviceID, kind string, sourceID int64) (*ManualReview, error) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, target, err := s.beginTarget(ctx, actor, scope, deviceID)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	source, err := lockManualSource(ctx, tx, target, kind, sourceID, false)
	if err != nil {
		return nil, err
	}
	resource := fmt.Sprintf("%s/%s/%d/profile/%d", deviceID, kind, sourceID, source.source.ProfileID)
	if _, err = tx.ExecContext(ctx, "INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,$2,$3,'inventory.execution.review',$4)", scope.TenantID, scope.SiteID, actor, resource); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &ManualReview{Target: target, Source: source.source}, nil
}

func (s *ManualExecutionStore) Request(parent context.Context, actor string, scope access.Scope, deviceID, requestID, kind string, sourceID int64, revision string) (*ManualRequest, error) {
	if !canonicalRequestID(requestID) || !ValidReportDeviceID(deviceID) || (kind != "task" && kind != "profile") || sourceID <= 0 || !validManualRevision(revision) {
		return nil, ErrManualInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := s.beginRecord(ctx, actor, scope)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(684629913,hashtext($1))", deviceID); err != nil {
		return nil, err
	}
	existing, err := scanManual(tx.QueryRowContext(ctx, "SELECT "+manualColumns+" FROM uem_manual_execution r WHERE r.id=$1", requestID))
	if err == nil {
		if existing.Actor != actor || existing.DeviceID != deviceID || existing.Scope != scope || existing.Individual != s.individual || existing.Kind != kind || existing.SourceID != sourceID || existing.Revision != revision {
			return nil, ErrManualConflict
		}
		return existing, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	var pending bool
	if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM uem_manual_execution WHERE device_id=$1 AND status='queued')", deviceID).Scan(&pending); err != nil {
		return nil, err
	}
	if pending {
		return nil, ErrManualConflict
	}
	target, err := s.target(ctx, tx, scope, deviceID)
	if err != nil {
		return nil, err
	}
	source, err := lockManualSource(ctx, tx, target, kind, sourceID, kind == "task")
	if err != nil {
		return nil, err
	}
	if source.source.Revision != revision {
		return nil, ErrManualChanged
	}
	// Reject invalid or undecryptable configuration before recording a new intent.
	if kind == "task" {
		if _, err = taskexecution.Build(source.task, s.masterKey); err != nil {
			return nil, ErrManualUnsupported
		}
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO uem_manual_execution(id,device_id,tenant_id,site_id,actor,individual,kind,source_id,profile_id,source_tenant_id,source_site_id,revision) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)", requestID, deviceID, scope.TenantID, scope.SiteID, actor, s.individual, kind, sourceID, source.source.ProfileID, source.source.Scope.TenantID, source.source.Scope.SiteID, revision)
	if err != nil {
		return nil, err
	}
	request, err := scanManual(tx.QueryRowContext(ctx, "SELECT "+manualColumns+" FROM uem_manual_execution r WHERE r.id=$1", requestID))
	if err != nil {
		return nil, err
	}
	if err = manualAudit(ctx, tx, request, "request", "recorded"); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
	return request, nil
}

// Read uses the recorded site, retaining receipts after endpoint/source removal.
func (s *ManualExecutionStore) Read(parent context.Context, actor string, scope access.Scope, deviceID, requestID string) (*ManualRequest, error) {
	if !ValidReportDeviceID(deviceID) || !canonicalRequestID(requestID) {
		return nil, ErrManualInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := s.beginRecord(ctx, actor, scope)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	request, err := scanManual(tx.QueryRowContext(ctx, "SELECT "+manualColumns+" FROM uem_manual_execution r WHERE r.id=$1 AND r.device_id=$2 AND r.tenant_id=$3 AND r.site_id=$4 FOR SHARE OF r", requestID, deviceID, scope.TenantID, scope.SiteID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO uem_inventory_audit(tenant_id,site_id,actor,action,resource_id) VALUES($1,$2,$3,'inventory.execution.read',$4)", scope.TenantID, scope.SiteID, actor, requestID); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return request, nil
}

func finishManual(ctx context.Context, tx *sql.Tx, r *ManualRequest, status, reason string) error {
	if _, err := tx.ExecContext(ctx, "UPDATE uem_manual_execution SET status=$2,reason=$3,finished_at=clock_timestamp() WHERE id=$1", r.ID, status, reason); err != nil {
		return err
	}
	result := "failure"
	if status == "accepted" {
		result = "success"
	} else if status == "stopped" {
		result = "cancelled"
	}
	if err := manualAudit(ctx, tx, r, status, result); err != nil {
		return err
	}
	return tx.Commit()
}

// Attempt evidence is committed on a second connection before the sole send.
// Any later rollback/restart becomes unconfirmed; it never causes a repeat send.
func (s *ManualExecutionStore) DispatchOne(parent context.Context) (bool, error) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	request, err := scanManual(tx.QueryRowContext(ctx, "SELECT "+manualColumns+" FROM uem_manual_execution r WHERE r.status='queued' ORDER BY r.requested_at,r.id FOR UPDATE OF r SKIP LOCKED LIMIT 1"))
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	stop := func(reason string) (bool, error) { return true, finishManual(ctx, tx, request, "stopped", reason) }
	if request.AttemptedAt != nil {
		return true, finishManual(ctx, tx, request, "unconfirmed", "delivery_unconfirmed")
	}
	if request.Individual != s.individual {
		return stop("mode_changed")
	}
	if !time.Now().Before(request.ExpiresAt) {
		return stop("expired")
	}
	for _, scope := range []access.Scope{request.Scope, {}} {
		err = s.permissions.AuthorizeTransaction(ctx, tx, request.Actor, access.ManageProfiles, scope)
		if errors.Is(err, access.ErrDenied) {
			return stop("not_authorized")
		}
		if err != nil {
			return true, err
		}
	}
	target, err := s.target(ctx, tx, request.Scope, request.DeviceID)
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrRefreshNotReady) || errors.Is(err, ErrManualUnsupported) {
		return stop("target_changed")
	}
	if err != nil {
		return true, err
	}
	source, err := lockManualSource(ctx, tx, target, request.Kind, request.SourceID, request.Kind == "task")
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrManualChanged) || errors.Is(err, ErrManualUnsupported) {
		return stop("source_changed")
	}
	if err != nil {
		return true, err
	}
	if source.source.ProfileID != request.ProfileID || source.source.Scope != request.SourceScope || source.source.Revision != request.Revision {
		return stop("source_changed")
	}
	payload := &taskexecution.Payload{Operation: "runprofile"}
	if request.Kind == "task" {
		payload, err = taskexecution.Build(source.task, s.masterKey)
	} else {
		payload.Data, err = json.Marshal(openuem.CfgProfiles{AgentID: request.DeviceID, ProfileID: int(request.ProfileID)})
	}
	if err != nil {
		return stop("configuration_unavailable")
	}
	// Lock acquisition or configuration preparation may have consumed the
	// remaining request lifetime. Expiry is checked again at the handoff.
	if !time.Now().Before(request.ExpiresAt) {
		return stop("expired")
	}
	if err = manualAudit(ctx, s.db, request, "attempt", "recorded"); err != nil {
		return true, err
	}
	handoff, cancelHandoff := context.WithTimeout(ctx, 2*time.Second)
	err = s.publish(handoff, request.DeviceID, request.ID, payload)
	cancelHandoff()
	if ctx.Err() != nil {
		return true, ctx.Err()
	}
	if err == nil {
		return true, finishManual(ctx, tx, request, "accepted", "")
	}
	if errors.Is(err, ErrManualRejected) {
		return true, finishManual(ctx, tx, request, "rejected", "agent_rejected")
	}
	return true, finishManual(ctx, tx, request, "unconfirmed", "delivery_unconfirmed")
}

func (s *ManualExecutionStore) Run(ctx context.Context, logger *slog.Logger) {
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
					logger.Error("manual execution dispatch is unavailable")
				}
				break
			}
			if !worked {
				break
			}
		}
	}
}

package inventory

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/netbirdcommand"
	"github.com/open-uem/openuem-console/internal/security/access"
)

// NetbirdPreparationExecutor sends one direct preparation RPC and bounds local
// waiting by its context. Cancellation cannot retract remote work already sent.
// It never invokes an installer or retries an uncertain response.
type NetbirdPreparationExecutor func(context.Context, netbirdcommand.PreparationRequest) (*netbirdcommand.PreparationResponse, error)

// NewNetbirdInstallationPreparationStore requires both explicit native
// capabilities. Construction starts no worker and creates no installation route.
func NewNetbirdInstallationPreparationStore(db *sql.DB, permissions *access.Store, individual bool, master string, control NetbirdOperationControl, prepare NetbirdPreparationExecutor) (*NetbirdInstallationStore, error) {
	if control == nil || prepare == nil {
		return nil, ErrNetbirdOperationInvalid
	}
	inspect := func(ctx context.Context, identity netbirdcommand.Identity) (netbirdcommand.State, error) {
		var state netbirdcommand.State
		for _, kind := range []string{"preparation-state", "installation-state"} {
			now := time.Now().UTC()
			c := netbirdcommand.ControlRequest{Version: netbirdcommand.Version, Identity: identity, RequestID: uuid.NewString(), Kind: kind, IssuedAt: now, ExpiresAt: now.Add(2 * time.Second)}
			if deadline, ok := ctx.Deadline(); ok && deadline.Before(c.ExpiresAt) {
				c.ExpiresAt = deadline
			}
			if !c.Executable(identity, now) || ctx.Err() != nil {
				return netbirdcommand.State{}, ErrNetbirdOperationNotReady
			}
			response, err := control(ctx, c)
			if err != nil || ctx.Err() != nil || response == nil || !response.Matches(c) || response.Outcome != "ok" || response.State.Status != "ready" {
				return netbirdcommand.State{}, ErrNetbirdOperationNotReady
			}
			if kind == "installation-state" && state != response.State {
				return netbirdcommand.State{}, ErrNetbirdOperationNotReady
			}
			state = response.State
		}
		return state, nil
	}
	s, err := NewNetbirdInstallationStore(db, permissions, individual, master, inspect)
	if err != nil {
		return nil, err
	}
	s.prepare = prepare
	return s, nil
}

// NetbirdInstallationPreparation is historical source-free evidence. Prepared
// does not prove that the ephemeral agent cache or current authority still exists.
// A missing result is pending/uncertain and never authorizes another delivery.
type NetbirdInstallationPreparation struct {
	RequestID, RequestHash, Outcome string
	IssuedAt, ExpiresAt             time.Time
	RecordedAt                      *time.Time
}

func preparationAudit(ctx context.Context, tx *sql.Tx, r *NetbirdInstallation, stage string) error {
	return netbirdOperationAudit(ctx, tx, &NetbirdOperation{ID: r.ID, DeviceID: r.DeviceID, Scope: r.Scope, Operation: "install/" + stage}, r.Actor, "attempt", "recorded")
}

func readInstallationPreparation(ctx context.Context, tx *sql.Tx, id string) (*NetbirdInstallationPreparation, error) {
	var p NetbirdInstallationPreparation
	err := tx.QueryRowContext(ctx, `SELECT p.request_id::text,p.request_hash,p.issued_at,p.expires_at,coalesce(r.outcome,'pending'),r.recorded_at FROM uem_netbird_preparations p LEFT JOIN uem_netbird_preparation_results r USING(request_id) WHERE p.request_id=$1`, id).Scan(&p.RequestID, &p.RequestHash, &p.IssuedAt, &p.ExpiresAt, &p.Outcome, &p.RecordedAt)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// Prepare commits exact intent before its only RPC, then records correlated
// evidence independently. No database connection or authorization lock is held
// across the download. Native command admission must recheck all authority later.
func (s *NetbirdInstallationStore) Prepare(parent context.Context, actor string, scope access.Scope, device, id, revision string) (*NetbirdInstallationPreparation, error) {
	if parent == nil || !canonicalRequestID(device) || !canonicalRequestID(id) || !netbirdcommand.ValidDigest(revision) || s.prepare == nil {
		return nil, ErrNetbirdOperationInvalid
	}
	r, p, request, err := s.admitPreparation(parent, actor, scope, device, id, revision)
	if err != nil || request == nil {
		return p, err
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Minute)
	defer cancel()
	call, finish := context.WithDeadline(ctx, request.ExpiresAt)
	defer finish()
	var response *netbirdcommand.PreparationResponse
	if call.Err() == nil {
		response, err = s.prepare(call, *request)
	}
	outcome := "unconfirmed"
	var data []byte
	if err == nil && call.Err() == nil && response != nil && response.Matches(*request) && time.Now().Before(request.ExpiresAt) {
		data, err = netbirdcommand.EncodePreparationResponse(*request, *response)
		if err == nil {
			outcome = response.Outcome
		}
	}
	// Appending the result of already-authorized work is not a new action. Retain
	// uncertainty even if the caller disconnected or its rights changed meanwhile.
	record, stop := context.WithTimeout(context.WithoutCancel(parent), 10*time.Second)
	defer stop()
	return s.finishPreparation(record, r, outcome, data)
}

func (s *NetbirdInstallationStore) admitPreparation(parent context.Context, actor string, scope access.Scope, device, id, revision string) (*NetbirdInstallation, *NetbirdInstallationPreparation, *netbirdcommand.PreparationRequest, error) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, actor, scope, access.AssignSoftware)
	if err != nil {
		return nil, nil, nil, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684629914,hashtext($1))`, device); err != nil {
		return nil, nil, nil, err
	}
	r, err := scanInstallation(tx.QueryRowContext(ctx, `SELECT `+installationColumns+` FROM uem_netbird_installations WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4 FOR UPDATE`, id, device, scope.TenantID, scope.SiteID))
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	if err != nil {
		return nil, nil, nil, err
	}
	if r.Actor != actor || r.Revision != revision {
		return nil, nil, nil, ErrNetbirdOperationConflict
	}
	p, err := readInstallationPreparation(ctx, tx, id)
	if err == nil {
		if err = installationAudit(ctx, tx, actor, r, "read", "recorded"); err != nil {
			return nil, nil, nil, err
		}
		return r, p, nil, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil, err
	}
	stopped, err := readInstallationDispatchStop(ctx, tx, id)
	if err != nil {
		return nil, nil, nil, err
	}
	if stopped != nil {
		return nil, nil, nil, ErrNetbirdOperationConflict
	}
	if r.CancelledAt != nil || !time.Now().Before(r.ExpiresAt) {
		return nil, nil, nil, ErrNetbirdOperationConflict
	}
	source, err := s.source(ctx, tx, scope, device, r.ApprovalID, r.ApprovalDigest)
	if err != nil {
		return nil, nil, nil, err
	}
	if source.review.Revision != revision || source.review.Journal.Revision != r.JournalRevision {
		return nil, nil, nil, ErrNetbirdOperationChanged
	}
	var issued time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&issued); err != nil {
		return nil, nil, nil, err
	}
	expires := r.ExpiresAt
	if source.identityExpiresAt.Before(expires) {
		expires = source.identityExpiresAt
	}
	request := netbirdcommand.PreparationRequest{Version: netbirdcommand.PreparationVersion, Identity: source.identity, RequestID: id, Revision: revision, JournalRevision: r.JournalRevision, Package: source.packageDescriptor, IssuedAt: issued.UTC(), ExpiresAt: expires.UTC()}
	if !request.Executable(source.identity, time.Now()) {
		return nil, nil, nil, ErrNetbirdOperationChanged
	}
	hash, err := request.Digest()
	if err != nil {
		return nil, nil, nil, ErrNetbirdOperationInvalid
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO uem_netbird_preparations(request_id,wire_version,certificate_hash,request_hash,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,$6)`, id, request.Version, request.CertificateHash, hash, request.IssuedAt, request.ExpiresAt)
	if err != nil {
		return nil, nil, nil, err
	}
	if err = preparationAudit(ctx, tx, r, "prepare"); err != nil {
		return nil, nil, nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, nil, nil, err
	}
	return r, nil, &request, nil
}

func (s *NetbirdInstallationStore) finishPreparation(ctx context.Context, r *NetbirdInstallation, outcome string, data []byte) (*NetbirdInstallationPreparation, error) {
	tx, err := s.packages.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var locked string
	if err = tx.QueryRowContext(ctx, `SELECT id::text FROM uem_netbird_installations WHERE id=$1 FOR UPDATE`, r.ID).Scan(&locked); err != nil {
		return nil, err
	}
	var response any
	if data != nil {
		response = string(data)
	}
	// A response that expires while waiting to persist is retained as uncertain.
	_, err = tx.ExecContext(ctx, `WITH stamp AS(SELECT clock_timestamp() AS at) INSERT INTO uem_netbird_preparation_results(request_id,outcome,response,recorded_at) SELECT p.request_id,CASE WHEN $2='prepared' AND stamp.at>=p.expires_at THEN 'unconfirmed' ELSE $2 END,CASE WHEN $2='prepared' AND stamp.at>=p.expires_at THEN NULL ELSE $3::jsonb END,stamp.at FROM uem_netbird_preparations p,stamp WHERE p.request_id=$1`, r.ID, outcome, response)
	if err != nil {
		return nil, err
	}
	p, err := readInstallationPreparation(ctx, tx, r.ID)
	if err != nil {
		return nil, err
	}
	if err = preparationAudit(ctx, tx, r, "preparation-"+p.Outcome); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return p, nil
}

func (s *NetbirdInstallationStore) ReadPreparation(parent context.Context, actor string, scope access.Scope, device, id string) (*NetbirdInstallationPreparation, error) {
	if parent == nil || !canonicalRequestID(device) || !canonicalRequestID(id) {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, actor, scope, access.ReadSoftware)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	r, err := scanInstallation(tx.QueryRowContext(ctx, `SELECT `+installationColumns+` FROM uem_netbird_installations WHERE id=$1 AND device_id=$2 AND tenant_id=$3 AND site_id=$4`, id, device, scope.TenantID, scope.SiteID))
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p, err := readInstallationPreparation(ctx, tx, id)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err = installationAudit(ctx, tx, actor, r, "read", "recorded"); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return p, nil
}

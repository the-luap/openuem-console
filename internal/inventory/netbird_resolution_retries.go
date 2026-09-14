package inventory

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/open-uem/nats/netbirdcommand"
	"github.com/open-uem/openuem-console/internal/security/access"
)

// NetbirdResolutionRetry identifies one explicitly reviewed transmission. Its ID
// is separate from the unchanged resolution UUID used by the agent journal.
// Only the latest summary is loaded; every prior attempt remains permanent.
type NetbirdResolutionRetry struct {
	ID, Actor, Revision, Kind string
	Sequence                  int64
	CreatedAt                 time.Time
}

func readNetbirdResolutionRetry(ctx context.Context, tx *sql.Tx, family, request string) (*NetbirdResolutionRetry, error) {
	r := &NetbirdResolutionRetry{}
	err := tx.QueryRowContext(ctx, `SELECT id,actor,revision,kind,sequence,created_at FROM uem_netbird_resolution_retries WHERE family=$1 AND request_id=$2 ORDER BY sequence DESC LIMIT 1`, family, request).Scan(&r.ID, &r.Actor, &r.Revision, &r.Kind, &r.Sequence, &r.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return r, err
}

func netbirdResolutionRetryReplay(ctx context.Context, tx *sql.Tx, family, request, resolution, id, actor, revision string) (bool, error) {
	var f, r, d, a, v string
	err := tx.QueryRowContext(ctx, `SELECT family,request_id,resolution_id,actor,revision FROM uem_netbird_resolution_retries WHERE id=$1`, id).Scan(&f, &r, &d, &a, &v)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if f != family || r != request || d != resolution || a != actor || v != revision {
		return false, ErrNetbirdOperationConflict
	}
	return true, nil
}

// The caller holds the original request and current authority locks. This
// separate transaction commits both the attempt and audit before any RPC.
func recordNetbirdResolutionRetry(ctx context.Context, db *sql.DB, family string, r *NetbirdOperation, resolution, id, actor, revision string, previous *NetbirdResolutionRetry, c netbirdcommand.ControlRequest) error {
	wire, err := netbirdcommand.EncodeControl(c)
	if err != nil {
		return err
	}
	hash, err := c.Digest()
	if err != nil {
		return err
	}
	sequence := int64(1)
	if previous != nil {
		sequence = previous.Sequence + 1
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO uem_netbird_resolution_retries(id,family,request_id,resolution_id,actor,revision,kind,sequence,control,control_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10)`, id, family, r.ID, resolution, actor, revision, c.Kind, sequence, string(wire), hash)
	if err != nil {
		var state interface{ SQLState() string }
		if errors.As(err, &state) && state.SQLState() == "23505" {
			return ErrNetbirdOperationConflict
		}
		return err
	}
	audited := *r
	audited.Operation += "/resolution-retry/" + id
	if err = netbirdOperationAudit(ctx, tx, &audited, actor, "resolution.attempt", "recorded"); err != nil {
		return err
	}
	return tx.Commit()
}

// Retry requires new live evidence and explicit confirmation for each attempt.
// Replaying the same form returns the retained attempt without another RPC.
func (s *NetbirdResolutionStore) Retry(parent context.Context, actor string, scope access.Scope, device, request, resolution, id, revision string) (*NetbirdResolution, error) {
	if !canonicalRequestID(resolution) || !canonicalRequestID(id) || !validManualRevision(revision) {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	tx, r, err := s.begin(ctx, actor, scope, device, request)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	d, err := readNetbirdResolution(ctx, tx, r.ID)
	if err != nil {
		return nil, err
	}
	if d == nil || d.ID != resolution {
		return nil, ErrNetbirdOperationConflict
	}
	replay, err := netbirdResolutionRetryReplay(ctx, tx, "operation", r.ID, resolution, id, actor, revision)
	if err != nil {
		return nil, err
	}
	if replay {
		if err = netbirdOperationAudit(ctx, tx, r, actor, "read", "recorded"); err != nil {
			return nil, err
		}
		return d, tx.Commit()
	}
	v, err := s.review(ctx, tx, r)
	if err != nil {
		return nil, err
	}
	if !v.CanRetry || v.Revision != revision {
		return nil, ErrNetbirdOperationChanged
	}
	c := netbirdControlRequest(ctx, v, "release", d.ID)
	if v.RetryKind == "withdraw" {
		c = netbirdRecoveryControl(ctx, v, "withdraw", d.ID)
	}
	if err = recordNetbirdResolutionRetry(ctx, s.operations.db, "operation", r, d.ID, id, actor, revision, d.LastRetry, c); err != nil {
		return nil, err
	}
	d, err = readNetbirdResolution(ctx, tx, r.ID)
	if err != nil {
		return nil, err
	}
	p, err := s.request(ctx, c)
	if err != nil {
		p = nil
	}
	return s.finish(ctx, tx, v, d, actor, c, p)
}

// Retry never repeats registration, provider creation or cleanup. A withdrawal
// intent can acquire a separately reviewed release phase if execution won the
// withdrawal race. The original intent and original outcome stay unchanged.
func (s *NetbirdRegistrationResolutionStore) Retry(parent context.Context, actor string, scope access.Scope, device, request, resolution, id, revision string) (*NetbirdRegistrationResolution, error) {
	if !canonicalRequestID(resolution) || !canonicalRequestID(id) || !validManualRevision(revision) {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 25*time.Second)
	defer cancel()
	tx, r, err := s.begin(ctx, actor, scope, device, request)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	d, err := readRegistrationResolution(ctx, tx, r.ID)
	if err != nil {
		return nil, err
	}
	if d == nil || d.ID != resolution {
		return nil, ErrNetbirdOperationConflict
	}
	replay, err := netbirdResolutionRetryReplay(ctx, tx, "registration", r.ID, resolution, id, actor, revision)
	if err != nil {
		return nil, err
	}
	if replay {
		if err = registrationAudit(ctx, tx, r, actor, "read", "resolution"); err != nil {
			return nil, err
		}
		return d, tx.Commit()
	}
	v, err := s.review(ctx, tx, r)
	if err != nil {
		return nil, err
	}
	if !v.CanRetry || v.Revision != revision {
		return nil, ErrNetbirdOperationChanged
	}
	c := netbirdControlRequest(ctx, v.agent, "release", d.ID)
	if v.RetryKind == "withdraw" {
		c = netbirdRecoveryControl(ctx, v.agent, "withdraw", d.ID)
	}
	if err = recordNetbirdResolutionRetry(ctx, s.registrations.operations.db, "registration", v.agent.Operation, d.ID, id, actor, revision, d.LastRetry, c); err != nil {
		return nil, err
	}
	d, err = readRegistrationResolution(ctx, tx, r.ID)
	if err != nil {
		return nil, err
	}
	p, err := s.agent.request(ctx, c)
	if err != nil {
		p = nil
	}
	return s.finish(ctx, tx, v, d, actor, c, p)
}

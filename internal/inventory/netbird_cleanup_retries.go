package inventory

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/open-uem/nats/netbirdapi"
	"github.com/open-uem/openuem-console/internal/security/access"
)

// Every row records permission to try one DELETE, not proof that it succeeded.
// Only exact-key absence can supply that evidence. All earlier rows are retained.
type NetbirdCleanupRetry struct {
	ID, Actor, Revision string
	Sequence            int64
	CreatedAt           time.Time
}

type NetbirdCleanupReview struct {
	Registration                      *NetbirdRegistration
	Target                            ManualTarget
	Revision, ManagementURL, KeyState string
	CanRetry                          bool
	snapshot                          registrationSnapshot
}

func (v NetbirdCleanupReview) String() string   { return "NetBird cleanup review (credentials redacted)" }
func (v NetbirdCleanupReview) GoString() string { return v.String() }

func readNetbirdCleanupRetry(ctx context.Context, tx *sql.Tx, request string) (*NetbirdCleanupRetry, error) {
	r := &NetbirdCleanupRetry{}
	err := tx.QueryRowContext(ctx, `SELECT id,actor,revision,sequence,created_at FROM uem_netbird_cleanup_retries WHERE request_id=$1 ORDER BY sequence DESC LIMIT 1`, request).Scan(&r.ID, &r.Actor, &r.Revision, &r.Sequence, &r.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return r, err
}

func netbirdCleanupDigest(r *NetbirdRegistration) string {
	data, _ := json.Marshal([]any{r.ID, r.Revision, r.Key.ID, r.Key})
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func (s *NetbirdRegistrationStore) beginCleanup(ctx context.Context, actor string, scope access.Scope, device, request string) (*sql.Tx, *NetbirdRegistration, error) {
	if !canonicalRequestID(request) || !ValidReportDeviceID(device) {
		return nil, nil, ErrNetbirdOperationInvalid
	}
	tx, err := s.operations.recordTx(ctx, actor, scope, access.ManageDeviceSecurity)
	if err != nil {
		return nil, nil, err
	}
	r, err := recordedRegistration(ctx, tx, scope, device, request, "FOR UPDATE OF r")
	if err == nil {
		_, err = registrationEvidence(ctx, tx, r)
	}
	if err == nil && (r.Status != "unconfirmed" || r.Key == nil || !slices.Contains(r.Attempts, "delete")) {
		err = ErrNetbirdOperationConflict
	}
	if err != nil {
		tx.Rollback()
		return nil, nil, err
	}
	return tx, r, nil
}

func (s *NetbirdRegistrationStore) cleanupReview(ctx context.Context, tx *sql.Tx, r *NetbirdRegistration) (*NetbirdCleanupReview, error) {
	v := &NetbirdCleanupReview{Registration: r, Target: ManualTarget{ID: r.DeviceID, Scope: r.Scope}, KeyState: "absent"}
	if r.KeyAbsent {
		return v, nil
	}
	if r.ReleasedAt != nil {
		return nil, ErrNetbirdOperationConflict
	}
	op := &NetbirdOperation{ID: r.ID, DeviceID: r.DeviceID, Scope: r.Scope, Individual: r.Individual, Revision: r.Revision, Operation: "register"}
	current, generation, err := s.operations.resolutionTarget(ctx, tx, op)
	if err != nil {
		return nil, err
	}
	v.Target = current.Target
	v.KeyState = "unavailable"
	v.snapshot, err = s.snapshot(r)
	if err == nil {
		v.ManagementURL = v.snapshot.Base
		observed, absent, observeErr := s.observe(ctx, v.snapshot, r.Key.ID)
		switch {
		case observeErr != nil:
		case absent:
			v.KeyState = "absent"
		case observed == nil || !r.Key.SameOwnership(*observed):
			v.KeyState = "changed"
		default:
			v.KeyState = "present"
			v.CanRetry = true
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if r.Individual && !time.Now().Before(current.identityExpiry) {
		return nil, ErrNetbirdOperationChanged
	}
	// Mutable usage counters are not ownership. The exact retained creation
	// policy, original provider snapshot, live authority and latest attempt are.
	data, _ := json.Marshal([]any{r.ID, r.Revision, generation, r.Key, r.KeyAbsent, r.LastCleanupRetry, v.ManagementURL, v.KeyState, v.CanRetry})
	digest := sha256.Sum256(data)
	v.Revision = hex.EncodeToString(digest[:])
	return v, nil
}

// ReviewCleanup is read-only at the provider. It never contacts the agent.
func (s *NetbirdRegistrationStore) ReviewCleanup(parent context.Context, actor string, scope access.Scope, device, request string) (*NetbirdCleanupReview, error) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, r, err := s.beginCleanup(ctx, actor, scope, device, request)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	v, err := s.cleanupReview(ctx, tx, r)
	if err != nil {
		return nil, err
	}
	if err = registrationAudit(ctx, tx, r, actor, "review", "cleanup-retry"); err != nil {
		return nil, err
	}
	return v, tx.Commit()
}

func (s *NetbirdRegistrationStore) recordCleanupRetry(ctx context.Context, r *NetbirdRegistration, actor, id, revision string) error {
	tx, err := s.operations.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	sequence := int64(1)
	if r.LastCleanupRetry != nil {
		sequence = r.LastCleanupRetry.Sequence + 1
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO uem_netbird_cleanup_retries(id,request_id,actor,revision,key_id,digest,sequence) VALUES($1,$2,$3,$4,$5,$6,$7)`, id, r.ID, actor, revision, r.Key.ID, netbirdCleanupDigest(r), sequence)
	if err != nil {
		var state interface{ SQLState() string }
		if errors.As(err, &state) && state.SQLState() == "23505" {
			return ErrNetbirdOperationConflict
		}
		return err
	}
	if err = registrationAudit(ctx, tx, r, actor, "attempt", "cleanup-retry/"+id); err != nil {
		return err
	}
	return tx.Commit()
}

// RetryCleanup freshly checks the exact key policy and commits an independent
// attempt with audit before one DELETE. Replaying a form returns retained state
// without provider calls. Another attempt requires a new review and form UUID.
func (s *NetbirdRegistrationStore) RetryCleanup(parent context.Context, actor string, scope access.Scope, device, request, id, revision string) (*NetbirdRegistration, error) {
	if !canonicalRequestID(id) || !validManualRevision(revision) {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	tx, r, err := s.beginCleanup(ctx, actor, scope, device, request)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var storedRequest, storedActor, storedRevision string
	err = tx.QueryRowContext(ctx, `SELECT request_id,actor,revision FROM uem_netbird_cleanup_retries WHERE id=$1`, id).Scan(&storedRequest, &storedActor, &storedRevision)
	if err == nil {
		if storedRequest != r.ID || storedActor != actor || storedRevision != revision {
			return nil, ErrNetbirdOperationConflict
		}
		if err = registrationAudit(ctx, tx, r, actor, "read", "cleanup-retry"); err != nil {
			return nil, err
		}
		return r, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	v, err := s.cleanupReview(ctx, tx, r)
	if err != nil {
		return nil, err
	}
	if !v.CanRetry || v.Revision != revision {
		return nil, ErrNetbirdOperationChanged
	}
	if err = s.recordCleanupRetry(ctx, r, actor, id, revision); err != nil {
		return nil, err
	}
	r.LastCleanupRetry, err = readNetbirdCleanupRetry(ctx, tx, r.ID)
	if err != nil {
		return nil, err
	}
	call, cancelDelete := context.WithTimeout(ctx, 5*time.Second)
	_ = netbirdapi.DeleteKey(call, s.transport, v.snapshot.Base, v.snapshot.Token, r.Key.ID)
	cancelDelete()
	// A successful response is not absence evidence. A lost response may still
	// have removed the key; a fresh exact-ID read distinguishes those cases.
	_, absent, observeErr := s.observe(ctx, v.snapshot, r.Key.ID)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if observeErr == nil && absent {
		if err = s.evidenceAs(ctx, r, actor, "absent", struct {
			KeyID  string `json:"key_id"`
			Absent bool   `json:"absent"`
		}{r.Key.ID, true}, ""); err != nil {
			return nil, err
		}
		r.KeyAbsent = true
	}
	if err = registrationAudit(ctx, tx, r, actor, "read", "cleanup-retry"); err != nil {
		return nil, err
	}
	return r, tx.Commit()
}

package inventory

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/netbirdcommand"
	"github.com/open-uem/openuem-console/internal/security/access"
)

// Resolution history is source-free. Release confirms a journal decision, not
// native removal success, rollback, or termination of an independently running process.
type NetbirdRemovalStageCleanupResolution struct {
	ID, RequestID, Actor, Kind string
	CreatedAt                  time.Time
	ConfirmedAt, CompletedAt   *time.Time
	ConfirmedBy                string
	LastAttempt                *NetbirdRemovalStageCleanupControlAttempt
}

type NetbirdRemovalStageCleanupControlAttempt struct {
	ID, Actor, Kind, ReviewRevision, Outcome string
	Sequence                                 int
	CreatedAt                                time.Time
	RecordedAt                               *time.Time
}

// Only an eligible, retained two-minute review has a nonempty Revision. A fresh
// explicit review is required for every additional control, using the same
// permanent resolution ID. Replaying a consumed review only reads history.
type NetbirdRemovalStageCleanupResolutionReview struct {
	RequestID, ResolutionID, Revision, Outcome, Kind string
	ExpiresAt                                        *time.Time
	Journal                                          netbirdcommand.State
	Resolution                                       *NetbirdRemovalStageCleanupResolution
}

type stageCleanupResolutionSnapshot struct {
	target                             *NetbirdResolutionReview
	outcome, kind, hash, observationID string
	journal                            netbirdcommand.State
}

func readStageCleanupResolution(ctx context.Context, tx *sql.Tx, id string) (*NetbirdRemovalStageCleanupResolution, error) {
	d := &NetbirdRemovalStageCleanupResolution{}
	err := tx.QueryRowContext(ctx, `SELECT d.id::text,d.request_id::text,d.actor,v.kind,d.created_at,r.released_at,r.completed_at,coalesce(r.released_by,'')
 FROM uem_netbird_removal_stage_cleanup_resolutions d JOIN uem_netbird_removal_stage_cleanup_reviews v ON v.id=d.review_id JOIN uem_netbird_removal_stage_cleanups r ON r.id=d.request_id WHERE d.request_id=$1`, id).Scan(&d.ID, &d.RequestID, &d.Actor, &d.Kind, &d.CreatedAt, &d.ConfirmedAt, &d.CompletedAt, &d.ConfirmedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a := &NetbirdRemovalStageCleanupControlAttempt{}
	err = tx.QueryRowContext(ctx, `SELECT a.id::text,a.actor,a.kind,v.revision,a.sequence,a.created_at,p.recorded_at,
 CASE WHEN p.attempt_id IS NULL THEN 'pending' WHEN p.response->>'outcome'='ok' THEN p.response->'receipt'->>'status' ELSE coalesce(p.response->>'outcome','unavailable') END
 FROM uem_netbird_removal_stage_cleanup_controls a JOIN uem_netbird_removal_stage_cleanup_reviews v ON v.id=a.review_id LEFT JOIN uem_netbird_removal_stage_cleanup_control_results p ON p.attempt_id=a.id WHERE a.request_id=$1 ORDER BY a.sequence DESC LIMIT 1`, id).Scan(&a.ID, &a.Actor, &a.Kind, &a.ReviewRevision, &a.Sequence, &a.CreatedAt, &a.RecordedAt, &a.Outcome)
	if errors.Is(err, sql.ErrNoRows) {
		return d, nil
	}
	if err != nil {
		return nil, err
	}
	d.LastAttempt = a
	return d, nil
}

func (s *NetbirdRemovalStageCleanupStore) stageCleanupResolutionTarget(ctx context.Context, tx *sql.Tx, r *NetbirdRemovalStageCleanup) (*NetbirdResolutionReview, string, error) {
	d, err := readRemovalStageCleanupDelivery(ctx, tx, r.ID)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNetbirdOperationConflict
	}
	if err != nil {
		return nil, "", err
	}
	operations := &NetbirdOperationStore{db: s.base.db, permissions: s.base.permissions, individual: s.base.individual}
	return operations.resolutionTarget(ctx, tx, &NetbirdOperation{ID: r.ID, DeviceID: r.DeviceID, Scope: r.Scope, Individual: true, Revision: r.Revision, Operation: "cleanup-removal-stage", CommandHash: d.CommandHash})
}

func (s *NetbirdRemovalStageCleanupStore) stageCleanupResolutionSnapshot(ctx context.Context, tx *sql.Tx, r *NetbirdRemovalStageCleanup, actor string, d *NetbirdRemovalStageCleanupResolution) (*stageCleanupResolutionSnapshot, error) {
	target, generation, err := s.stageCleanupResolutionTarget(ctx, tx, r)
	if err != nil {
		return nil, err
	}
	c, err := removalResolutionControl(ctx, tx, target, "receipt", uuid.NewString())
	if err != nil {
		return nil, err
	}
	p := s.base.removalControl(ctx, c)
	if p == nil {
		return nil, ErrNetbirdOperationNotReady
	}
	if _, err = recordStageCleanupObservation(ctx, tx, r, actor, c, p); err != nil {
		return nil, err
	}
	v := &stageCleanupResolutionSnapshot{target: target, outcome: p.Outcome, observationID: c.RequestID}
	if p.Outcome == "ok" {
		v.outcome = p.Receipt.Status
		if p.ReleaseID != "" {
			v.outcome = "conflict"
			if d != nil && p.ReleaseID == d.ID {
				v.outcome = "awaiting-confirmation"
			}
		}
	}
	if p.Outcome == "missing" || v.outcome == "unconfirmed" {
		stateControl, err := removalResolutionControl(ctx, tx, target, "state", uuid.NewString())
		if err != nil {
			return nil, err
		}
		state := s.base.removalControl(ctx, stateControl)
		if state == nil || state.Outcome != "ok" {
			return nil, ErrNetbirdOperationNotReady
		}
		v.journal = state.State
		if p.Outcome == "missing" && state.State.Status == "ready" && state.State.Remaining > 0 {
			v.kind = "withdraw"
			v.outcome = "not-received"
		}
		if v.outcome == "unconfirmed" && state.State.Status == "unconfirmed" && state.State.CanRelease && state.State.PendingID == r.ID && state.State.PendingHash == target.Operation.CommandHash {
			v.kind = "release"
		}
		if v.kind == "" {
			v.outcome = "waiting"
		}
	}
	sequence := 0
	if d != nil && d.LastAttempt != nil {
		sequence = d.LastAttempt.Sequence
		if d.LastAttempt.Kind == "release" && v.kind == "withdraw" {
			v.kind = ""
			v.outcome = "conflict"
		}
	}
	data, err := json.Marshal([]any{generation, r.ID, r.Revision, target.Operation.CommandHash, v.outcome, v.kind, p.Receipt, p.ReleaseID, v.journal, sequence})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(append([]byte("openuem/netbird/removal-stage-cleanup-resolution/v1\x00"), data...))
	v.hash = hex.EncodeToString(digest[:])
	return v, nil
}

func (s *NetbirdRemovalStageCleanupStore) ReviewStageCleanupResolution(parent context.Context, actor string, scope access.Scope, device, id, revision string) (*NetbirdRemovalStageCleanupResolutionReview, error) {
	if parent == nil || s.base.control == nil {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, r, err := s.stageCleanupRecord(ctx, actor, scope, device, id, revision, access.AssignSoftware)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	d, err := readStageCleanupResolution(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	out := &NetbirdRemovalStageCleanupResolutionReview{RequestID: id, Resolution: d}
	if d != nil {
		out.ResolutionID = d.ID
	}
	if r.ReleasedAt != nil {
		out.Outcome = "released"
	} else if r.CompletedAt != nil {
		out.Outcome = "completed"
	} else {
		v, err := s.stageCleanupResolutionSnapshot(ctx, tx, r, actor, d)
		if err != nil {
			return nil, err
		}
		out.Outcome, out.Kind, out.Journal = v.outcome, v.kind, v.journal
		if v.kind != "" {
			reviewID := uuid.NewString()
			if out.ResolutionID == "" {
				out.ResolutionID = uuid.NewString()
			}
			seq := 1
			if d != nil && d.LastAttempt != nil {
				seq = d.LastAttempt.Sequence + 1
			}
			digest := sha256.Sum256([]byte(reviewID + ":" + v.hash))
			out.Revision = hex.EncodeToString(digest[:])
			var created, expires time.Time
			if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&created); err != nil {
				return nil, err
			}
			expires = created.Add(2 * time.Minute)
			if v.target.identityExpiry.Before(expires) {
				expires = v.target.identityExpiry
			}
			journal, _ := json.Marshal(v.journal)
			_, err = tx.ExecContext(ctx, `INSERT INTO uem_netbird_removal_stage_cleanup_reviews(id,request_id,resolution_id,actor,revision,snapshot_hash,sequence,kind,observation_id,journal,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12)`, reviewID, id, out.ResolutionID, actor, out.Revision, v.hash, seq, v.kind, v.observationID, string(journal), created, expires)
			if err != nil {
				return nil, err
			}
			out.ExpiresAt = &expires
		}
	}
	if err = removalStageCleanupStageAudit(ctx, tx, r, actor, "resolution.review", "resolution"); err != nil {
		return nil, err
	}
	return out, tx.Commit()
}

// ResolveStageCleanup consumes one retained review. Its immutable intent,
// exact control and audit commit before transport; no transaction spans delivery.
func (s *NetbirdRemovalStageCleanupStore) ResolveStageCleanup(parent context.Context, actor string, scope access.Scope, device, id, revision, resolutionID, reviewRevision string) (*NetbirdRemovalStageCleanupResolution, error) {
	if parent == nil || s.base.control == nil || !canonicalRequestID(resolutionID) || !netbirdcommand.ValidDigest(reviewRevision) {
		return nil, ErrNetbirdOperationInvalid
	}
	r, d, attempt, c, err := s.admitStageCleanupResolution(parent, actor, scope, device, id, revision, resolutionID, reviewRevision)
	if err != nil || c == nil {
		return d, err
	}
	p := s.base.removalControl(parent, *c)
	record, cancel := context.WithTimeout(context.WithoutCancel(parent), 10*time.Second)
	defer cancel()
	return s.finishStageCleanupResolution(record, r, actor, resolutionID, attempt, *c, p)
}

func (s *NetbirdRemovalStageCleanupStore) admitStageCleanupResolution(parent context.Context, actor string, scope access.Scope, device, id, revision, resolutionID, reviewRevision string) (*NetbirdRemovalStageCleanup, *NetbirdRemovalStageCleanupResolution, string, *netbirdcommand.ControlRequest, error) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, r, err := s.stageCleanupRecord(ctx, actor, scope, device, id, revision, access.AssignSoftware)
	if err != nil {
		return nil, nil, "", nil, err
	}
	defer tx.Rollback()
	if resolutionID == r.OriginalID || resolutionID == r.StageCleanup.Original.ReleaseID {
		return nil, nil, "", nil, ErrNetbirdOperationConflict
	}
	d, err := readStageCleanupResolution(ctx, tx, id)
	if err != nil {
		return nil, nil, "", nil, err
	}
	var reviewID, hash, kind string
	var expires time.Time
	var sequence int
	err = tx.QueryRowContext(ctx, `SELECT id::text,snapshot_hash,kind,expires_at,sequence FROM uem_netbird_removal_stage_cleanup_reviews WHERE request_id=$1 AND actor=$2 AND resolution_id=$3 AND revision=$4`, id, actor, resolutionID, reviewRevision).Scan(&reviewID, &hash, &kind, &expires, &sequence)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNetbirdOperationConflict
	}
	if err != nil {
		return nil, nil, "", nil, err
	}
	var consumed bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_netbird_removal_stage_cleanup_controls WHERE review_id=$1)`, reviewID).Scan(&consumed); err != nil {
		return nil, nil, "", nil, err
	}
	if consumed {
		if err = removalStageCleanupAudit(ctx, tx, actor, r, "read", "recorded"); err != nil {
			return nil, nil, "", nil, err
		}
		return r, d, "", nil, tx.Commit()
	}
	if r.CancelledAt != nil || r.CompletedAt != nil || r.ReleasedAt != nil || !time.Now().Before(expires) || d != nil && d.ID != resolutionID {
		return nil, nil, "", nil, ErrNetbirdOperationChanged
	}
	v, err := s.stageCleanupResolutionSnapshot(ctx, tx, r, actor, d)
	if err != nil {
		return nil, nil, "", nil, err
	}
	if v.hash != hash || v.kind != kind || v.kind == "" {
		return nil, nil, "", nil, ErrNetbirdOperationChanged
	}
	c, err := removalResolutionControl(ctx, tx, v.target, kind, resolutionID)
	if err != nil {
		return nil, nil, "", nil, err
	}
	if expires.Before(c.ExpiresAt) {
		c.ExpiresAt = expires.UTC()
	}
	if !c.Executable(c.Identity, time.Now()) {
		return nil, nil, "", nil, ErrNetbirdOperationChanged
	}
	wire, err := netbirdcommand.EncodeControl(c)
	if err != nil {
		return nil, nil, "", nil, err
	}
	digest, err := c.Digest()
	if err != nil {
		return nil, nil, "", nil, err
	}
	if d == nil {
		_, err = tx.ExecContext(ctx, `INSERT INTO uem_netbird_removal_stage_cleanup_resolutions(request_id,id,actor,review_id) VALUES($1,$2,$3,$4)`, id, resolutionID, actor, reviewID)
		if err != nil {
			return nil, nil, "", nil, err
		}
	}
	attempt := uuid.NewString()
	_, err = tx.ExecContext(ctx, `INSERT INTO uem_netbird_removal_stage_cleanup_controls(id,request_id,resolution_id,review_id,actor,sequence,kind,control_hash,control) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)`, attempt, id, resolutionID, reviewID, actor, sequence, kind, digest, string(wire))
	if err != nil {
		return nil, nil, "", nil, err
	}
	if err = removalStageCleanupStageAudit(ctx, tx, r, actor, "resolution.attempt", "resolution"); err != nil {
		return nil, nil, "", nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, nil, "", nil, err
	}
	return r, nil, attempt, &c, nil
}

func (s *NetbirdRemovalStageCleanupStore) finishStageCleanupResolution(ctx context.Context, r *NetbirdRemovalStageCleanup, actor, resolutionID, attempt string, c netbirdcommand.ControlRequest, p *netbirdcommand.ControlResponse) (*NetbirdRemovalStageCleanupResolution, error) {
	tx, err := s.base.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var completed, released *time.Time
	if err = tx.QueryRowContext(ctx, `SELECT completed_at,released_at FROM uem_netbird_removal_stage_cleanups WHERE id=$1 FOR UPDATE`, r.ID).Scan(&completed, &released); err != nil {
		return nil, err
	}
	var response any
	// Version-one release correlation additionally needs the stage cleanup command
	// revision and operation, which its control envelope does not carry.
	if p != nil && p.Outcome == "ok" && (p.Receipt.Revision != r.Revision || p.Receipt.Operation != "cleanup-removal-stage") {
		p = nil
	}
	if p != nil {
		wire, err := netbirdcommand.EncodeControlResponse(c, *p)
		if err != nil {
			return nil, err
		}
		response = string(wire)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_netbird_removal_stage_cleanup_control_results(attempt_id,response) VALUES($1,$2::jsonb)`, attempt, response); err != nil {
		return nil, err
	}
	if completed == nil && released == nil && p != nil && p.Outcome == "ok" && p.ReleaseID == resolutionID {
		if err = recordStageCleanupRelease(ctx, tx, r, actor, resolutionID, attempt, ""); err != nil {
			return nil, err
		}
	}
	if err = removalStageCleanupStageAudit(ctx, tx, r, actor, "resolution.observe", "resolution-result"); err != nil {
		return nil, err
	}
	d, err := readStageCleanupResolution(ctx, tx, r.ID)
	if err != nil {
		return nil, err
	}
	return d, tx.Commit()
}

func recordStageCleanupRelease(ctx context.Context, tx *sql.Tx, r *NetbirdRemovalStageCleanup, actor, resolutionID, attempt, observation string) error {
	var recorded time.Time
	err := tx.QueryRowContext(ctx, `INSERT INTO uem_netbird_removal_stage_cleanup_release_proofs(request_id,resolution_id,actor,attempt_id,observation_id) VALUES($1,$2,$3,nullif($4,'')::uuid,nullif($5,'')::uuid) RETURNING recorded_at`, r.ID, resolutionID, actor, attempt, observation).Scan(&recorded)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE uem_netbird_removal_stage_cleanups SET released_at=$2,released_by=$3,resolution_id=$4 WHERE id=$1`, r.ID, recorded, actor, resolutionID); err != nil {
		return err
	}
	return removalStageCleanupStageAudit(ctx, tx, r, actor, "release", "resolution")
}

// ReconcileStageCleanupResolution sends only a current-identity receipt query.
// A foreign release ID, a missing receipt, or a release with no owned mutating
// attempt leaves the barrier intact. Positive completion uses normal observation.
func (s *NetbirdRemovalStageCleanupStore) ReconcileStageCleanupResolution(parent context.Context, actor string, scope access.Scope, device, id, revision, resolutionID string) (*NetbirdRemovalStageCleanupResolution, error) {
	if parent == nil || s.base.control == nil || !canonicalRequestID(resolutionID) {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, r, err := s.stageCleanupRecord(ctx, actor, scope, device, id, revision, access.AssignSoftware)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	d, err := readStageCleanupResolution(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	if d == nil || d.ID != resolutionID {
		return nil, ErrNetbirdOperationConflict
	}
	if r.CompletedAt == nil && r.ReleasedAt == nil {
		v, _, err := s.stageCleanupResolutionTarget(ctx, tx, r)
		if err != nil {
			return nil, err
		}
		c, err := removalResolutionControl(ctx, tx, v, "receipt", uuid.NewString())
		if err != nil {
			return nil, err
		}
		p := s.base.removalControl(ctx, c)
		if _, err = recordStageCleanupObservation(ctx, tx, r, actor, c, p); err != nil {
			return nil, err
		}
		if p != nil && p.Outcome == "ok" && p.ReleaseID == resolutionID {
			kind := "release"
			if p.Receipt.Status == "withdrawn" {
				kind = "withdraw"
			}
			var attempted bool
			if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_netbird_removal_stage_cleanup_controls WHERE request_id=$1 AND resolution_id=$2 AND kind=$3)`, id, resolutionID, kind).Scan(&attempted); err != nil {
				return nil, err
			}
			if attempted {
				if err = recordStageCleanupRelease(ctx, tx, r, actor, resolutionID, "", c.RequestID); err != nil {
					return nil, err
				}
			}
		}
	}
	if err = removalStageCleanupStageAudit(ctx, tx, r, actor, "resolution.observe", "resolution-reconcile"); err != nil {
		return nil, err
	}
	d, err = readStageCleanupResolution(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	return d, tx.Commit()
}

func (s *NetbirdRemovalStageCleanupStore) ReadStageCleanupResolution(parent context.Context, actor string, scope access.Scope, device, id, revision string) (*NetbirdRemovalStageCleanupResolution, error) {
	if parent == nil {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, r, err := s.stageCleanupRecord(ctx, actor, scope, device, id, revision, access.ReadSoftware)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	d, err := readStageCleanupResolution(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	if err = removalStageCleanupAudit(ctx, tx, actor, r, "read", "recorded"); err != nil {
		return nil, err
	}
	return d, tx.Commit()
}

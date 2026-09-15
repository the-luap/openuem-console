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
// installer success, rollback, or termination of an independently running process.
type NetbirdInstallationResolution struct {
	ID, RequestID, Actor, Kind string
	CreatedAt                  time.Time
	ConfirmedAt, CompletedAt   *time.Time
	ConfirmedBy                string
	LastAttempt                *NetbirdInstallationControlAttempt
}

type NetbirdInstallationControlAttempt struct {
	ID, Actor, Kind, ReviewRevision, Outcome string
	Sequence                                 int
	CreatedAt                                time.Time
	RecordedAt                               *time.Time
}

// Only an eligible, retained two-minute review has a nonempty Revision. A fresh
// explicit review is required for every additional control, using the same
// permanent resolution ID. Replaying a consumed review only reads history.
type NetbirdInstallationResolutionReview struct {
	RequestID, ResolutionID, Revision, Outcome, Kind string
	ExpiresAt                                        *time.Time
	Journal                                          netbirdcommand.State
	Resolution                                       *NetbirdInstallationResolution
}

type installationResolutionSnapshot struct {
	target                             *NetbirdResolutionReview
	outcome, kind, hash, observationID string
	journal                            netbirdcommand.State
}

func readInstallationResolution(ctx context.Context, tx *sql.Tx, id string) (*NetbirdInstallationResolution, error) {
	d := &NetbirdInstallationResolution{}
	err := tx.QueryRowContext(ctx, `SELECT d.id::text,d.request_id::text,d.actor,v.kind,d.created_at,r.released_at,r.completed_at,coalesce(r.released_by,'')
 FROM uem_netbird_installation_resolutions d JOIN uem_netbird_installation_reviews v ON v.id=d.review_id JOIN uem_netbird_installations r ON r.id=d.request_id WHERE d.request_id=$1`, id).Scan(&d.ID, &d.RequestID, &d.Actor, &d.Kind, &d.CreatedAt, &d.ConfirmedAt, &d.CompletedAt, &d.ConfirmedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a := &NetbirdInstallationControlAttempt{}
	err = tx.QueryRowContext(ctx, `SELECT a.id::text,a.actor,a.kind,v.revision,a.sequence,a.created_at,p.recorded_at,
 CASE WHEN p.attempt_id IS NULL THEN 'pending' WHEN p.response->>'outcome'='ok' THEN p.response->'receipt'->>'status' ELSE coalesce(p.response->>'outcome','unavailable') END
 FROM uem_netbird_installation_controls a JOIN uem_netbird_installation_reviews v ON v.id=a.review_id LEFT JOIN uem_netbird_installation_control_results p ON p.attempt_id=a.id WHERE a.request_id=$1 ORDER BY a.sequence DESC LIMIT 1`, id).Scan(&a.ID, &a.Actor, &a.Kind, &a.ReviewRevision, &a.Sequence, &a.CreatedAt, &a.RecordedAt, &a.Outcome)
	if errors.Is(err, sql.ErrNoRows) {
		return d, nil
	}
	if err != nil {
		return nil, err
	}
	d.LastAttempt = a
	return d, nil
}

func (s *NetbirdInstallationStore) installationResolutionTarget(ctx context.Context, tx *sql.Tx, r *NetbirdInstallation) (*NetbirdResolutionReview, string, error) {
	d, err := readInstallationDelivery(ctx, tx, r.ID)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNetbirdOperationConflict
	}
	if err != nil {
		return nil, "", err
	}
	operations := &NetbirdOperationStore{db: s.packages.db, permissions: s.packages.permissions, individual: s.individual}
	return operations.resolutionTarget(ctx, tx, &NetbirdOperation{ID: r.ID, DeviceID: r.DeviceID, Scope: r.Scope, Individual: true, Revision: r.Revision, Operation: "install", CommandHash: d.CommandHash})
}

func installationResolutionControl(ctx context.Context, tx *sql.Tx, v *NetbirdResolutionReview, kind, id string) (netbirdcommand.ControlRequest, error) {
	c := netbirdControlRequest(ctx, v, kind, id)
	if kind == "state" {
		c.ReferenceID, c.CommandHash = "", ""
	}
	if kind == "receipt" || kind == "withdraw" {
		c = netbirdRecoveryControl(ctx, v, kind, id)
	}
	var issued time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&issued); err != nil {
		return c, err
	}
	c.IssuedAt = issued.UTC()
	lifetime := 2 * time.Second
	if kind == "release" || kind == "withdraw" {
		lifetime = netbirdcommand.ControlLifetime
	}
	if expires := c.IssuedAt.Add(lifetime); expires.Before(c.ExpiresAt) {
		c.ExpiresAt = expires
	}
	c.ExpiresAt = c.ExpiresAt.UTC()
	if !c.Executable(c.Identity, time.Now()) {
		return c, ErrNetbirdOperationNotReady
	}
	return c, nil
}

func (s *NetbirdInstallationStore) installationResolutionSnapshot(ctx context.Context, tx *sql.Tx, r *NetbirdInstallation, actor string, d *NetbirdInstallationResolution) (*installationResolutionSnapshot, error) {
	target, generation, err := s.installationResolutionTarget(ctx, tx, r)
	if err != nil {
		return nil, err
	}
	c, err := installationResolutionControl(ctx, tx, target, "receipt", uuid.NewString())
	if err != nil {
		return nil, err
	}
	p := s.installationControl(ctx, c)
	if p == nil {
		return nil, ErrNetbirdOperationNotReady
	}
	if _, err = recordInstallationObservation(ctx, tx, r, actor, c, p); err != nil {
		return nil, err
	}
	v := &installationResolutionSnapshot{target: target, outcome: p.Outcome, observationID: c.RequestID}
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
		stateControl, err := installationResolutionControl(ctx, tx, target, "state", uuid.NewString())
		if err != nil {
			return nil, err
		}
		state := s.installationControl(ctx, stateControl)
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
	digest := sha256.Sum256(data)
	v.hash = hex.EncodeToString(digest[:])
	return v, nil
}

func (s *NetbirdInstallationStore) ReviewInstallationResolution(parent context.Context, actor string, scope access.Scope, device, id, revision string) (*NetbirdInstallationResolutionReview, error) {
	if parent == nil || s.control == nil {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, r, err := s.installationRecord(ctx, actor, scope, device, id, revision, access.AssignSoftware)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	d, err := readInstallationResolution(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	out := &NetbirdInstallationResolutionReview{RequestID: id, Resolution: d}
	if d != nil {
		out.ResolutionID = d.ID
	}
	if r.ReleasedAt != nil {
		out.Outcome = "released"
	} else if r.CompletedAt != nil {
		out.Outcome = "completed"
	} else {
		v, err := s.installationResolutionSnapshot(ctx, tx, r, actor, d)
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
			_, err = tx.ExecContext(ctx, `INSERT INTO uem_netbird_installation_reviews(id,request_id,resolution_id,actor,revision,snapshot_hash,sequence,kind,observation_id,journal,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12)`, reviewID, id, out.ResolutionID, actor, out.Revision, v.hash, seq, v.kind, v.observationID, string(journal), created, expires)
			if err != nil {
				return nil, err
			}
			out.ExpiresAt = &expires
		}
	}
	if err = installationStageAudit(ctx, tx, r, actor, "resolution.review", "resolution"); err != nil {
		return nil, err
	}
	return out, tx.Commit()
}

// ResolveInstallation consumes one retained review. Its immutable intent,
// exact control and audit commit before transport; no transaction spans delivery.
func (s *NetbirdInstallationStore) ResolveInstallation(parent context.Context, actor string, scope access.Scope, device, id, revision, resolutionID, reviewRevision string) (*NetbirdInstallationResolution, error) {
	if parent == nil || s.control == nil || !canonicalRequestID(resolutionID) || !netbirdcommand.ValidDigest(reviewRevision) {
		return nil, ErrNetbirdOperationInvalid
	}
	r, d, attempt, c, err := s.admitInstallationResolution(parent, actor, scope, device, id, revision, resolutionID, reviewRevision)
	if err != nil || c == nil {
		return d, err
	}
	p := s.installationControl(parent, *c)
	record, cancel := context.WithTimeout(context.WithoutCancel(parent), 10*time.Second)
	defer cancel()
	return s.finishInstallationResolution(record, r, actor, resolutionID, attempt, *c, p)
}

func (s *NetbirdInstallationStore) admitInstallationResolution(parent context.Context, actor string, scope access.Scope, device, id, revision, resolutionID, reviewRevision string) (*NetbirdInstallation, *NetbirdInstallationResolution, string, *netbirdcommand.ControlRequest, error) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, r, err := s.installationRecord(ctx, actor, scope, device, id, revision, access.AssignSoftware)
	if err != nil {
		return nil, nil, "", nil, err
	}
	defer tx.Rollback()
	d, err := readInstallationResolution(ctx, tx, id)
	if err != nil {
		return nil, nil, "", nil, err
	}
	var reviewID, hash, kind string
	var expires time.Time
	var sequence int
	err = tx.QueryRowContext(ctx, `SELECT id::text,snapshot_hash,kind,expires_at,sequence FROM uem_netbird_installation_reviews WHERE request_id=$1 AND actor=$2 AND resolution_id=$3 AND revision=$4`, id, actor, resolutionID, reviewRevision).Scan(&reviewID, &hash, &kind, &expires, &sequence)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNetbirdOperationConflict
	}
	if err != nil {
		return nil, nil, "", nil, err
	}
	var consumed bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_netbird_installation_controls WHERE review_id=$1)`, reviewID).Scan(&consumed); err != nil {
		return nil, nil, "", nil, err
	}
	if consumed {
		if err = installationAudit(ctx, tx, actor, r, "read", "recorded"); err != nil {
			return nil, nil, "", nil, err
		}
		return r, d, "", nil, tx.Commit()
	}
	if r.CancelledAt != nil || r.CompletedAt != nil || r.ReleasedAt != nil || !time.Now().Before(expires) || d != nil && d.ID != resolutionID {
		return nil, nil, "", nil, ErrNetbirdOperationChanged
	}
	v, err := s.installationResolutionSnapshot(ctx, tx, r, actor, d)
	if err != nil {
		return nil, nil, "", nil, err
	}
	if v.hash != hash || v.kind != kind || v.kind == "" {
		return nil, nil, "", nil, ErrNetbirdOperationChanged
	}
	c, err := installationResolutionControl(ctx, tx, v.target, kind, resolutionID)
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
		_, err = tx.ExecContext(ctx, `INSERT INTO uem_netbird_installation_resolutions(request_id,id,actor,review_id) VALUES($1,$2,$3,$4)`, id, resolutionID, actor, reviewID)
		if err != nil {
			return nil, nil, "", nil, err
		}
	}
	attempt := uuid.NewString()
	_, err = tx.ExecContext(ctx, `INSERT INTO uem_netbird_installation_controls(id,request_id,resolution_id,review_id,actor,sequence,kind,control_hash,control) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)`, attempt, id, resolutionID, reviewID, actor, sequence, kind, digest, string(wire))
	if err != nil {
		return nil, nil, "", nil, err
	}
	if err = installationStageAudit(ctx, tx, r, actor, "resolution.attempt", "resolution"); err != nil {
		return nil, nil, "", nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, nil, "", nil, err
	}
	return r, nil, attempt, &c, nil
}

func (s *NetbirdInstallationStore) finishInstallationResolution(ctx context.Context, r *NetbirdInstallation, actor, resolutionID, attempt string, c netbirdcommand.ControlRequest, p *netbirdcommand.ControlResponse) (*NetbirdInstallationResolution, error) {
	tx, err := s.packages.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var completed, released *time.Time
	if err = tx.QueryRowContext(ctx, `SELECT completed_at,released_at FROM uem_netbird_installations WHERE id=$1 FOR UPDATE`, r.ID).Scan(&completed, &released); err != nil {
		return nil, err
	}
	var response any
	// Version-one release correlation additionally needs the original install
	// revision and operation, which its control envelope does not carry.
	if p != nil && p.Outcome == "ok" && (p.Receipt.Revision != r.Revision || p.Receipt.Operation != "install") {
		p = nil
	}
	if p != nil {
		wire, err := netbirdcommand.EncodeControlResponse(c, *p)
		if err != nil {
			return nil, err
		}
		response = string(wire)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_netbird_installation_control_results(attempt_id,response) VALUES($1,$2::jsonb)`, attempt, response); err != nil {
		return nil, err
	}
	if completed == nil && released == nil && p != nil && p.Outcome == "ok" && p.ReleaseID == resolutionID {
		if err = recordInstallationRelease(ctx, tx, r, actor, resolutionID, attempt, ""); err != nil {
			return nil, err
		}
	}
	if err = installationStageAudit(ctx, tx, r, actor, "resolution.observe", "resolution-result"); err != nil {
		return nil, err
	}
	d, err := readInstallationResolution(ctx, tx, r.ID)
	if err != nil {
		return nil, err
	}
	return d, tx.Commit()
}

func recordInstallationRelease(ctx context.Context, tx *sql.Tx, r *NetbirdInstallation, actor, resolutionID, attempt, observation string) error {
	var recorded time.Time
	err := tx.QueryRowContext(ctx, `INSERT INTO uem_netbird_installation_release_proofs(request_id,resolution_id,actor,attempt_id,observation_id) VALUES($1,$2,$3,nullif($4,'')::uuid,nullif($5,'')::uuid) RETURNING recorded_at`, r.ID, resolutionID, actor, attempt, observation).Scan(&recorded)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE uem_netbird_installations SET released_at=$2,released_by=$3,resolution_id=$4 WHERE id=$1`, r.ID, recorded, actor, resolutionID); err != nil {
		return err
	}
	return installationStageAudit(ctx, tx, r, actor, "release", "resolution")
}

// ReconcileInstallationResolution sends only a current-identity receipt query.
// A foreign release ID, a missing receipt, or a release with no owned mutating
// attempt leaves the barrier intact. Positive completion uses normal observation.
func (s *NetbirdInstallationStore) ReconcileInstallationResolution(parent context.Context, actor string, scope access.Scope, device, id, revision, resolutionID string) (*NetbirdInstallationResolution, error) {
	if parent == nil || s.control == nil || !canonicalRequestID(resolutionID) {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, r, err := s.installationRecord(ctx, actor, scope, device, id, revision, access.AssignSoftware)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	d, err := readInstallationResolution(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	if d == nil || d.ID != resolutionID {
		return nil, ErrNetbirdOperationConflict
	}
	if r.CompletedAt == nil && r.ReleasedAt == nil {
		v, _, err := s.installationResolutionTarget(ctx, tx, r)
		if err != nil {
			return nil, err
		}
		c, err := installationResolutionControl(ctx, tx, v, "receipt", uuid.NewString())
		if err != nil {
			return nil, err
		}
		p := s.installationControl(ctx, c)
		if _, err = recordInstallationObservation(ctx, tx, r, actor, c, p); err != nil {
			return nil, err
		}
		if p != nil && p.Outcome == "ok" && p.ReleaseID == resolutionID {
			kind := "release"
			if p.Receipt.Status == "withdrawn" {
				kind = "withdraw"
			}
			var attempted bool
			if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_netbird_installation_controls WHERE request_id=$1 AND resolution_id=$2 AND kind=$3)`, id, resolutionID, kind).Scan(&attempted); err != nil {
				return nil, err
			}
			if attempted {
				if err = recordInstallationRelease(ctx, tx, r, actor, resolutionID, "", c.RequestID); err != nil {
					return nil, err
				}
			}
		}
	}
	if err = installationStageAudit(ctx, tx, r, actor, "resolution.observe", "resolution-reconcile"); err != nil {
		return nil, err
	}
	d, err = readInstallationResolution(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	return d, tx.Commit()
}

func (s *NetbirdInstallationStore) ReadInstallationResolution(parent context.Context, actor string, scope access.Scope, device, id, revision string) (*NetbirdInstallationResolution, error) {
	if parent == nil {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, r, err := s.installationRecord(ctx, actor, scope, device, id, revision, access.ReadSoftware)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	d, err := readInstallationResolution(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	if err = installationAudit(ctx, tx, actor, r, "read", "recorded"); err != nil {
		return nil, err
	}
	return d, tx.Commit()
}

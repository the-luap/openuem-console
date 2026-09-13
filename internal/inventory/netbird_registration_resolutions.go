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

	"github.com/google/uuid"
	"github.com/open-uem/nats/netbirdcommand"
	"github.com/open-uem/openuem-console/internal/security/access"
)

// Registration resolution coordinates retained provider and agent evidence. A
// release is sent only after key absence, with its own committed control intent.
type NetbirdRegistrationResolutionStore struct {
	registrations *NetbirdRegistrationStore
	agent         *NetbirdResolutionStore
}

func NewNetbirdRegistrationResolutionStore(registrations *NetbirdRegistrationStore, control NetbirdOperationControl) (*NetbirdRegistrationResolutionStore, error) {
	if registrations == nil {
		return nil, ErrNetbirdOperationInvalid
	}
	agent, err := NewNetbirdResolutionStore(registrations.operations, control)
	if err != nil {
		return nil, err
	}
	return &NetbirdRegistrationResolutionStore{registrations, agent}, nil
}

type NetbirdRegistrationResolution struct {
	ID, RequestID, Actor, Revision, Kind string
	CreatedAt                            time.Time
	AgentAttemptedAt                     *time.Time
	ConfirmedAt                          *time.Time
	ConfirmedBy                          string
	LastRetry                            *NetbirdResolutionRetry
}
type NetbirdRegistrationResolutionReview struct {
	Registration                        *NetbirdRegistration
	Target                              ManualTarget
	Revision, KeyState, AgentState      string
	CanResolve, CanContinue, CanCleanup bool
	CanRetry                            bool
	RetryKind                           string
	Resolution                          *NetbirdRegistrationResolution
	agent                               *NetbirdResolutionReview
	generation                          string
	canWithdraw                         bool
}

func readRegistrationResolution(ctx context.Context, tx *sql.Tx, id string) (*NetbirdRegistrationResolution, error) {
	d := &NetbirdRegistrationResolution{}
	var attempted, confirmed sql.NullTime
	var actor sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT d.id,d.request_id,d.actor,d.revision,d.kind,d.created_at,a.created_at,e.created_at,e.actor FROM uem_netbird_registration_resolutions d LEFT JOIN uem_netbird_registration_resolution_attempts a ON a.request_id=d.request_id LEFT JOIN uem_netbird_registration_resolution_evidence e ON e.request_id=d.request_id WHERE d.request_id=$1`, id).Scan(&d.ID, &d.RequestID, &d.Actor, &d.Revision, &d.Kind, &d.CreatedAt, &attempted, &confirmed, &actor)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if attempted.Valid {
		d.AgentAttemptedAt = &attempted.Time
	}
	if confirmed.Valid {
		d.ConfirmedAt = &confirmed.Time
		d.ConfirmedBy = actor.String
	}
	d.LastRetry, err = readNetbirdResolutionRetry(ctx, tx, "registration", id)
	return d, err
}
func (s *NetbirdRegistrationResolutionStore) begin(ctx context.Context, actor string, scope access.Scope, device, id string) (*sql.Tx, *NetbirdRegistration, error) {
	if !canonicalRequestID(id) || !ValidReportDeviceID(device) {
		return nil, nil, ErrNetbirdOperationInvalid
	}
	tx, err := s.registrations.operations.recordTx(ctx, actor, scope, access.ManageDeviceSecurity)
	if err != nil {
		return nil, nil, err
	}
	r, err := recordedRegistration(ctx, tx, scope, device, id, "FOR UPDATE OF r")
	if err == nil {
		_, err = registrationEvidence(ctx, tx, r)
	}
	if err == nil && (r.Status != "unconfirmed" || !slices.Contains(r.Attempts, "create")) {
		err = ErrNetbirdOperationConflict
	}
	if err != nil {
		tx.Rollback()
		return nil, nil, err
	}
	return tx, r, nil
}
func registrationResolutionKind(state string) string {
	switch state {
	case "not-attempted":
		return "not-delivered"
	case "completed":
		return "acknowledge"
	case "unconfirmed":
		return "release"
	case "not-received", "withdrawn":
		return "withdraw"
	default:
		return ""
	}
}
func (s *NetbirdRegistrationResolutionStore) currentTarget(ctx context.Context, tx *sql.Tx, r *NetbirdRegistration) (*NetbirdRegistrationResolutionReview, error) {
	operation := &NetbirdOperation{ID: r.ID, DeviceID: r.DeviceID, Scope: r.Scope, Individual: r.Individual, Revision: r.Revision, Operation: "register", CommandHash: r.CommandHash}
	agent, generation, err := s.agent.currentTarget(ctx, tx, operation)
	if err != nil {
		return nil, err
	}
	return &NetbirdRegistrationResolutionReview{Registration: r, Target: agent.Target, agent: agent, generation: generation}, nil
}
func registrationRecoveryControl(ctx context.Context, v *NetbirdResolutionReview, kind, id string) netbirdcommand.ControlRequest {
	durationKind := kind
	if kind == "withdraw" {
		durationKind = "release"
	}
	c := netbirdControlRequest(ctx, v, durationKind, id)
	c.Version, c.Kind = netbirdcommand.RecoveryVersion, kind
	c.Revision, c.Operation = v.Operation.Revision, v.Operation.Operation
	return c
}

func (s *NetbirdRegistrationResolutionStore) agentEvidence(ctx context.Context, v *NetbirdRegistrationResolutionReview) error {
	if !slices.Contains(v.Registration.Attempts, "deliver") {
		v.AgentState = "not-attempted"
		return nil
	}
	if !netbirdcommand.ValidDigest(v.Registration.CommandHash) {
		return ErrNetbirdOperationConflict
	}
	a := v.agent
	a.response = nil
	a.CanRelease = false
	v.canWithdraw = false
	a.query = netbirdControlRequest(ctx, a, "receipt", uuid.NewString())
	if v.Resolution != nil && v.Resolution.Kind == "withdraw" {
		a.query = registrationRecoveryControl(ctx, a, "receipt", uuid.NewString())
	}
	response, err := s.agent.request(ctx, a.query)
	if err != nil {
		v.AgentState = "unavailable"
		return nil
	}
	if response.Outcome == "missing" && a.query.Version != netbirdcommand.RecoveryVersion {
		// A correlated version-two response, not a legacy missing receipt, proves
		// that the owner supports durable withdrawal and extended receipt queries.
		a.query = registrationRecoveryControl(ctx, a, "receipt", uuid.NewString())
		response, err = s.agent.request(ctx, a.query)
		if err != nil {
			v.AgentState = "recovery-unavailable"
			return nil
		}
	}
	a.response = response
	v.AgentState = response.Outcome
	if response.Outcome == "missing" {
		journal, valid := s.registrationAgentJournal(ctx, v)
		if !valid {
			v.AgentState = "unavailable"
			return nil
		}
		v.canWithdraw = journal.Status == "ready" && journal.Remaining > 0
		if v.canWithdraw {
			v.AgentState = "not-received"
		} else {
			v.AgentState = "waiting"
		}
		return nil
	}
	if response.Outcome != "ok" {
		return nil
	}
	if !netbirdResolutionReceipt(a, response) {
		return ErrNetbirdOperationConflict
	}
	v.AgentState = response.Receipt.Status
	if response.Receipt.Status == "withdrawn" {
		if v.Resolution == nil || v.Resolution.Kind != "withdraw" || v.Resolution.ID != response.ReleaseID {
			v.AgentState = "conflict"
		}
		return nil
	}
	if response.Receipt.Status == "completed" {
		a.CanRelease = true
		return nil
	}
	if response.ReleaseID != "" {
		if v.Resolution == nil || v.Resolution.ID != response.ReleaseID {
			v.AgentState = "conflict"
		}
		return nil
	}
	journal, valid := s.registrationAgentJournal(ctx, v)
	if !valid {
		v.AgentState = "unavailable"
		return nil
	}
	a.CanRelease = journal.Status == "unconfirmed" && journal.CanRelease && journal.PendingID == v.Registration.ID && journal.PendingHash == v.Registration.CommandHash
	if !a.CanRelease {
		v.AgentState = "waiting"
	}
	return nil
}

func (s *NetbirdRegistrationResolutionStore) registrationAgentJournal(ctx context.Context, v *NetbirdRegistrationResolutionReview) (netbirdcommand.State, bool) {
	deadline := netbirdControlRequest(ctx, v.agent, "receipt", uuid.NewString()).ExpiresAt
	call, cancel := context.WithDeadline(ctx, deadline)
	journal, err := s.registrations.operations.inspect(call, v.agent.identity)
	valid := err == nil && call.Err() == nil && journal.Valid()
	cancel()
	if valid {
		data, _ := json.Marshal(journal)
		v.generation += "/" + string(data)
	}
	return journal, valid
}
func (s *NetbirdRegistrationResolutionStore) review(ctx context.Context, tx *sql.Tx, r *NetbirdRegistration) (*NetbirdRegistrationResolutionReview, error) {
	d, err := readRegistrationResolution(ctx, tx, r.ID)
	if err != nil {
		return nil, err
	}
	if r.ReleasedAt != nil {
		return &NetbirdRegistrationResolutionReview{Registration: r, Target: ManualTarget{ID: r.DeviceID, Scope: r.Scope}, Resolution: d, KeyState: "absent", AgentState: "resolved"}, nil
	}
	v, err := s.currentTarget(ctx, tx, r)
	if err != nil {
		return nil, err
	}
	v.Resolution = d
	v.KeyState = "unknown"
	if r.Key != nil {
		if r.KeyAbsent {
			v.KeyState = "absent"
		} else {
			snapshot, err := s.registrations.snapshot(r)
			if err != nil {
				v.KeyState = "unavailable"
			} else {
				observed, absent, err := s.registrations.observe(ctx, snapshot, r.Key.ID)
				switch {
				case err != nil:
					v.KeyState = "unavailable"
				case absent:
					v.KeyState = "absent"
				case observed == nil || !r.Key.SameOwnership(*observed):
					v.KeyState = "changed"
				default:
					v.KeyState = "present"
				}
			}
		}
	}
	if err = s.agentEvidence(ctx, v); err != nil {
		return nil, err
	}
	v.CanCleanup = r.Key != nil && !slices.Contains(r.Attempts, "delete") && (v.KeyState == "present" || v.KeyState == "absent")
	eligible := v.AgentState == "not-attempted" || v.AgentState == "completed" || v.AgentState == "unconfirmed" && v.agent.CanRelease || v.AgentState == "not-received" && v.canWithdraw
	keyReady := v.KeyState == "absent" || v.CanCleanup
	if d == nil {
		v.CanResolve = eligible && keyReady
	} else {
		compatible := d.Kind == registrationResolutionKind(v.AgentState) || d.Kind == "withdraw" && v.AgentState == "completed"
		v.CanContinue = compatible && eligible && keyReady && d.AgentAttemptedAt == nil && d.LastRetry == nil
		attempted := d.AgentAttemptedAt != nil || d.LastRetry != nil
		if r.KeyAbsent && v.AgentState == "unconfirmed" && v.agent.CanRelease && (d.Kind == "withdraw" || d.Kind == "release" && attempted) {
			v.CanRetry, v.RetryKind = true, "release"
		}
		if r.KeyAbsent && v.AgentState == "not-received" && v.canWithdraw && d.Kind == "withdraw" && attempted && (d.LastRetry == nil || d.LastRetry.Kind != "release") {
			v.CanRetry, v.RetryKind = true, "withdraw"
		}
	}
	var receipt netbirdcommand.Receipt
	var release string
	if v.agent.response != nil {
		receipt = v.agent.response.Receipt
		release = v.agent.response.ReleaseID
	}
	data, _ := json.Marshal([]any{r.ID, r.Revision, r.CommandHash, v.generation, v.KeyState, r.KeyAbsent, r.Attempts, v.AgentState, receipt, release, v.CanResolve, v.CanContinue, v.CanCleanup, v.CanRetry, v.RetryKind, d})
	digest := sha256.Sum256(data)
	v.Revision = hex.EncodeToString(digest[:])
	return v, nil
}
func (s *NetbirdRegistrationResolutionStore) Review(parent context.Context, actor string, scope access.Scope, device, id string) (*NetbirdRegistrationResolutionReview, error) {
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	tx, r, err := s.begin(ctx, actor, scope, device, id)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	v, err := s.review(ctx, tx, r)
	if err != nil {
		return nil, err
	}
	if err = registrationAudit(ctx, tx, r, actor, "resolution.review", "resolution"); err != nil {
		return nil, err
	}
	return v, tx.Commit()
}
func (s *NetbirdRegistrationResolutionStore) recordIntent(ctx context.Context, r *NetbirdRegistration, actor, id, revision, kind string) error {
	tx, err := s.registrations.operations.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO uem_netbird_registration_resolutions(request_id,id,actor,revision,kind,command_hash) VALUES($1,$2,$3,$4,$5,$6)`, r.ID, id, actor, revision, kind, r.CommandHash)
	if err != nil {
		return err
	}
	if err = registrationAudit(ctx, tx, r, actor, "resolution.attempt", "resolution-intent"); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *NetbirdRegistrationResolutionStore) recordControl(ctx context.Context, r *NetbirdRegistration, d *NetbirdRegistrationResolution, actor string, c netbirdcommand.ControlRequest) error {
	wire, err := netbirdcommand.EncodeControl(c)
	if err != nil {
		return err
	}
	hash, err := c.Digest()
	if err != nil {
		return err
	}
	tx, err := s.registrations.operations.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO uem_netbird_registration_resolution_attempts(request_id,resolution_id,actor,control,control_hash) VALUES($1,$2,$3,$4,$5)`, r.ID, d.ID, actor, string(wire), hash)
	if err != nil {
		return err
	}
	if err = registrationAudit(ctx, tx, r, actor, "resolution.attempt", "agent-resolution"); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *NetbirdRegistrationResolutionStore) pending(ctx context.Context, tx *sql.Tx, r *NetbirdRegistration, d *NetbirdRegistrationResolution, actor string) (*NetbirdRegistrationResolution, error) {
	if err := registrationAudit(ctx, tx, r, actor, "resolution.observe", "resolution"); err != nil {
		return nil, err
	}
	current, err := readRegistrationResolution(ctx, tx, r.ID)
	if err != nil {
		return nil, err
	}
	return current, tx.Commit()
}

func (s *NetbirdRegistrationResolutionStore) finish(ctx context.Context, tx *sql.Tx, v *NetbirdRegistrationResolutionReview, d *NetbirdRegistrationResolution, actor string, c netbirdcommand.ControlRequest, p *netbirdcommand.ControlResponse) (*NetbirdRegistrationResolution, error) {
	r := v.Registration
	matched := r.KeyAbsent
	control, response := []byte(`{}`), []byte(`{}`)
	if d.Kind == "not-delivered" {
		matched = matched && !slices.Contains(r.Attempts, "deliver")
	} else {
		matched = matched && p != nil && p.Matches(c) && netbirdResolutionReceipt(v.agent, p)
		if matched && d.Kind == "release" {
			matched = p.Receipt.Status == "unconfirmed" && p.ReleaseID == d.ID
		}
		if matched && d.Kind == "acknowledge" {
			matched = p.Receipt.Status == "completed" && p.ReleaseID == ""
		}
		if matched && d.Kind == "withdraw" {
			matched = (p.Receipt.Status == "withdrawn" && p.ReleaseID == d.ID) || (c.Kind == "receipt" && p.Receipt.Status == "completed" && p.ReleaseID == "") || (d.LastRetry != nil && d.LastRetry.Kind == "release" && p.Receipt.Status == "unconfirmed" && p.ReleaseID == d.ID)
		}
		if matched {
			var err error
			control, err = netbirdcommand.EncodeControl(c)
			if err != nil {
				return nil, err
			}
			response, err = netbirdcommand.EncodeControlResponse(c, *p)
			if err != nil {
				return nil, err
			}
		}
	}
	if !matched {
		return s.pending(ctx, tx, r, d, actor)
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO uem_netbird_registration_resolution_evidence(request_id,resolution_id,actor,control,response) VALUES($1,$2,$3,$4,$5)`, r.ID, d.ID, actor, string(control), string(response))
	if err != nil {
		return nil, err
	}
	_, err = tx.ExecContext(ctx, `UPDATE uem_netbird_registrations SET released_at=clock_timestamp(),released_by=$2 WHERE id=$1`, r.ID, actor)
	if err != nil {
		return nil, err
	}
	if err = registrationAudit(ctx, tx, r, actor, "release", "resolution"); err != nil {
		return nil, err
	}
	result, err := readRegistrationResolution(ctx, tx, r.ID)
	if err != nil {
		return nil, err
	}
	return result, tx.Commit()
}

// advance may attempt each external stage only once. On replay, only a fresh,
// explicitly confirmed continuation can begin an as-yet unattempted stage.
func (s *NetbirdRegistrationResolutionStore) advance(ctx context.Context, tx *sql.Tx, v *NetbirdRegistrationResolutionReview, d *NetbirdRegistrationResolution, actor string, allowNew bool) (*NetbirdRegistrationResolution, error) {
	r := v.Registration
	if !r.KeyAbsent {
		if r.Key == nil {
			return s.pending(ctx, tx, r, d, actor)
		}
		if !allowNew && !slices.Contains(r.Attempts, "delete") {
			return s.pending(ctx, tx, r, d, actor)
		}
		snapshot, err := s.registrations.snapshot(r)
		if err != nil {
			return nil, err
		}
		if err = s.registrations.cleanupAs(ctx, r, snapshot, actor); err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return s.pending(ctx, tx, r, d, actor)
		}
	}
	if !r.KeyAbsent {
		return s.pending(ctx, tx, r, d, actor)
	}
	if d.Kind == "not-delivered" {
		return s.finish(ctx, tx, v, d, actor, netbirdcommand.ControlRequest{}, nil)
	}
	// Recheck the agent after provider cleanup. Its local state may have changed
	// while the provider call was in flight, despite retained console authority.
	v.agent.CanRelease = false
	if err := s.agentEvidence(ctx, v); err != nil {
		return nil, err
	}
	c, p := v.agent.query, v.agent.response
	if d.AgentAttemptedAt == nil && d.LastRetry == nil {
		if d.Kind != registrationResolutionKind(v.AgentState) && !(d.Kind == "withdraw" && v.AgentState == "completed") {
			return s.pending(ctx, tx, r, d, actor)
		}
		if d.Kind == "release" {
			if !allowNew || !v.agent.CanRelease {
				return s.pending(ctx, tx, r, d, actor)
			}
			c = netbirdControlRequest(ctx, v.agent, "release", d.ID)
		}
		if d.Kind == "withdraw" && v.AgentState != "completed" {
			if !allowNew || !v.canWithdraw {
				return s.pending(ctx, tx, r, d, actor)
			}
			c = registrationRecoveryControl(ctx, v.agent, "withdraw", d.ID)
		}
		if err := s.recordControl(ctx, r, d, actor, c); err != nil {
			return nil, err
		}
		if c.Kind == "release" || c.Kind == "withdraw" {
			var err error
			p, err = s.agent.request(ctx, c)
			if err != nil {
				p = nil
			}
		}
	}
	return s.finish(ctx, tx, v, d, actor, c, p)
}

func (s *NetbirdRegistrationResolutionStore) Resolve(parent context.Context, actor string, scope access.Scope, device, id, resolutionID, revision string) (*NetbirdRegistrationResolution, error) {
	if !canonicalRequestID(resolutionID) || !validManualRevision(revision) {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 45*time.Second)
	defer cancel()
	tx, r, err := s.begin(ctx, actor, scope, device, id)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	d, err := readRegistrationResolution(ctx, tx, r.ID)
	if err != nil {
		return nil, err
	}
	if d != nil {
		if d.ID != resolutionID || d.Actor != actor || d.Revision != revision {
			return nil, ErrNetbirdOperationConflict
		}
		if err = registrationAudit(ctx, tx, r, actor, "read", "resolution"); err != nil {
			return nil, err
		}
		return d, tx.Commit()
	}
	v, err := s.review(ctx, tx, r)
	if err != nil {
		return nil, err
	}
	if !v.CanResolve || v.Revision != revision {
		return nil, ErrNetbirdOperationChanged
	}
	kind := registrationResolutionKind(v.AgentState)
	if err = s.recordIntent(ctx, r, actor, resolutionID, revision, kind); err != nil {
		return nil, err
	}
	d, err = readRegistrationResolution(ctx, tx, r.ID)
	if err != nil {
		return nil, err
	}
	v.Resolution = d
	return s.advance(ctx, tx, v, d, actor, true)
}

// Continue requires a new review. It can start an unattempted cleanup/release,
// while retaining the original resolution identity and never repeating a stage.
func (s *NetbirdRegistrationResolutionStore) Continue(parent context.Context, actor string, scope access.Scope, device, id, resolutionID, revision string) (*NetbirdRegistrationResolution, error) {
	if !canonicalRequestID(resolutionID) || !validManualRevision(revision) {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 45*time.Second)
	defer cancel()
	tx, r, err := s.begin(ctx, actor, scope, device, id)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	v, err := s.review(ctx, tx, r)
	if err != nil {
		return nil, err
	}
	if v.Resolution == nil || v.Resolution.ID != resolutionID || !v.CanContinue || v.Revision != revision {
		return nil, ErrNetbirdOperationChanged
	}
	return s.advance(ctx, tx, v, v.Resolution, actor, true)
}

// Reconcile only reads external evidence. It cannot create a resolution intent,
// repeat DELETE, or send a release that has not yet been explicitly attempted.
func (s *NetbirdRegistrationResolutionStore) Reconcile(parent context.Context, actor string, scope access.Scope, device, id, resolutionID string) (*NetbirdRegistrationResolution, error) {
	if !canonicalRequestID(resolutionID) {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	tx, r, err := s.begin(ctx, actor, scope, device, id)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	d, err := readRegistrationResolution(ctx, tx, r.ID)
	if err != nil {
		return nil, err
	}
	if d == nil || d.ID != resolutionID {
		return nil, ErrNetbirdOperationConflict
	}
	if r.ReleasedAt != nil {
		if err = registrationAudit(ctx, tx, r, actor, "read", "resolution"); err != nil {
			return nil, err
		}
		return d, tx.Commit()
	}
	v, err := s.currentTarget(ctx, tx, r)
	if err != nil {
		return nil, err
	}
	v.Resolution = d
	return s.advance(ctx, tx, v, d, actor, false)
}

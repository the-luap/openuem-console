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

// NetbirdOperationControl sends a single correlated control. It must honor its
// deadline and never retry mutating controls. The store checks the response again.
type NetbirdOperationControl func(context.Context, netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error)

type NetbirdResolutionStore struct {
	operations *NetbirdOperationStore
	control    NetbirdOperationControl
}

func NewNetbirdResolutionStore(operations *NetbirdOperationStore, control NetbirdOperationControl) (*NetbirdResolutionStore, error) {
	if operations == nil || control == nil {
		return nil, ErrNetbirdOperationInvalid
	}
	return &NetbirdResolutionStore{operations: operations, control: control}, nil
}

type NetbirdResolution struct {
	ID, RequestID, Actor, Revision, Kind string
	CreatedAt                            time.Time
	ConfirmedAt                          *time.Time
	ConfirmedBy                          string
	LastRetry                            *NetbirdResolutionRetry
}

type NetbirdResolutionReview struct {
	Operation         *NetbirdOperation
	Target            ManualTarget
	Revision, Outcome string
	CanRelease        bool
	CanRetry          bool
	CanWithdraw       bool
	RetryKind         string
	Resolution        *NetbirdResolution
	identity          netbirdcommand.Identity
	identityExpiry    time.Time
	query             netbirdcommand.ControlRequest
	response          *netbirdcommand.ControlResponse
}

func readNetbirdResolution(ctx context.Context, tx *sql.Tx, id string) (*NetbirdResolution, error) {
	d := &NetbirdResolution{}
	var confirmed sql.NullTime
	var actor sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT d.id,d.request_id,d.actor,d.revision,d.kind,d.created_at,e.created_at,e.actor FROM uem_netbird_resolutions d LEFT JOIN uem_netbird_resolution_evidence e ON e.request_id=d.request_id WHERE d.request_id=$1`, id).Scan(&d.ID, &d.RequestID, &d.Actor, &d.Revision, &d.Kind, &d.CreatedAt, &confirmed, &actor)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if confirmed.Valid {
		d.ConfirmedAt = &confirmed.Time
		d.ConfirmedBy = actor.String
	}
	d.LastRetry, err = readNetbirdResolutionRetry(ctx, tx, "operation", id)
	return d, err
}

func (s *NetbirdResolutionStore) begin(ctx context.Context, actor string, scope access.Scope, device, id string) (*sql.Tx, *NetbirdOperation, error) {
	if !canonicalRequestID(id) || !ValidReportDeviceID(device) {
		return nil, nil, ErrNetbirdOperationInvalid
	}
	tx, err := s.operations.recordTx(ctx, actor, scope, access.ManageDeviceSecurity)
	if err != nil {
		return nil, nil, err
	}
	r, err := netbirdRecorded(ctx, tx, scope, device, id, "FOR UPDATE OF r")
	if err == nil {
		err = netbirdAttempt(ctx, tx, r)
	}
	if err == nil && (r.Status != "unconfirmed" || !netbirdcommand.ValidDigest(r.CommandHash) || r.AttemptedAt == nil) {
		err = ErrNetbirdOperationConflict
	}
	if err != nil {
		tx.Rollback()
		return nil, nil, err
	}
	return tx, r, nil
}

// currentTarget uses current inventory and enrollment authority, not historical
// read permission. Provider settings/installation reports are not release identity.
func (s *NetbirdResolutionStore) currentTarget(ctx context.Context, tx *sql.Tx, r *NetbirdOperation) (*NetbirdResolutionReview, string, error) {
	if s.operations.individual != r.Individual {
		return nil, "", ErrNetbirdOperationChanged
	}
	manual := &ManualExecutionStore{db: s.operations.db, permissions: s.operations.permissions, individual: s.operations.individual}
	target, err := manual.target(ctx, tx, r.Scope, r.DeviceID)
	if err != nil {
		return nil, "", err
	}
	v := &NetbirdResolutionReview{Operation: r, Target: target, identity: netbirdcommand.Identity{DeviceID: r.DeviceID, TenantID: int64(r.Scope.TenantID), SiteID: int64(r.Scope.SiteID), Individual: r.Individual}}
	var generation, broker string
	var consumer int64
	if err = tx.QueryRowContext(ctx, `SELECT revision::text FROM uem_netbird_device_bindings WHERE device_id=$1 FOR SHARE`, r.DeviceID).Scan(&generation); err != nil {
		return nil, "", err
	}
	if r.Individual {
		err = tx.QueryRowContext(ctx, `SELECT i.certificate_hash,i.broker_key,i.certificate_expires_at,q.revision FROM uem_agent_identities i JOIN uem_agent_command_consumers q ON q.device_id=i.id WHERE i.id=$1 AND i.tenant_id=$2 AND i.site_id=$3 FOR SHARE OF i,q`, r.DeviceID, r.Scope.TenantID, r.Scope.SiteID).Scan(&v.identity.CertificateHash, &broker, &v.identityExpiry, &consumer)
		if err != nil {
			return nil, "", err
		}
	}
	if !v.identity.Valid() {
		return nil, "", ErrNetbirdOperationChanged
	}
	data, _ := json.Marshal(struct {
		Identity           netbirdcommand.Identity
		Generation, Broker string
		Consumer           int64
	}{v.identity, generation, broker, consumer})
	return v, string(data), nil
}

func netbirdControlRequest(ctx context.Context, v *NetbirdResolutionReview, kind, id string) netbirdcommand.ControlRequest {
	now := time.Now().UTC()
	expires := now.Add(netbirdcommand.ControlLifetime)
	if kind != "release" {
		expires = now.Add(2 * time.Second)
	}
	if d, ok := ctx.Deadline(); ok && d.Before(expires) {
		expires = d
	}
	if !v.identityExpiry.IsZero() && v.identityExpiry.Before(expires) {
		expires = v.identityExpiry
	}
	return netbirdcommand.ControlRequest{Version: netbirdcommand.Version, Identity: v.identity, RequestID: id, Kind: kind, ReferenceID: v.Operation.ID, CommandHash: v.Operation.CommandHash, IssuedAt: now, ExpiresAt: expires}
}

func netbirdRecoveryControl(ctx context.Context, v *NetbirdResolutionReview, kind, id string) netbirdcommand.ControlRequest {
	durationKind := kind
	if kind == "withdraw" {
		durationKind = "release"
	}
	c := netbirdControlRequest(ctx, v, durationKind, id)
	c.Version, c.Kind = netbirdcommand.RecoveryVersion, kind
	c.Revision, c.Operation = v.Operation.Revision, v.Operation.Operation
	return c
}

func (s *NetbirdResolutionStore) request(ctx context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
	if !c.Executable(c.Identity, time.Now()) {
		return nil, ErrNetbirdOperationNotReady
	}
	call, cancel := context.WithDeadline(ctx, c.ExpiresAt)
	defer cancel()
	r, err := s.control(call, c)
	if err != nil || call.Err() != nil || r == nil || !r.Matches(c) {
		return nil, ErrNetbirdOperationNotReady
	}
	return r, nil
}

func netbirdResolutionReceipt(v *NetbirdResolutionReview, r *netbirdcommand.ControlResponse) bool {
	return r != nil && r.Outcome == "ok" && r.Receipt.RequestID == v.Operation.ID && r.Receipt.CommandHash == v.Operation.CommandHash && r.Receipt.DeviceID == v.Operation.DeviceID && r.Receipt.Revision == v.Operation.Revision && r.Receipt.Operation == v.Operation.Operation
}

func (s *NetbirdResolutionStore) review(ctx context.Context, tx *sql.Tx, r *NetbirdOperation) (*NetbirdResolutionReview, error) {
	v, generation, err := s.currentTarget(ctx, tx, r)
	if err != nil {
		return nil, err
	}
	v.Resolution, err = readNetbirdResolution(ctx, tx, r.ID)
	if err != nil {
		return nil, err
	}
	if r.ReleasedAt != nil {
		v.Outcome = "released"
		return v, nil
	}
	v.query = netbirdControlRequest(ctx, v, "receipt", uuid.NewString())
	if v.Resolution != nil && v.Resolution.Kind == "withdraw" {
		v.query = netbirdRecoveryControl(ctx, v, "receipt", uuid.NewString())
	}
	v.response, err = s.request(ctx, v.query)
	if err != nil {
		return nil, err
	}
	v.Outcome = v.response.Outcome
	if v.Outcome == "missing" && v.query.Version != netbirdcommand.RecoveryVersion {
		// A legacy missing receipt cannot establish permanent-withdrawal support.
		v.query = netbirdRecoveryControl(ctx, v, "receipt", uuid.NewString())
		v.response, err = s.request(ctx, v.query)
		if err != nil {
			v.Outcome = "recovery-unavailable"
		} else {
			v.Outcome = v.response.Outcome
		}
	}
	var journal netbirdcommand.State
	if v.Outcome == "missing" {
		journal, err = s.resolutionJournal(ctx, v)
		if err != nil {
			return nil, err
		}
		eligible := journal.Status == "ready" && journal.Remaining > 0
		if eligible {
			v.Outcome = "not-received"
			v.CanWithdraw = v.Resolution == nil
			v.CanRetry = v.Resolution != nil && v.Resolution.Kind == "withdraw" && (v.Resolution.LastRetry == nil || v.Resolution.LastRetry.Kind != "release")
			if v.CanRetry {
				v.RetryKind = "withdraw"
			}
		} else {
			v.Outcome = "waiting"
			if journal.Status == "full" {
				v.Outcome = "full"
			}
		}
	}
	if v.Outcome == "ok" {
		if !netbirdResolutionReceipt(v, v.response) {
			return nil, ErrNetbirdOperationConflict
		}
		v.Outcome = v.response.Receipt.Status
		if v.Outcome == "withdrawn" {
			if v.Resolution == nil || v.Resolution.Kind != "withdraw" || v.response.ReleaseID != v.Resolution.ID {
				v.Outcome = "conflict"
			}
		} else if v.Outcome == "completed" {
			v.CanRelease = v.Resolution == nil
		} else if v.response.ReleaseID != "" {
			if v.Resolution == nil || v.response.ReleaseID != v.Resolution.ID {
				v.Outcome = "conflict"
			}
		} else if v.Outcome == "unconfirmed" {
			journal, err = s.resolutionJournal(ctx, v)
			if err != nil {
				return nil, err
			}
			eligible := journal.Status == "unconfirmed" && journal.CanRelease && journal.PendingID == r.ID && journal.PendingHash == r.CommandHash
			v.CanRelease = eligible && v.Resolution == nil
			v.CanRetry = eligible && v.Resolution != nil && (v.Resolution.Kind == "release" || v.Resolution.Kind == "withdraw")
			if v.CanRetry {
				v.RetryKind = "release"
			}
			if !eligible {
				v.Outcome = "waiting"
			}
		}
	}
	// Time, query UUID and response request hash are deliberately excluded: a
	// fresh read of the same evidence must preserve the reviewed revision.
	var release string
	var receipt netbirdcommand.Receipt
	if v.response != nil {
		release, receipt = v.response.ReleaseID, v.response.Receipt
	}
	data, _ := json.Marshal([]any{generation, r.ID, r.CommandHash, v.Outcome, release, receipt, journal, v.CanRelease, v.CanWithdraw, v.CanRetry, v.RetryKind, v.Resolution})
	digest := sha256.Sum256(data)
	v.Revision = hex.EncodeToString(digest[:])
	return v, nil
}

func (s *NetbirdResolutionStore) resolutionJournal(ctx context.Context, v *NetbirdResolutionReview) (netbirdcommand.State, error) {
	deadline := netbirdControlRequest(ctx, v, "receipt", uuid.NewString()).ExpiresAt
	probe, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	journal, err := s.operations.inspect(probe, v.identity)
	if err != nil || probe.Err() != nil || !journal.Valid() {
		return netbirdcommand.State{}, ErrNetbirdOperationNotReady
	}
	return journal, nil
}

func (s *NetbirdResolutionStore) Review(parent context.Context, actor string, scope access.Scope, device, id string) (*NetbirdResolutionReview, error) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
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
	if err = netbirdOperationAudit(ctx, tx, r, actor, "resolution.review", "recorded"); err != nil {
		return nil, err
	}
	return v, tx.Commit()
}

func (s *NetbirdResolutionStore) recordIntent(ctx context.Context, r *NetbirdOperation, actor, id, revision, kind string, c netbirdcommand.ControlRequest) error {
	wire, err := netbirdcommand.EncodeControl(c)
	if err != nil {
		return err
	}
	hash, err := c.Digest()
	if err != nil {
		return err
	}
	tx, err := s.operations.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO uem_netbird_resolutions(request_id,id,device_id,tenant_id,site_id,actor,individual,command_hash,revision,kind,control,control_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12)`, r.ID, id, r.DeviceID, r.Scope.TenantID, r.Scope.SiteID, actor, r.Individual, r.CommandHash, revision, kind, string(wire), hash)
	if err != nil {
		return err
	}
	if err = netbirdOperationAudit(ctx, tx, r, actor, "resolution.attempt", "recorded"); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *NetbirdResolutionStore) finish(ctx context.Context, tx *sql.Tx, v *NetbirdResolutionReview, d *NetbirdResolution, actor string, c netbirdcommand.ControlRequest, p *netbirdcommand.ControlResponse) (*NetbirdResolution, error) {
	matched := netbirdResolutionReceipt(v, p) && p.Matches(c)
	if matched && d.Kind == "release" {
		matched = p.Receipt.Status == "unconfirmed" && p.ReleaseID == d.ID
	}
	if matched && d.Kind == "acknowledge" {
		matched = p.Receipt.Status == "completed" && p.ReleaseID == ""
	}
	if matched && d.Kind == "withdraw" {
		matched = (p.Receipt.Status == "withdrawn" && p.ReleaseID == d.ID) || (c.Kind == "receipt" && p.Receipt.Status == "completed" && p.ReleaseID == "") || (d.LastRetry != nil && d.LastRetry.Kind == "release" && p.Receipt.Status == "unconfirmed" && p.ReleaseID == d.ID)
	}
	if !matched {
		if err := netbirdOperationAudit(ctx, tx, v.Operation, actor, "resolution.observe", "failure"); err != nil {
			return nil, err
		}
		return d, tx.Commit()
	}
	wire, err := netbirdcommand.EncodeControl(c)
	if err != nil {
		return nil, err
	}
	response, err := netbirdcommand.EncodeControlResponse(c, *p)
	if err != nil {
		return nil, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO uem_netbird_resolution_evidence(request_id,resolution_id,actor,control,response) VALUES($1,$2,$3,$4::jsonb,$5::jsonb)`, v.Operation.ID, d.ID, actor, string(wire), string(response))
	if err != nil {
		return nil, err
	}
	_, err = tx.ExecContext(ctx, `UPDATE uem_netbird_operations SET released_at=clock_timestamp(),released_by=$2 WHERE id=$1`, v.Operation.ID, actor)
	if err != nil {
		return nil, err
	}
	if err = netbirdOperationAudit(ctx, tx, v.Operation, actor, "release", "recorded"); err != nil {
		return nil, err
	}
	d, err = readNetbirdResolution(ctx, tx, v.Operation.ID)
	if err != nil {
		return nil, err
	}
	return d, tx.Commit()
}

// Resolve persists one immutable intent before a mutating control. Replays return it and
// never send another mutating control, including after outer transaction failure.
func (s *NetbirdResolutionStore) Resolve(parent context.Context, actor string, scope access.Scope, device, id, resolutionID, revision string) (*NetbirdResolution, error) {
	if !canonicalRequestID(resolutionID) || !validManualRevision(revision) {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	tx, r, err := s.begin(ctx, actor, scope, device, id)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	existing, err := readNetbirdResolution(ctx, tx, r.ID)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		if existing.ID != resolutionID || existing.Actor != actor || existing.Revision != revision {
			return nil, ErrNetbirdOperationConflict
		}
		if err = netbirdOperationAudit(ctx, tx, r, actor, "read", "recorded"); err != nil {
			return nil, err
		}
		return existing, tx.Commit()
	}
	if r.ReleasedAt != nil {
		return nil, ErrNetbirdOperationConflict
	}
	v, err := s.review(ctx, tx, r)
	if err != nil {
		return nil, err
	}
	if (!v.CanRelease && !v.CanWithdraw) || v.Revision != revision {
		return nil, ErrNetbirdOperationChanged
	}
	kind := "acknowledge"
	c := v.query
	p := v.response
	if v.Outcome == "unconfirmed" {
		kind = "release"
		c = netbirdControlRequest(ctx, v, "release", resolutionID)
	}
	if v.CanWithdraw {
		kind = "withdraw"
		c = netbirdRecoveryControl(ctx, v, "withdraw", resolutionID)
	}
	if err = s.recordIntent(ctx, r, actor, resolutionID, revision, kind, c); err != nil {
		return nil, err
	}
	d, err := readNetbirdResolution(ctx, tx, r.ID)
	if err != nil {
		return nil, err
	}
	if kind == "release" || kind == "withdraw" {
		p, err = s.request(ctx, c)
		// Loss of a response leaves the immutable intent available for read-only
		// reconciliation. No private transport error is retained or exposed.
		if err != nil {
			p = nil
		}
	}
	return s.finish(ctx, tx, v, d, actor, c, p)
}

// Reconcile only queries the original command under current target identity. It
// cannot create an intent, retry a mutation or change the original outcome.
func (s *NetbirdResolutionStore) Reconcile(parent context.Context, actor string, scope access.Scope, device, id, resolutionID string) (*NetbirdResolution, error) {
	if !canonicalRequestID(resolutionID) {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, r, err := s.begin(ctx, actor, scope, device, id)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	d, err := readNetbirdResolution(ctx, tx, r.ID)
	if err != nil {
		return nil, err
	}
	if d == nil || d.ID != resolutionID {
		return nil, ErrNetbirdOperationConflict
	}
	if r.ReleasedAt != nil {
		if err = netbirdOperationAudit(ctx, tx, r, actor, "read", "recorded"); err != nil {
			return nil, err
		}
		return d, tx.Commit()
	}
	v, _, err := s.currentTarget(ctx, tx, r)
	if err != nil {
		return nil, err
	}
	c := netbirdControlRequest(ctx, v, "receipt", uuid.NewString())
	if d.Kind == "withdraw" {
		c = netbirdRecoveryControl(ctx, v, "receipt", uuid.NewString())
	}
	p, err := s.request(ctx, c)
	if err != nil {
		return nil, err
	}
	return s.finish(ctx, tx, v, d, actor, c, p)
}

package inventory

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/open-uem/nats/netbirdapi"
	"github.com/open-uem/openuem-console/internal/security/access"
)

// An attempt permits one DELETE, including when that request was lost.
// It never establishes removal. Earlier attempts cannot be overwritten or reset.
type NetbirdPeerRemovalAttempt struct {
	ID, Actor, Revision string
	Sequence            int64
	CreatedAt           time.Time
}
type NetbirdPeerAbsence struct {
	Actor     string
	CreatedAt time.Time
}
type NetbirdPeerRemovalReview struct {
	Registration                   *NetbirdRegistration
	Target                         ManualTarget
	Revision, ManagementURL, State string
	Peer                           *netbirdapi.ManagedPeerMetadata
	CanRemove                      bool
	snapshot                       registrationSnapshot
	identityExpiry                 time.Time
}

func (v NetbirdPeerRemovalReview) String() string {
	return "NetBird peer removal review (credentials redacted)"
}
func (v NetbirdPeerRemovalReview) GoString() string { return v.String() }

func readNetbirdPeerRemoval(ctx context.Context, tx *sql.Tx, r *NetbirdRegistration) error {
	a := &NetbirdPeerRemovalAttempt{}
	err := tx.QueryRowContext(ctx, `SELECT id,actor,revision,sequence,created_at FROM uem_netbird_peer_removals WHERE request_id=$1 ORDER BY sequence DESC LIMIT 1`, r.ID).Scan(&a.ID, &a.Actor, &a.Revision, &a.Sequence, &a.CreatedAt)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	r.LastPeerRemoval = nil
	if err == nil {
		r.LastPeerRemoval = a
	}
	b := &NetbirdPeerAbsence{}
	err = tx.QueryRowContext(ctx, `SELECT actor,created_at FROM uem_netbird_peer_absence WHERE request_id=$1`, r.ID).Scan(&b.Actor, &b.CreatedAt)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	r.PeerAbsence = nil
	if err == nil {
		r.PeerAbsence = b
	}
	return nil
}

func (s *NetbirdRegistrationStore) peerRemovalReview(ctx context.Context, tx *sql.Tx, r *NetbirdRegistration) (*NetbirdPeerRemovalReview, error) {
	v := &NetbirdPeerRemovalReview{Registration: r, Target: ManualTarget{ID: r.DeviceID, Scope: r.Scope}, State: "unassociated"}
	if r.PeerBinding == nil {
		return v, nil
	}
	b := r.PeerBinding
	v.ManagementURL = b.ManagementURL
	if r.PeerAbsence != nil {
		v.State = "retained"
		return v, nil
	}
	op := &NetbirdOperation{ID: r.ID, DeviceID: r.DeviceID, Scope: r.Scope, Individual: r.Individual, Revision: r.Revision, Operation: "register"}
	current, generation, err := s.operations.resolutionTarget(ctx, tx, op)
	if err != nil {
		return nil, err
	}
	v.Target = current.Target
	v.identityExpiry = current.identityExpiry
	if r.Individual {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, v.identityExpiry)
		defer cancel()
	}
	v.State = "unavailable"
	v.snapshot, err = s.snapshot(r)
	if err == nil && v.snapshot.Base == b.ManagementURL {
		call, cancel := context.WithTimeout(ctx, 5*time.Second)
		var absent bool
		v.Peer, absent, err = netbirdapi.ObserveManagedPeer(call, s.transport, v.snapshot.Base, v.snapshot.Token, b.Peer.ID)
		cancel()
		switch {
		case err != nil:
		case absent:
			v.State = "absent"
		case v.Peer == nil || v.Peer.ID != b.Peer.ID || !v.Peer.CreatedAt.Equal(b.Peer.CreatedAt) || v.Peer.UserID != b.Peer.UserID || v.Peer.Ephemeral != b.Peer.Ephemeral:
			v.State = "changed"
		default:
			v.State = "present"
			v.CanRemove = true
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if r.Individual && !time.Now().Before(current.identityExpiry) {
		return nil, ErrNetbirdOperationChanged
	}
	data, _ := json.Marshal([]any{r.ID, r.Revision, r.CommandHash, b, generation, r.LastPeerRemoval, r.PeerAbsence, v.ManagementURL, v.State, v.Peer, v.CanRemove})
	digest := sha256.Sum256(data)
	v.Revision = hex.EncodeToString(digest[:])
	return v, nil
}

// ReviewPeerRemoval makes an exact-ID read under current scope and identity.
// It uses the retained association, never an address/name lookup or an agent RPC.
func (s *NetbirdRegistrationStore) ReviewPeerRemoval(parent context.Context, actor string, scope access.Scope, device, request string) (*NetbirdPeerRemovalReview, error) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, r, err := s.beginPeerBinding(ctx, actor, scope, device, request)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	v, err := s.peerRemovalReview(ctx, tx, r)
	if err != nil {
		return nil, err
	}
	if err = registrationAudit(ctx, tx, r, actor, "review", "peer-removal"); err != nil {
		return nil, err
	}
	return v, tx.Commit()
}

func (s *NetbirdRegistrationStore) recordPeerRemoval(ctx context.Context, r *NetbirdRegistration, actor, id, revision string) error {
	tx, err := s.operations.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	sequence := int64(1)
	if r.LastPeerRemoval != nil {
		sequence = r.LastPeerRemoval.Sequence + 1
	}
	b := r.PeerBinding
	_, err = tx.ExecContext(ctx, `INSERT INTO uem_netbird_peer_removals(id,request_id,binding_id,binding_revision,peer_id,actor,revision,sequence) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, id, r.ID, b.ID, b.Revision, b.Peer.ID, actor, revision, sequence)
	if err != nil {
		var state interface{ SQLState() string }
		if errors.As(err, &state) && state.SQLState() == "23505" {
			return ErrNetbirdOperationConflict
		}
		return err
	}
	if err = registrationAudit(ctx, tx, r, actor, "attempt", "peer-removal/"+id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *NetbirdRegistrationStore) retainPeerAbsence(ctx context.Context, r *NetbirdRegistration, actor string) error {
	tx, err := s.operations.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	b := r.PeerBinding
	_, err = tx.ExecContext(ctx, `INSERT INTO uem_netbird_peer_absence(request_id,binding_id,peer_id,actor) VALUES($1,$2,$3,$4)`, r.ID, b.ID, b.Peer.ID, actor)
	if err != nil {
		return err
	}
	if err = registrationAudit(ctx, tx, r, actor, "attempt", "peer-absence"); err != nil {
		return err
	}
	return tx.Commit()
}

// RemovePeer retains a separate intent/attempt with audit before one fixed-ID
// DELETE. Replayed forms return stored evidence without any external call. A new
// attempt needs a fresh review and form UUID, even if a prior request was lost.
func (s *NetbirdRegistrationStore) RemovePeer(parent context.Context, actor string, scope access.Scope, device, request, id, revision string) (*NetbirdRegistration, error) {
	if !canonicalRequestID(id) || !validManualRevision(revision) {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	tx, r, err := s.beginPeerBinding(ctx, actor, scope, device, request)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var storedRequest, storedActor, storedRevision string
	err = tx.QueryRowContext(ctx, `SELECT request_id,actor,revision FROM uem_netbird_peer_removals WHERE id=$1`, id).Scan(&storedRequest, &storedActor, &storedRevision)
	if err == nil {
		if storedRequest != r.ID || storedActor != actor || storedRevision != revision {
			return nil, ErrNetbirdOperationConflict
		}
		if err = registrationAudit(ctx, tx, r, actor, "read", "peer-removal"); err != nil {
			return nil, err
		}
		return r, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	v, err := s.peerRemovalReview(ctx, tx, r)
	if err != nil {
		return nil, err
	}
	if !v.CanRemove || v.Revision != revision {
		return nil, ErrNetbirdOperationChanged
	}
	if r.Individual {
		var cancelIdentity context.CancelFunc
		ctx, cancelIdentity = context.WithDeadline(ctx, v.identityExpiry)
		defer cancelIdentity()
	}
	if err = s.recordPeerRemoval(ctx, r, actor, id, revision); err != nil {
		return nil, err
	}
	call, cancelDelete := context.WithTimeout(ctx, 5*time.Second)
	_ = netbirdapi.DeletePeer(call, s.transport, v.snapshot.Base, v.snapshot.Token, r.PeerBinding.Peer.ID)
	cancelDelete()
	// Neither success nor failure of DELETE establishes absence. The next read
	// is a separate exact-ID request, including after a lost mutation response.
	call, cancelRead := context.WithTimeout(ctx, 5*time.Second)
	_, absent, observeErr := netbirdapi.ObserveManagedPeer(call, s.transport, v.snapshot.Base, v.snapshot.Token, r.PeerBinding.Peer.ID)
	cancelRead()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if observeErr == nil && absent {
		if err = s.retainPeerAbsence(ctx, r, actor); err != nil {
			return nil, err
		}
	}
	if err = readNetbirdPeerRemoval(ctx, tx, r); err != nil {
		return nil, err
	}
	if err = registrationAudit(ctx, tx, r, actor, "read", "peer-removal"); err != nil {
		return nil, err
	}
	return r, tx.Commit()
}

// ReconcilePeerRemoval is read-only at the provider and may retain positive
// absence after a lost reply or external removal. It never repeats DELETE.
func (s *NetbirdRegistrationStore) ReconcilePeerRemoval(parent context.Context, actor string, scope access.Scope, device, request string) (*NetbirdRegistration, error) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	tx, r, err := s.beginPeerBinding(ctx, actor, scope, device, request)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	v, err := s.peerRemovalReview(ctx, tx, r)
	if err != nil {
		return nil, err
	}
	if v.State == "absent" && r.PeerAbsence == nil {
		if err = s.retainPeerAbsence(ctx, r, actor); err != nil {
			return nil, err
		}
		if err = readNetbirdPeerRemoval(ctx, tx, r); err != nil {
			return nil, err
		}
	}
	if err = registrationAudit(ctx, tx, r, actor, "read", "peer-removal-check"); err != nil {
		return nil, err
	}
	return r, tx.Commit()
}

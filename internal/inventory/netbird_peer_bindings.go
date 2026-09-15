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

type NetbirdPeerBinding struct {
	ID, Actor, Revision, ManagementURL string
	Event                              netbirdapi.ManagedPeerEvent
	Peer                               netbirdapi.ManagedPeerMetadata
	CreatedAt                          time.Time
}

type NetbirdPeerReview struct {
	Registration                   *NetbirdRegistration
	Target                         ManualTarget
	Revision, ManagementURL, State string
	Event                          *netbirdapi.ManagedPeerEvent
	Peer                           *netbirdapi.ManagedPeerMetadata
	CanBind                        bool
}

func readNetbirdPeerBinding(ctx context.Context, tx *sql.Tx, request string) (*NetbirdPeerBinding, error) {
	b := &NetbirdPeerBinding{}
	var event, peer []byte
	err := tx.QueryRowContext(ctx, `SELECT id,actor,revision,provider_url,event,peer,created_at FROM uem_netbird_peer_bindings WHERE request_id=$1`, request).Scan(&b.ID, &b.Actor, &b.Revision, &b.ManagementURL, &event, &peer, &b.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if json.Unmarshal(event, &b.Event) != nil || json.Unmarshal(peer, &b.Peer) != nil {
		return nil, ErrNetbirdOperationInvalid
	}
	return b, nil
}

func (s *NetbirdRegistrationStore) beginPeerBinding(ctx context.Context, actor string, scope access.Scope, device, request string) (*sql.Tx, *NetbirdRegistration, error) {
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
	if err == nil && r.Status != "completed" && r.Status != "unconfirmed" {
		err = ErrNetbirdOperationConflict
	}
	if err != nil {
		tx.Rollback()
		return nil, nil, err
	}
	return tx, r, nil
}

func (s *NetbirdRegistrationStore) peerBindingReview(ctx context.Context, tx *sql.Tx, r *NetbirdRegistration) (*NetbirdPeerReview, error) {
	v := &NetbirdPeerReview{Registration: r, Target: ManualTarget{ID: r.DeviceID, Scope: r.Scope}}
	if r.PeerBinding != nil {
		v.State = "retained"
		v.ManagementURL = r.PeerBinding.ManagementURL
		v.Event = &r.PeerBinding.Event
		v.Peer = &r.PeerBinding.Peer
		return v, nil
	}
	if r.Key == nil {
		v.State = "key-unknown"
		return v, nil
	}
	if !slices.Contains(r.Attempts, "deliver") {
		v.State = "not-delivered"
		return v, nil
	}
	if !r.KeyAbsent {
		v.State = "cleanup-required"
		return v, nil
	}
	op := &NetbirdOperation{ID: r.ID, DeviceID: r.DeviceID, Scope: r.Scope, Individual: r.Individual, Revision: r.Revision, Operation: "register"}
	current, generation, err := s.operations.resolutionTarget(ctx, tx, op)
	if err != nil {
		return nil, err
	}
	v.Target = current.Target
	v.State = "unavailable"
	snapshot, err := s.snapshot(r)
	if err == nil {
		v.ManagementURL = snapshot.Base
		start, end := r.RequestedAt.Add(-5*time.Minute), r.Key.ExpiresAt.Add(5*time.Minute)
		if limit := r.Key.ExpiresAt.Add(-netbirdapi.ManagedKeyLifetime - 5*time.Minute); start.Before(limit) {
			start = limit
		}
		call, cancel := context.WithTimeout(ctx, 5*time.Second)
		v.Event, err = netbirdapi.ManagedKeyPeer(call, s.transport, snapshot.Base, snapshot.Token, r.Key.ID, start, end)
		cancel()
		switch {
		case errors.Is(err, netbirdapi.ErrPeerEvidenceConflict):
			v.State = "conflict"
		case err != nil:
		case v.Event == nil:
			v.State = "missing"
		default:
			call, cancel = context.WithTimeout(ctx, 5*time.Second)
			var absent bool
			v.Peer, absent, err = netbirdapi.ObserveManagedPeer(call, s.transport, snapshot.Base, snapshot.Token, v.Event.PeerID)
			cancel()
			switch {
			case err != nil:
			case absent:
				v.State = "absent"
			case v.Peer == nil || v.Peer.ID != v.Event.PeerID || v.Peer.UserID != "" || v.Peer.Ephemeral || v.Peer.CreatedAt.Before(start) || v.Peer.CreatedAt.After(r.Key.ExpiresAt) || v.Peer.CreatedAt.After(v.Event.Timestamp) || v.Event.Timestamp.After(time.Now().Add(5*time.Minute)):
				v.State = "conflict"
			default:
				v.State = "matched"
				v.CanBind = true
			}
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if r.Individual && !time.Now().Before(current.identityExpiry) {
		return nil, ErrNetbirdOperationChanged
	}
	data, _ := json.Marshal([]any{r.ID, r.Revision, r.CommandHash, r.Key, r.KeyAbsent, generation, v.ManagementURL, v.State, v.Event, v.Peer, v.CanBind})
	digest := sha256.Sum256(data)
	v.Revision = hex.EncodeToString(digest[:])
	return v, nil
}

// ReviewPeerBinding reads positive provider evidence under current authority.
// A missing audit event cannot establish absence or local non-execution.
func (s *NetbirdRegistrationStore) ReviewPeerBinding(parent context.Context, actor string, scope access.Scope, device, request string) (*NetbirdPeerReview, error) {
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	tx, r, err := s.beginPeerBinding(ctx, actor, scope, device, request)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	v, err := s.peerBindingReview(ctx, tx, r)
	if err != nil {
		return nil, err
	}
	if err = registrationAudit(ctx, tx, r, actor, "review", "peer-association"); err != nil {
		return nil, err
	}
	return v, tx.Commit()
}

// BindPeer retains a freshly reviewed provider association and audit atomically.
// No provider mutation or agent RPC occurs. The original outcome is unchanged.
func (s *NetbirdRegistrationStore) BindPeer(parent context.Context, actor string, scope access.Scope, device, request, id, revision string) (*NetbirdPeerBinding, error) {
	if !canonicalRequestID(id) || !validManualRevision(revision) {
		return nil, ErrNetbirdOperationInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	tx, r, err := s.beginPeerBinding(ctx, actor, scope, device, request)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if b := r.PeerBinding; b != nil {
		if b.ID != id || b.Actor != actor || b.Revision != revision {
			return nil, ErrNetbirdOperationConflict
		}
		if err = registrationAudit(ctx, tx, r, actor, "read", "peer-association"); err != nil {
			return nil, err
		}
		return b, tx.Commit()
	}
	v, err := s.peerBindingReview(ctx, tx, r)
	if err != nil {
		return nil, err
	}
	if !v.CanBind || v.Revision != revision {
		return nil, ErrNetbirdOperationChanged
	}
	event, _ := json.Marshal(v.Event)
	peer, _ := json.Marshal(v.Peer)
	_, err = tx.ExecContext(ctx, `INSERT INTO uem_netbird_peer_bindings(request_id,id,actor,revision,provider_url,event,peer) VALUES($1,$2,$3,$4,$5,$6,$7)`, r.ID, id, actor, revision, v.ManagementURL, string(event), string(peer))
	if err != nil {
		var state interface{ SQLState() string }
		if errors.As(err, &state) && state.SQLState() == "23505" {
			return nil, ErrNetbirdOperationConflict
		}
		return nil, err
	}
	if err = registrationAudit(ctx, tx, r, actor, "request", "peer-association/"+id); err != nil {
		return nil, err
	}
	b, err := readNetbirdPeerBinding(ctx, tx, r.ID)
	if err != nil {
		return nil, err
	}
	return b, tx.Commit()
}

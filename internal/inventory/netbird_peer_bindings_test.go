package inventory_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func registrationPeerEvidence(p *ownedRegistrationProvider, r *inventory.NetbirdRegistration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	at := time.Now().UTC()
	p.events = []map[string]any{{"id": "owned-event", "activity_code": "peer.setupkey.add", "initiator_id": r.Key.ID, "target_id": "owned-peer", "timestamp": at, "initiator_email": "private@example.test", "meta": map[string]string{"setup_key_name": r.Key.Name}}}
	p.peer = map[string]any{"id": "owned-peer", "name": "Owned <provider peer>", "created_at": at.Add(-time.Millisecond), "user_id": "", "ephemeral": false}
}

func peerBindingFixture(t *testing.T, uncertain bool) (*refreshFixture, *ownedRegistrationProvider, *inventory.NetbirdRegistrationStore, *inventory.NetbirdRegistration) {
	t.Helper()
	f, id := netbirdFixture(t)
	p := newRegistrationProvider(t, f, id)
	var execute inventory.NetbirdOperationExecutor
	if uncertain {
		execute = func(context.Context, inventory.NetbirdOperationCommand) (*inventory.NetbirdOperationResult, error) {
			return nil, errors.New("owned lost registration reply")
		}
	}
	s := registrationStore(t, f, p, nil, execute)
	r := registrationRequest(t, f, s)
	_, err := s.DispatchOne(t.Context())
	require.NoError(t, err)
	r = registrationRead(t, f, s, r.ID)
	require.True(t, r.KeyAbsent)
	registrationPeerEvidence(p, r)
	return f, p, s, r
}

func TestNetbirdPeerBindingRetainsExactProviderEvidence(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		t.Run(map[bool]string{false: "completed", true: "unconfirmed"}[uncertain], func(t *testing.T) {
			f, p, s, r := peerBindingFixture(t, uncertain)
			v, err := s.ReviewPeerBinding(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
			require.NoError(t, err)
			require.True(t, v.CanBind)
			require.Equal(t, "matched", v.State)
			require.Equal(t, r.Key.ID, v.Event.KeyID)
			require.Equal(t, "owned-peer", v.Peer.ID)
			id := uuid.NewString()
			b, err := s.BindPeer(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, id, v.Revision)
			require.NoError(t, err)
			require.Equal(t, id, b.ID)
			require.Equal(t, p.server.URL, b.ManagementURL)
			retained := registrationRead(t, f, s, r.ID)
			require.Equal(t, r.Status, retained.Status)
			require.Nil(t, retained.ReleasedAt)
			require.Equal(t, b, retained.PeerBinding)
			p.mu.Lock()
			reads := p.eventReads + p.peerReads
			require.Equal(t, 1, p.creates)
			require.Equal(t, 1, p.deletes)
			p.mu.Unlock()
			again, err := s.BindPeer(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, id, v.Revision)
			require.NoError(t, err)
			require.Equal(t, b, again)
			stored, err := s.ReviewPeerBinding(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
			require.NoError(t, err)
			require.Equal(t, "retained", stored.State)
			require.False(t, stored.CanBind)
			p.mu.Lock()
			require.Equal(t, reads, p.eventReads+p.peerReads)
			p.mu.Unlock()
			_, err = s.BindPeer(t.Context(), "admin", r.Scope, r.DeviceID, r.ID, id, v.Revision)
			require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
			data, err := json.Marshal(retained)
			require.NoError(t, err)
			for _, secret := range []string{"owned-private-setup-key", "private@example.test", "access_token"} {
				require.NotContains(t, string(data), secret)
			}
			if uncertain {
				newReview, err := s.Review(t.Context(), "tag-admin", r.Scope, r.DeviceID, nil, false)
				require.NoError(t, err)
				_, err = s.Request(t.Context(), "tag-admin", r.Scope, r.DeviceID, uuid.NewString(), newReview.Revision, nil, false)
				require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
			}
			require.NoError(t, f.client.Agent.DeleteOneID(f.id).Exec(t.Context()))
			require.Equal(t, b, registrationRead(t, f, s, r.ID).PeerBinding)
			history, err := s.ReviewPeerBinding(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
			require.NoError(t, err)
			require.Equal(t, "retained", history.State)
		})
	}
}

func TestNetbirdPeerBindingRejectsMissingAndChangedEvidence(t *testing.T) {
	for _, change := range []string{"missing", "wrong-key", "wrong-activity", "multiple", "old", "future", "peer-recreated", "peer-old", "peer-user", "peer-ephemeral", "absent", "unavailable", "peer-unavailable", "renamed"} {
		t.Run(change, func(t *testing.T) {
			_, p, s, r := peerBindingFixture(t, true)
			v, err := s.ReviewPeerBinding(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
			require.NoError(t, err)
			require.True(t, v.CanBind)
			p.mu.Lock()
			switch change {
			case "missing":
				p.events = []map[string]any{}
			case "wrong-key":
				p.events[0]["initiator_id"] = "other-key"
			case "wrong-activity":
				p.events[0]["activity_code"] = "peer.user.add"
			case "multiple":
				other := map[string]any{}
				for k, value := range p.events[0] {
					other[k] = value
				}
				other["id"] = "other-event"
				p.events = append(p.events, other)
			case "old":
				p.events[0]["timestamp"] = r.RequestedAt.Add(-time.Hour)
			case "future":
				p.events[0]["timestamp"] = time.Now().Add(time.Hour)
			case "peer-recreated":
				p.peer["created_at"] = time.Now().Add(time.Minute)
			case "peer-old":
				p.peer["created_at"] = r.RequestedAt.Add(-time.Hour)
			case "peer-user":
				p.peer["user_id"] = "other-user"
			case "peer-ephemeral":
				p.peer["ephemeral"] = true
			case "absent":
				p.peerStatus = 404
			case "unavailable":
				p.eventsStatus = 503
			case "peer-unavailable":
				p.peerStatus = 503
			case "renamed":
				p.peer["name"] = "Renamed peer"
			}
			p.mu.Unlock()
			_, err = s.BindPeer(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), v.Revision)
			require.ErrorIs(t, err, inventory.ErrNetbirdOperationChanged)
			fresh, err := s.ReviewPeerBinding(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
			require.NoError(t, err)
			require.Equal(t, change == "renamed", fresh.CanBind)
			if change == "renamed" {
				b, err := s.BindPeer(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), fresh.Revision)
				require.NoError(t, err)
				require.Equal(t, "owned-peer", b.Peer.ID)
			}
		})
	}
}

func TestNetbirdPeerBindingChecksAuthorityBeforeProviderAccess(t *testing.T) {
	for _, change := range []string{"moved", "removed", "disabled", "mode"} {
		t.Run(change, func(t *testing.T) {
			f, p, s, r := peerBindingFixture(t, true)
			v, err := s.ReviewPeerBinding(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
			require.NoError(t, err)
			for _, actor := range []string{"viewer", "operator", "missing"} {
				_, err = s.ReviewPeerBinding(t.Context(), actor, r.Scope, r.DeviceID, r.ID)
				require.ErrorIs(t, err, access.ErrDenied)
				_, err = s.BindPeer(t.Context(), actor, r.Scope, r.DeviceID, r.ID, uuid.NewString(), v.Revision)
				require.ErrorIs(t, err, access.ErrDenied)
			}
			p.mu.Lock()
			reads := p.eventReads + p.peerReads
			p.mu.Unlock()
			switch change {
			case "moved":
				err = f.client.Agent.UpdateOneID(f.id).RemoveSiteIDs(f.scope.SiteID).AddSiteIDs(f.otherSite).Exec(t.Context())
			case "removed":
				err = f.client.Agent.DeleteOneID(f.id).Exec(t.Context())
			case "disabled":
				_, err = f.db.ExecContext(t.Context(), `UPDATE agents SET agent_status='Disabled' WHERE oid=$1`, f.id)
			case "mode":
				s, err = inventory.NewNetbirdRegistrationStore(f.db, f.permissions, true, strings.Repeat("k", 32), p.server.Client().Transport, registrationControl, netbirdSuccess)
			}
			require.NoError(t, err)
			_, err = s.BindPeer(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), v.Revision)
			require.Error(t, err)
			p.mu.Lock()
			require.Equal(t, reads, p.eventReads+p.peerReads)
			p.mu.Unlock()
		})
	}
}

func TestNetbirdPeerBindingRequiresRetainedRegistrationStages(t *testing.T) {
	for _, state := range []string{"key-unknown", "not-delivered", "cleanup-required"} {
		t.Run(state, func(t *testing.T) {
			f, id := netbirdFixture(t)
			p := newRegistrationProvider(t, f, id)
			p.failCreate = state == "key-unknown"
			p.failRead = true
			s := registrationStore(t, f, p, nil, netbirdSuccess)
			r := registrationRequest(t, f, s)
			if state == "not-delivered" {
				_, err := f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_peer_no_delivery CHECK(resource_id NOT LIKE '%/register/deliver') NOT VALID`)
				require.NoError(t, err)
			}
			_, err := s.DispatchOne(t.Context())
			if state == "not-delivered" {
				require.Error(t, err)
				_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit DROP CONSTRAINT owned_peer_no_delivery`)
				require.NoError(t, err)
				_, err = s.DispatchOne(t.Context())
			}
			require.NoError(t, err)
			v, err := s.ReviewPeerBinding(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
			require.NoError(t, err)
			require.False(t, v.CanBind)
			require.Equal(t, state, v.State)
			p.mu.Lock()
			require.Zero(t, p.eventReads)
			require.Zero(t, p.peerReads)
			p.mu.Unlock()
		})
	}
}

func TestNetbirdPeerBindingAtomicAuditAndConcurrentConfirmation(t *testing.T) {
	for _, mode := range []string{"audit", "same-form", "different-forms"} {
		t.Run(mode, func(t *testing.T) {
			f, p, s, r := peerBindingFixture(t, true)
			v, err := s.ReviewPeerBinding(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
			require.NoError(t, err)
			ids := []string{uuid.NewString(), uuid.NewString()}
			if mode == "audit" {
				_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_peer_audit CHECK(resource_id NOT LIKE '%/peer-association/%') NOT VALID`)
				require.NoError(t, err)
				_, err = s.BindPeer(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, ids[0], v.Revision)
				require.Error(t, err)
				require.Nil(t, registrationRead(t, f, s, r.ID).PeerBinding)
				_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit DROP CONSTRAINT owned_peer_audit`)
				require.NoError(t, err)
				_, err = s.BindPeer(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, ids[0], v.Revision)
				require.NoError(t, err)
			} else {
				if mode == "same-form" {
					ids[1] = ids[0]
				}
				errs := make([]error, 2)
				var wg sync.WaitGroup
				for i := range ids {
					wg.Add(1)
					go func(i int) {
						defer wg.Done()
						_, errs[i] = s.BindPeer(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, ids[i], v.Revision)
					}(i)
				}
				wg.Wait()
				if mode == "same-form" {
					require.NoError(t, errs[0])
					require.NoError(t, errs[1])
				} else {
					require.NotEqual(t, errs[0] == nil, errs[1] == nil)
				}
			}
			var bindings, audits int
			require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT (SELECT count(*) FROM uem_netbird_peer_bindings WHERE request_id=$1),(SELECT count(*) FROM uem_netbird_operations_audit WHERE resource_id LIKE $2 AND action='inventory.netbird.request')`, r.ID, r.ID+"/device/"+r.DeviceID+"/register/peer-association/%").Scan(&bindings, &audits))
			require.Equal(t, 1, bindings)
			require.Equal(t, 1, audits)
			p.mu.Lock()
			require.Equal(t, 1, p.creates)
			require.Equal(t, 1, p.deletes)
			p.mu.Unlock()
		})
	}
}

func TestNetbirdPeerBindingDatabaseGuardsAndOriginalProvider(t *testing.T) {
	f, p, s, r := peerBindingFixture(t, false)
	v, err := s.ReviewPeerBinding(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
	require.NoError(t, err)
	for _, change := range []string{"valid", "request", "key", "peer", "user", "time", "extra"} {
		event, peer := *v.Event, *v.Peer
		request := r.ID
		switch change {
		case "request":
			request = uuid.NewString()
		case "key":
			event.KeyID = "wrong-key"
		case "peer":
			peer.ID = "wrong-peer"
		case "user":
			peer.UserID = "wrong-user"
		case "time":
			peer.CreatedAt = event.Timestamp.Add(time.Second)
		}
		e, err := json.Marshal(event)
		require.NoError(t, err)
		p, err := json.Marshal(peer)
		require.NoError(t, err)
		if change == "extra" {
			p = []byte(strings.TrimSuffix(string(p), "}") + `,"Secret":"unexpected"}`)
		}
		tx, err := f.db.BeginTx(t.Context(), nil)
		require.NoError(t, err)
		_, err = tx.ExecContext(t.Context(), `INSERT INTO uem_netbird_peer_bindings(request_id,id,actor,revision,provider_url,event,peer) VALUES($1,$2,'tag-admin',$3,$4,$5,$6)`, request, uuid.NewString(), v.Revision, v.ManagementURL, string(e), string(p))
		if change == "valid" {
			require.NoError(t, err)
		} else {
			require.Error(t, err, change)
		}
		require.NoError(t, tx.Rollback())
	}
	_, err = f.db.ExecContext(t.Context(), `UPDATE netbird_settings SET management_url='https://changed.invalid',access_token='changed-token'`)
	require.NoError(t, err)
	b, err := s.BindPeer(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), v.Revision)
	require.NoError(t, err)
	require.Equal(t, p.server.URL, b.ManagementURL)
	p.mu.Lock()
	for _, token := range p.tokens {
		require.NotContains(t, token, "changed-token")
	}
	p.mu.Unlock()
	for _, query := range []string{`UPDATE uem_netbird_peer_bindings SET actor='changed'`, `DELETE FROM uem_netbird_peer_bindings`} {
		_, err = f.db.ExecContext(t.Context(), query)
		require.Error(t, err)
	}
	for _, trigger := range []string{"uem_netbird_peer_binding_valid", "uem_netbird_peer_binding_immutable"} {
		_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_peer_bindings DISABLE TRIGGER `+trigger)
		require.NoError(t, err)
		require.Error(t, inventory.Migrate(t.Context(), f.db))
		_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_peer_bindings ENABLE TRIGGER `+trigger)
		require.NoError(t, err)
	}
}

func exerciseNetbirdPeerBindingIdentity(t *testing.T, f *refreshFixture, p *ownedRegistrationProvider, s *inventory.NetbirdRegistrationStore, r *inventory.NetbirdRegistration, change string) {
	t.Helper()
	r = registrationRead(t, f, s, r.ID)
	registrationPeerEvidence(p, r)
	v, err := s.ReviewPeerBinding(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
	require.NoError(t, err)
	require.True(t, v.CanBind)
	switch change {
	case "renewed":
		_, err = f.db.ExecContext(t.Context(), `UPDATE uem_agent_identities SET certificate_hash=repeat('a',64) WHERE id=$1`, f.id)
	case "revoked":
		_, err = f.db.ExecContext(t.Context(), `UPDATE uem_agent_identities SET revoked_at=clock_timestamp() WHERE id=$1`, f.id)
	case "expired":
		_, err = f.db.ExecContext(t.Context(), `UPDATE uem_agent_identities SET certificate_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, f.id)
	case "consumer":
		_, err = f.db.ExecContext(t.Context(), `UPDATE uem_agent_command_consumers SET desired_active=false WHERE device_id=$1`, f.id)
	case "moved":
		err = f.client.Agent.UpdateOneID(f.id).RemoveSiteIDs(f.scope.SiteID).AddSiteIDs(f.otherSite).Exec(t.Context())
	}
	require.NoError(t, err)
	p.mu.Lock()
	reads := p.eventReads + p.peerReads
	p.mu.Unlock()
	_, err = s.BindPeer(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), v.Revision)
	require.Error(t, err)
	if change == "renewed" {
		fresh, err := s.ReviewPeerBinding(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
		require.NoError(t, err)
		require.NotEqual(t, v.Revision, fresh.Revision)
		b, err := s.BindPeer(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), fresh.Revision)
		require.NoError(t, err)
		require.Equal(t, "owned-peer", b.Peer.ID)
	} else {
		p.mu.Lock()
		require.Equal(t, reads, p.eventReads+p.peerReads)
		p.mu.Unlock()
	}
}

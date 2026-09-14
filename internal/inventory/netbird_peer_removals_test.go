package inventory_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func peerRemovalFixture(t *testing.T, uncertain bool) (*refreshFixture, *ownedRegistrationProvider, *inventory.NetbirdRegistrationStore, *inventory.NetbirdRegistration) {
	t.Helper()
	f, p, s, r := peerBindingFixture(t, uncertain)
	bindRegistrationPeer(t, s, r)
	return f, p, s, registrationRead(t, f, s, r.ID)
}
func bindRegistrationPeer(t *testing.T, s *inventory.NetbirdRegistrationStore, r *inventory.NetbirdRegistration) {
	t.Helper()
	v, err := s.ReviewPeerBinding(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
	require.NoError(t, err)
	require.True(t, v.CanBind)
	_, err = s.BindPeer(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), v.Revision)
	require.NoError(t, err)
}

func TestNetbirdPeerRemovalRetainsAttemptBeforeMutationAndRecoversAbsence(t *testing.T) {
	for _, loss := range []string{"none", "reply", "request", "read", "absence-audit", "final-audit"} {
		t.Run(loss, func(t *testing.T) {
			f, p, s, r := peerRemovalFixture(t, true)
			v, err := s.ReviewPeerRemoval(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
			require.NoError(t, err)
			require.True(t, v.CanRemove)
			require.Equal(t, "present", v.State)
			id := uuid.NewString()
			p.mu.Lock()
			p.retainPeerDelete = loss == "request"
			p.failPeerDelete = loss == "reply"
			p.onPeerDelete = func() {
				var attempts, audits int
				require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT (SELECT count(*) FROM uem_netbird_peer_removals WHERE request_id=$1 AND id=$2 AND binding_id=$3 AND binding_revision=$4 AND peer_id='owned-peer' AND actor='tag-admin'),(SELECT count(*) FROM uem_netbird_operations_audit WHERE resource_id=$5 AND action='inventory.netbird.attempt')`, r.ID, id, r.PeerBinding.ID, r.PeerBinding.Revision, r.ID+"/device/"+r.DeviceID+"/register/peer-removal/"+id).Scan(&attempts, &audits))
				require.Equal(t, 1, attempts)
				require.Equal(t, 1, audits)
				if loss == "read" {
					p.peerStatus = 500
				}
			}
			p.mu.Unlock()
			if strings.HasSuffix(loss, "audit") {
				stage := "peer-absence"
				if loss == "final-audit" {
					stage = "peer-removal"
				}
				_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_peer_remove_audit CHECK(resource_id NOT LIKE '%/register/`+stage+`') NOT VALID`)
				require.NoError(t, err)
			}
			result, err := s.RemovePeer(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, id, v.Revision)
			if strings.HasSuffix(loss, "audit") {
				require.Error(t, err)
				_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit DROP CONSTRAINT owned_peer_remove_audit`)
				require.NoError(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, loss == "none" || loss == "reply", result.PeerAbsence != nil)
			}
			retained := registrationRead(t, f, s, r.ID)
			require.Equal(t, id, retained.LastPeerRemoval.ID)
			require.Equal(t, int64(1), retained.LastPeerRemoval.Sequence)
			require.Equal(t, loss == "none" || loss == "reply" || loss == "final-audit", retained.PeerAbsence != nil)
			require.Equal(t, r.PeerBinding, retained.PeerBinding)
			require.Equal(t, "unconfirmed", retained.Status)
			require.Nil(t, retained.ReleasedAt)
			p.mu.Lock()
			reads := p.peerReads
			p.mu.Unlock()
			// A newly constructed store models restart without automatic resending.
			s = registrationStore(t, f, p, nil, nil)
			replay, err := s.RemovePeer(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, id, v.Revision)
			require.NoError(t, err)
			require.Equal(t, id, replay.LastPeerRemoval.ID)
			p.mu.Lock()
			require.Equal(t, reads, p.peerReads)
			require.Equal(t, 1, p.peerDeletes)
			require.Equal(t, 1, p.creates)
			require.Equal(t, 1, p.deletes)
			p.peerStatus = 0
			p.mu.Unlock()
			checked, err := s.ReconcilePeerRemoval(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
			require.NoError(t, err)
			require.Equal(t, loss != "request", checked.PeerAbsence != nil)
			require.Nil(t, checked.ReleasedAt)
			fresh, err := s.Review(t.Context(), "tag-admin", r.Scope, r.DeviceID, nil, false)
			require.NoError(t, err)
			_, err = s.Request(t.Context(), "tag-admin", r.Scope, r.DeviceID, uuid.NewString(), fresh.Revision, nil, false)
			require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
			require.NoError(t, f.client.Agent.DeleteOneID(f.id).Exec(t.Context()))
			history := registrationRead(t, f, s, r.ID)
			require.Equal(t, checked.PeerAbsence, history.PeerAbsence)
			require.Equal(t, id, history.LastPeerRemoval.ID)
			if history.PeerAbsence != nil {
				stored, err := s.ReviewPeerRemoval(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
				require.NoError(t, err)
				require.Equal(t, "retained", stored.State)
				require.False(t, stored.CanRemove)
			}
		})
	}
}

func TestNetbirdPeerRemovalRequiresCurrentExactPeerAndAuthority(t *testing.T) {
	for _, change := range []string{"created", "user", "ephemeral", "name", "absent", "unavailable", "moved", "removed", "disabled", "mode", "attempt-audit"} {
		t.Run(change, func(t *testing.T) {
			f, p, s, r := peerRemovalFixture(t, false)
			v, err := s.ReviewPeerRemoval(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
			require.NoError(t, err)
			p.mu.Lock()
			reads := p.peerReads
			p.mu.Unlock()
			for _, actor := range []string{"viewer", "operator", "missing"} {
				_, err = s.ReviewPeerRemoval(t.Context(), actor, r.Scope, r.DeviceID, r.ID)
				require.ErrorIs(t, err, access.ErrDenied)
				_, err = s.RemovePeer(t.Context(), actor, r.Scope, r.DeviceID, r.ID, uuid.NewString(), v.Revision)
				require.ErrorIs(t, err, access.ErrDenied)
				_, err = s.ReconcilePeerRemoval(t.Context(), actor, r.Scope, r.DeviceID, r.ID)
				require.ErrorIs(t, err, access.ErrDenied)
			}
			p.mu.Lock()
			require.Equal(t, reads, p.peerReads)
			switch change {
			case "created":
				p.peer["created_at"] = time.Now().Add(time.Second)
			case "user":
				p.peer["user_id"] = "other-user"
			case "ephemeral":
				p.peer["ephemeral"] = true
			case "name":
				p.peer["name"] = "A new display name"
			case "absent":
				p.peerAbsent = true
			case "unavailable":
				p.peerStatus = 500
			}
			p.mu.Unlock()
			err = nil
			switch change {
			case "moved":
				err = f.client.Agent.UpdateOneID(f.id).RemoveSiteIDs(f.scope.SiteID).AddSiteIDs(f.otherSite).Exec(t.Context())
			case "removed":
				err = f.client.Agent.DeleteOneID(f.id).Exec(t.Context())
			case "disabled":
				_, err = f.db.ExecContext(t.Context(), `UPDATE agents SET agent_status='Disabled' WHERE oid=$1`, f.id)
			case "mode":
				s, err = inventory.NewNetbirdRegistrationStore(f.db, f.permissions, true, strings.Repeat("k", 32), p.server.Client().Transport, registrationControl, netbirdSuccess)
			case "attempt-audit":
				_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_peer_attempt CHECK(resource_id NOT LIKE '%/peer-removal/%') NOT VALID`)
			}
			require.NoError(t, err)
			_, err = s.RemovePeer(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), v.Revision)
			require.Error(t, err)
			p.mu.Lock()
			require.Zero(t, p.peerDeletes)
			if change == "moved" || change == "removed" || change == "disabled" || change == "mode" {
				require.Equal(t, reads, p.peerReads)
			}
			p.mu.Unlock()
			require.Nil(t, registrationRead(t, f, s, r.ID).LastPeerRemoval)
			if change == "name" {
				fresh, err := s.ReviewPeerRemoval(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
				require.NoError(t, err)
				require.True(t, fresh.CanRemove)
				require.NotEqual(t, v.Revision, fresh.Revision)
				result, err := s.RemovePeer(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), fresh.Revision)
				require.NoError(t, err)
				require.NotNil(t, result.PeerAbsence)
				require.Equal(t, "completed", result.Status)
			}
		})
	}
}

func TestNetbirdPeerRemovalConcurrentFormsAndExplicitRetry(t *testing.T) {
	for _, same := range []bool{true, false} {
		t.Run(map[bool]string{true: "same-form", false: "different-forms"}[same], func(t *testing.T) {
			f, p, s, r := peerRemovalFixture(t, true)
			p.mu.Lock()
			p.retainPeerDelete = true
			p.mu.Unlock()
			v, err := s.ReviewPeerRemoval(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
			require.NoError(t, err)
			ids := []string{uuid.NewString(), uuid.NewString()}
			if same {
				ids[1] = ids[0]
			}
			errs := make([]error, 2)
			var wg sync.WaitGroup
			for i := range ids {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					_, errs[i] = s.RemovePeer(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, ids[i], v.Revision)
				}(i)
			}
			wg.Wait()
			if same {
				require.NoError(t, errs[0])
				require.NoError(t, errs[1])
			} else {
				require.NotEqual(t, errs[0] == nil, errs[1] == nil)
			}
			p.mu.Lock()
			require.Equal(t, 1, p.peerDeletes)
			p.retainPeerDelete = false
			p.mu.Unlock()
			fresh, err := s.ReviewPeerRemoval(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
			require.NoError(t, err)
			require.True(t, fresh.CanRemove)
			require.NotEqual(t, v.Revision, fresh.Revision)
			id := uuid.NewString()
			result, err := s.RemovePeer(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, id, fresh.Revision)
			require.NoError(t, err)
			require.NotNil(t, result.PeerAbsence)
			require.Equal(t, int64(2), result.LastPeerRemoval.Sequence)
			_, err = s.RemovePeer(t.Context(), "admin", r.Scope, r.DeviceID, r.ID, id, fresh.Revision)
			require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
			var count int
			require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT count(*) FROM uem_netbird_peer_removals WHERE request_id=$1`, r.ID).Scan(&count))
			require.Equal(t, 2, count)
			data, err := json.Marshal(result)
			require.NoError(t, err)
			for _, secret := range []string{"owned-private-setup-key", "private@example.test", "changed-token"} {
				require.NotContains(t, string(data), secret)
			}
		})
	}
}

func TestNetbirdPeerRemovalOriginalProviderAndExternalAbsence(t *testing.T) {
	f, p, s, r := peerBindingFixture(t, false)
	v, err := s.ReviewPeerRemoval(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
	require.NoError(t, err)
	require.Equal(t, "unassociated", v.State)
	require.False(t, v.CanRemove)
	_, err = s.RemovePeer(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), strings.Repeat("a", 64))
	require.Error(t, err)
	p.mu.Lock()
	require.Zero(t, p.peerReads)
	require.Zero(t, p.peerDeletes)
	p.mu.Unlock()
	bindRegistrationPeer(t, s, r)
	_, err = f.db.ExecContext(t.Context(), `UPDATE netbird_settings SET management_url='https://changed.invalid',access_token='changed-token'`)
	require.NoError(t, err)
	p.mu.Lock()
	p.peerAbsent = true
	p.eventsStatus = 500
	p.mu.Unlock()
	v, err = s.ReviewPeerRemoval(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
	require.NoError(t, err)
	require.Equal(t, "absent", v.State)
	require.Equal(t, p.server.URL, v.ManagementURL)
	require.False(t, v.CanRemove)
	require.Nil(t, registrationRead(t, f, s, r.ID).PeerAbsence)
	checked, err := s.ReconcilePeerRemoval(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
	require.NoError(t, err)
	require.NotNil(t, checked.PeerAbsence)
	require.Nil(t, checked.LastPeerRemoval)
	p.mu.Lock()
	require.Zero(t, p.peerDeletes)
	require.Equal(t, 2, p.eventReads)
	reads := p.peerReads
	for _, token := range p.tokens {
		require.NotContains(t, token, "changed-token")
	}
	p.mu.Unlock()
	_, err = s.ReconcilePeerRemoval(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
	require.NoError(t, err)
	p.mu.Lock()
	require.Equal(t, reads, p.peerReads)
	p.mu.Unlock()
}

func TestNetbirdPeerRemovalDatabaseGuards(t *testing.T) {
	f, _, s, r := peerRemovalFixture(t, false)
	v, err := s.ReviewPeerRemoval(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
	require.NoError(t, err)
	for _, change := range []string{"valid", "request", "binding", "revision", "peer", "sequence"} {
		request, binding, bindingRevision, peer, sequence := r.ID, r.PeerBinding.ID, r.PeerBinding.Revision, r.PeerBinding.Peer.ID, 1
		switch change {
		case "request":
			request = uuid.NewString()
		case "binding":
			binding = uuid.NewString()
		case "revision":
			bindingRevision = strings.Repeat("f", 64)
		case "peer":
			peer = "wrong-peer"
		case "sequence":
			sequence = 2
		}
		tx, err := f.db.BeginTx(t.Context(), nil)
		require.NoError(t, err)
		_, err = tx.ExecContext(t.Context(), `INSERT INTO uem_netbird_peer_removals(id,request_id,binding_id,binding_revision,peer_id,actor,revision,sequence) VALUES($1,$2,$3,$4,$5,'tag-admin',$6,$7)`, uuid.NewString(), request, binding, bindingRevision, peer, v.Revision, sequence)
		if change == "valid" {
			require.NoError(t, err)
		} else {
			require.Error(t, err, change)
		}
		require.NoError(t, tx.Rollback())
	}
	_, err = f.db.ExecContext(t.Context(), `INSERT INTO uem_netbird_peer_absence(request_id,binding_id,peer_id,actor) VALUES($1,$2,'wrong-peer','tag-admin')`, r.ID, r.PeerBinding.ID)
	require.Error(t, err)
	_, err = s.RemovePeer(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), v.Revision)
	require.NoError(t, err)
	_, err = f.db.ExecContext(t.Context(), `INSERT INTO uem_netbird_peer_removals(id,request_id,binding_id,binding_revision,peer_id,actor,revision,sequence) VALUES($1,$2,$3,$4,$5,'tag-admin',$6,2)`, uuid.NewString(), r.ID, r.PeerBinding.ID, r.PeerBinding.Revision, r.PeerBinding.Peer.ID, v.Revision)
	require.Error(t, err)
	for _, table := range []string{"uem_netbird_peer_removals", "uem_netbird_peer_absence"} {
		for _, query := range []string{`UPDATE ` + table + ` SET actor='changed'`, `DELETE FROM ` + table} {
			_, err = f.db.ExecContext(t.Context(), query)
			require.Error(t, err)
		}
	}
	for table, triggers := range map[string][]string{"uem_netbird_peer_removals": {"uem_netbird_peer_removal_immutable", "uem_netbird_peer_removal_valid"}, "uem_netbird_peer_absence": {"uem_netbird_peer_absence_immutable", "uem_netbird_peer_absence_valid"}} {
		for _, trigger := range triggers {
			_, err = f.db.ExecContext(t.Context(), `ALTER TABLE `+table+` DISABLE TRIGGER `+trigger)
			require.NoError(t, err)
			require.Error(t, inventory.Migrate(t.Context(), f.db))
			_, err = f.db.ExecContext(t.Context(), `ALTER TABLE `+table+` ENABLE TRIGGER `+trigger)
			require.NoError(t, err)
		}
	}
}

type ownedPeerRemovalTransport func(*http.Request) (*http.Response, error)

func (f ownedPeerRemovalTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func exerciseNetbirdPeerRemovalIdentity(t *testing.T, f *refreshFixture, p *ownedRegistrationProvider, s *inventory.NetbirdRegistrationStore, r *inventory.NetbirdRegistration, change string) {
	t.Helper()
	r = registrationRead(t, f, s, r.ID)
	registrationPeerEvidence(p, r)
	bindRegistrationPeer(t, s, r)
	v, err := s.ReviewPeerRemoval(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
	require.NoError(t, err)
	require.True(t, v.CanRemove)
	if change == "deadline" {
		var expiry time.Time
		err = f.db.QueryRowContext(t.Context(), `UPDATE uem_agent_identities SET certificate_expires_at=clock_timestamp()+interval '3 seconds' WHERE id=$1 RETURNING certificate_expires_at`, f.id).Scan(&expiry)
		require.NoError(t, err)
		observed := false
		transport := ownedPeerRemovalTransport(func(req *http.Request) (*http.Response, error) {
			if req.Method == "DELETE" {
				deadline, ok := req.Context().Deadline()
				require.True(t, ok)
				require.False(t, deadline.After(expiry))
				observed = true
			}
			return p.server.Client().Transport.RoundTrip(req)
		})
		s, err = inventory.NewNetbirdRegistrationStore(f.db, f.permissions, true, strings.Repeat("k", 32), transport, registrationControl, netbirdSuccess)
		require.NoError(t, err)
		fresh, err := s.ReviewPeerRemoval(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
		require.NoError(t, err)
		result, err := s.RemovePeer(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), fresh.Revision)
		require.NoError(t, err)
		require.NotNil(t, result.PeerAbsence)
		require.True(t, observed)
		return
	}
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
	reads := p.peerReads
	p.mu.Unlock()
	_, err = s.RemovePeer(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), v.Revision)
	require.Error(t, err)
	p.mu.Lock()
	require.Zero(t, p.peerDeletes)
	p.mu.Unlock()
	if change == "renewed" {
		fresh, err := s.ReviewPeerRemoval(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
		require.NoError(t, err)
		require.NotEqual(t, v.Revision, fresh.Revision)
		result, err := s.RemovePeer(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), fresh.Revision)
		require.NoError(t, err)
		require.NotNil(t, result.PeerAbsence)
	} else {
		_, err = s.ReconcilePeerRemoval(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
		require.Error(t, err)
		p.mu.Lock()
		require.Equal(t, reads, p.peerReads)
		p.mu.Unlock()
	}
}

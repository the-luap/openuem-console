package inventory_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func cleanupRetryFixture(t *testing.T) (*refreshFixture, *ownedRegistrationProvider, *inventory.NetbirdRegistrationStore, *inventory.NetbirdRegistration) {
	t.Helper()
	f, id := netbirdFixture(t)
	p := newRegistrationProvider(t, f, id)
	p.retainDelete = true
	s := registrationStore(t, f, p, nil, func(context.Context, inventory.NetbirdOperationCommand) (*inventory.NetbirdOperationResult, error) {
		return nil, errors.New("owned registration reply lost")
	})
	r := registrationRequest(t, f, s)
	_, err := s.DispatchOne(t.Context())
	require.NoError(t, err)
	r = registrationRead(t, f, s, r.ID)
	require.Equal(t, "unconfirmed", r.Status)
	require.False(t, r.KeyAbsent)
	require.Contains(t, r.Attempts, "delete")
	return f, p, s, r
}

func TestNetbirdCleanupRetryRetainsAttemptBeforeMutationAndSurvivesLoss(t *testing.T) {
	for _, loss := range []string{"none", "reply", "request", "read", "absence-audit", "final-audit"} {
		t.Run(loss, func(t *testing.T) {
			f, p, s, r := cleanupRetryFixture(t)
			v, err := s.ReviewCleanup(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
			require.NoError(t, err)
			require.True(t, v.CanRetry)
			require.Equal(t, p.server.URL, v.ManagementURL)
			id := uuid.NewString()
			p.mu.Lock()
			p.retainDelete = loss == "request"
			p.failDelete = loss == "reply"
			p.onDelete = func() {
				var attempts, audits int
				require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT (SELECT count(*) FROM uem_netbird_cleanup_retries WHERE request_id=$1 AND id=$2 AND actor='tag-admin' AND key_id='12345' AND digest=(SELECT digest FROM uem_netbird_registration_attempts WHERE request_id=$1 AND stage='delete')),(SELECT count(*) FROM uem_netbird_operations_audit WHERE resource_id=$3 AND action='inventory.netbird.attempt')`, r.ID, id, r.ID+"/device/"+r.DeviceID+"/register/cleanup-retry/"+id).Scan(&attempts, &audits))
				require.Equal(t, 1, attempts)
				require.Equal(t, 1, audits)
				p.failRead = loss == "read"
			}
			p.mu.Unlock()
			if loss == "absence-audit" || loss == "final-audit" {
				stage := "evidence-absent"
				if loss == "final-audit" {
					stage = "cleanup-retry"
				}
				_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_cleanup_failure CHECK(resource_id NOT LIKE '%/register/`+stage+`') NOT VALID`)
				require.NoError(t, err)
			}
			result, err := s.RetryCleanup(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, id, v.Revision)
			if strings.HasSuffix(loss, "audit") {
				require.Error(t, err)
				_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit DROP CONSTRAINT owned_cleanup_failure`)
				require.NoError(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, loss == "none" || loss == "reply", result.KeyAbsent)
			}
			retained := registrationRead(t, f, s, r.ID)
			require.Equal(t, id, retained.LastCleanupRetry.ID)
			require.Equal(t, int64(1), retained.LastCleanupRetry.Sequence)
			require.Equal(t, "unconfirmed", retained.Status)
			require.Nil(t, retained.ReleasedAt)
			require.Nil(t, retained.Delivered)
			p.mu.Lock()
			reads := p.reads
			p.mu.Unlock()
			replayed, err := s.RetryCleanup(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, id, v.Revision)
			require.NoError(t, err)
			require.Equal(t, id, replayed.LastCleanupRetry.ID)
			p.mu.Lock()
			require.Equal(t, reads, p.reads)
			require.Equal(t, 2, p.deletes)
			require.Equal(t, 1, p.creates)
			p.failRead = false
			p.mu.Unlock()
			checked, err := s.ReconcileCleanup(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
			require.NoError(t, err)
			require.Equal(t, loss != "request", checked.KeyAbsent)
			require.Nil(t, checked.ReleasedAt)
			newReview, err := s.Review(t.Context(), "tag-admin", r.Scope, r.DeviceID, nil, false)
			require.NoError(t, err)
			_, err = s.Request(t.Context(), "tag-admin", r.Scope, r.DeviceID, uuid.NewString(), newReview.Revision, nil, false)
			require.Error(t, err, "key absence alone must not release the command barrier")
			require.NoError(t, f.client.Agent.DeleteOneID(f.id).Exec(t.Context()))
			require.Equal(t, id, registrationRead(t, f, s, r.ID).LastCleanupRetry.ID)
		})
	}
}

func TestNetbirdCleanupRetryFreshReviewAndConcurrentForms(t *testing.T) {
	for _, same := range []bool{true, false} {
		t.Run(map[bool]string{true: "same-form", false: "different-forms"}[same], func(t *testing.T) {
			f, p, s, r := cleanupRetryFixture(t)
			v, err := s.ReviewCleanup(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
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
					_, errs[i] = s.RetryCleanup(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, ids[i], v.Revision)
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
			require.Equal(t, 2, p.deletes)
			p.mu.Unlock()
			fresh, err := s.ReviewCleanup(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
			require.NoError(t, err)
			require.True(t, fresh.CanRetry)
			require.NotEqual(t, v.Revision, fresh.Revision)
			p.mu.Lock()
			p.retainDelete = false
			p.mu.Unlock()
			result, err := s.RetryCleanup(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), fresh.Revision)
			require.NoError(t, err)
			require.True(t, result.KeyAbsent)
			require.Equal(t, int64(2), result.LastCleanupRetry.Sequence)
			var count int
			require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT count(*) FROM uem_netbird_cleanup_retries WHERE request_id=$1`, r.ID).Scan(&count))
			require.Equal(t, 2, count)
			_, err = s.RetryCleanup(t.Context(), "admin", r.Scope, r.DeviceID, r.ID, result.LastCleanupRetry.ID, fresh.Revision)
			require.ErrorIs(t, err, inventory.ErrNetbirdOperationConflict)
		})
	}
}

func TestNetbirdCleanupRetryRefusesChangedTargetAndMissingAuthority(t *testing.T) {
	for _, change := range []string{"policy", "unavailable", "absent", "moved", "removed", "disabled", "mode", "attempt-audit"} {
		t.Run(change, func(t *testing.T) {
			f, p, s, r := cleanupRetryFixture(t)
			v, err := s.ReviewCleanup(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
			require.NoError(t, err)
			for _, actor := range []string{"viewer", "operator", "missing"} {
				_, err = s.ReviewCleanup(t.Context(), actor, r.Scope, r.DeviceID, r.ID)
				require.ErrorIs(t, err, access.ErrDenied)
				_, err = s.RetryCleanup(t.Context(), actor, r.Scope, r.DeviceID, r.ID, uuid.NewString(), v.Revision)
				require.ErrorIs(t, err, access.ErrDenied)
			}
			err = nil
			switch change {
			case "policy":
				p.mu.Lock()
				p.drift = true
				p.mu.Unlock()
			case "unavailable":
				p.mu.Lock()
				p.failRead = true
				p.mu.Unlock()
			case "absent":
				p.mu.Lock()
				p.absent = true
				p.mu.Unlock()
			case "moved":
				err = f.client.Agent.UpdateOneID(f.id).RemoveSiteIDs(f.scope.SiteID).AddSiteIDs(f.otherSite).Exec(t.Context())
			case "removed":
				err = f.client.Agent.DeleteOneID(f.id).Exec(t.Context())
			case "disabled":
				_, err = f.db.ExecContext(t.Context(), `UPDATE agents SET agent_status='Disabled' WHERE oid=$1`, f.id)
			case "mode":
				s, err = inventory.NewNetbirdRegistrationStore(f.db, f.permissions, true, strings.Repeat("k", 32), p.server.Client().Transport, registrationControl, netbirdSuccess)
			case "attempt-audit":
				_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_operations_audit ADD CONSTRAINT owned_cleanup_attempt_failure CHECK(resource_id NOT LIKE '%/cleanup-retry/%') NOT VALID`)
			}
			require.NoError(t, err)
			_, err = s.RetryCleanup(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), v.Revision)
			require.Error(t, err)
			p.mu.Lock()
			require.Equal(t, 1, p.deletes)
			p.mu.Unlock()
			var attempts int
			require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT count(*) FROM uem_netbird_cleanup_retries WHERE request_id=$1`, r.ID).Scan(&attempts))
			require.Zero(t, attempts)
		})
	}
}

func TestNetbirdCleanupRetryUsesOriginalSnapshotAndPermanentEvidence(t *testing.T) {
	f, p, s, r := cleanupRetryFixture(t)
	v, err := s.ReviewCleanup(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
	require.NoError(t, err)
	_, err = f.db.ExecContext(t.Context(), `UPDATE netbird_settings SET management_url='https://changed.invalid',access_token='changed-token'`)
	require.NoError(t, err)
	p.mu.Lock()
	p.retainDelete = false
	p.mu.Unlock()
	result, err := s.RetryCleanup(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), v.Revision)
	require.NoError(t, err)
	require.True(t, result.KeyAbsent)
	p.mu.Lock()
	for _, token := range p.tokens {
		require.NotContains(t, token, "changed-token")
	}
	p.mu.Unlock()
	public, err := json.Marshal(result)
	require.NoError(t, err)
	for _, secret := range []string{"owned-private-setup-key", "changed-token", "Bearer"} {
		require.NotContains(t, string(public), secret)
	}
	for _, query := range []string{`UPDATE uem_netbird_cleanup_retries SET actor='changed'`, `DELETE FROM uem_netbird_cleanup_retries`, `UPDATE uem_netbird_registrations SET released_at=clock_timestamp(),released_by='admin' WHERE id=$1`} {
		if strings.Contains(query, "$1") {
			_, err = f.db.ExecContext(t.Context(), query, r.ID)
		} else {
			_, err = f.db.ExecContext(t.Context(), query)
		}
		require.Error(t, err)
	}
	for _, trigger := range []string{"uem_netbird_cleanup_retry_immutable", "uem_netbird_cleanup_retry_valid"} {
		_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_cleanup_retries DISABLE TRIGGER `+trigger)
		require.NoError(t, err)
		require.Error(t, inventory.Migrate(t.Context(), f.db))
		_, err = f.db.ExecContext(t.Context(), `ALTER TABLE uem_netbird_cleanup_retries ENABLE TRIGGER `+trigger)
		require.NoError(t, err)
	}
}

func TestNetbirdCleanupRetryDatabaseAdmission(t *testing.T) {
	f, _, s, r := cleanupRetryFixture(t)
	v, err := s.ReviewCleanup(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
	require.NoError(t, err)
	var digest string
	require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT digest FROM uem_netbird_registration_attempts WHERE request_id=$1 AND stage='delete'`, r.ID).Scan(&digest))
	for _, change := range []string{"valid", "request", "key", "digest", "sequence", "review"} {
		request, key, hash, rev, sequence := r.ID, r.Key.ID, digest, v.Revision, 1
		switch change {
		case "request":
			request = uuid.NewString()
		case "key":
			key = "foreign-key"
		case "digest":
			hash = strings.Repeat("0", 64)
		case "sequence":
			sequence = 2
		case "review":
			rev = "invalid"
		}
		tx, err := f.db.BeginTx(t.Context(), nil)
		require.NoError(t, err)
		_, err = tx.ExecContext(t.Context(), `INSERT INTO uem_netbird_cleanup_retries(id,request_id,actor,revision,key_id,digest,sequence) VALUES($1,$2,'tag-admin',$3,$4,$5,$6)`, uuid.NewString(), request, rev, key, hash, sequence)
		if change == "valid" {
			require.NoError(t, err)
		} else {
			require.Error(t, err, change)
		}
		require.NoError(t, tx.Rollback())
	}
}

func exerciseNetbirdCleanupIdentity(t *testing.T, f *refreshFixture, p *ownedRegistrationProvider, s *inventory.NetbirdRegistrationStore, r *inventory.NetbirdRegistration, change string) {
	t.Helper()
	v, err := s.ReviewCleanup(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
	require.NoError(t, err)
	require.True(t, v.CanRetry)
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
	_, err = s.RetryCleanup(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), v.Revision)
	require.Error(t, err)
	p.mu.Lock()
	require.Equal(t, 1, p.deletes)
	p.mu.Unlock()
	if change == "renewed" {
		fresh, err := s.ReviewCleanup(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID)
		require.NoError(t, err)
		require.NotEqual(t, v.Revision, fresh.Revision)
		p.mu.Lock()
		p.retainDelete = false
		p.mu.Unlock()
		result, err := s.RetryCleanup(t.Context(), "tag-admin", r.Scope, r.DeviceID, r.ID, uuid.NewString(), fresh.Revision)
		require.NoError(t, err)
		require.True(t, result.KeyAbsent)
	}
}

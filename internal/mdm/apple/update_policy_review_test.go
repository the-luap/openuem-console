package apple

import (
	"strings"
	"sync"
	"testing"

	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func TestReviewedDeviceUpdatePolicyPreservesConcurrentConfiguration(t *testing.T) {
	s, permissions, _, d := profileAssignmentAccessFixture(t)
	ctx := t.Context()
	scope := Scope{TenantID: 1, SiteID: 1}
	p := ownedUpdatePlanDefinition().Policy()
	assessment, err := s.AssessDeviceUpdate(ctx, "viewer", permissions, scope, d.ID)
	require.NoError(t, err)
	current := assessment.PolicyToken
	require.Equal(t, updatePolicyGroupToken(scope, d.ID, nil), current)
	apply := func(token string, policy *UpdatePolicy) error {
		return s.SetReviewedDeviceUpdatePolicy(ctx, scope, d.ID, token, policy, "operator", permissions)
	}
	require.NoError(t, apply(current, &p))
	var originalCommand string
	require.NoError(t, s.db.QueryRow(`SELECT id FROM mdm_apple_commands WHERE device_id=$1 AND request_type='DeclarativeManagement' AND status='queued'`, d.ID).Scan(&originalCommand))
	for _, policy := range []*UpdatePolicy{&p, nil} {
		require.ErrorIs(t, apply(current, policy), ErrUpdatePolicyReview)
	}
	var command string
	require.NoError(t, s.db.QueryRow(`SELECT id FROM mdm_apple_commands WHERE device_id=$1 AND request_type='DeclarativeManagement' AND status='queued'`, d.ID).Scan(&command))
	require.Equal(t, originalCommand, command)
	current = updatePolicyGroupToken(scope, d.ID, &p)
	_, err = s.db.Exec(`UPDATE mdm_apple_update_policies SET status='failed',error='owned failure',updated_at=clock_timestamp() WHERE device_id=$1`, d.ID)
	require.NoError(t, err)
	require.NoError(t, apply(current, nil), "Progress alone must not invalidate reviewed configured values")
	require.ErrorIs(t, apply(current, &p), ErrUpdatePolicyReview)
	require.NoError(t, apply(updatePolicyGroupToken(scope, d.ID, nil), &p))
	current = updatePolicyGroupToken(scope, d.ID, &p)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	start := make(chan struct{})
	for _, deadline := range []string{"2026-10-02T18:00:00", "2026-10-03T18:00:00"} {
		wg.Go(func() {
			changed := p
			changed.Deadline = deadline
			<-start
			results <- apply(current, &changed)
		})
	}
	close(start)
	wg.Wait()
	close(results)
	var accepted, conflicts int
	for err := range results {
		if err == nil {
			accepted++
		} else {
			require.ErrorIs(t, err, ErrUpdatePolicyReview)
			conflicts++
		}
	}
	require.Equal(t, 1, accepted)
	require.Equal(t, 1, conflicts)
}

func TestReviewedDeviceUpdatePolicyBindsCurrentAuthorityAndOriginalDeviceSite(t *testing.T) {
	s, permissions, _, d := profileAssignmentAccessFixture(t)
	ctx := t.Context()
	scope := Scope{TenantID: 1, SiteID: 1}
	p := ownedUpdatePlanDefinition().Policy()
	token := updatePolicyGroupToken(scope, d.ID, nil)
	require.ErrorIs(t, s.SetReviewedDeviceUpdatePolicy(ctx, scope, d.ID, token, &p, "viewer", permissions), access.ErrDenied)
	require.ErrorIs(t, s.SetReviewedDeviceUpdatePolicy(ctx, scope, d.ID, token, &p, "admin", nil), access.ErrDenied)
	for _, invalid := range []string{"", strings.Repeat("A", 64), token + "0", updatePolicyGroupToken(Scope{TenantID: 2, SiteID: 1}, d.ID, nil), updatePolicyGroupToken(scope, "10000000-0000-0000-0000-000000000002", nil)} {
		require.ErrorIs(t, s.SetReviewedDeviceUpdatePolicy(ctx, scope, d.ID, invalid, &p, "admin", permissions), ErrUpdatePolicyReview)
	}
	// An organization route retains the reviewed actual site in its comparison.
	require.NoError(t, s.SetReviewedDeviceUpdatePolicy(ctx, Scope{TenantID: 1}, d.ID, token, &p, "organization", permissions))
	_, err := s.db.Exec(`INSERT INTO sites(id,tenant_sites) VALUES(3,1)`)
	require.NoError(t, err)
	_, err = s.db.Exec(`UPDATE mdm_apple_devices SET site_id=3 WHERE id=$1`, d.ID)
	require.NoError(t, err)
	require.ErrorIs(t, s.SetReviewedDeviceUpdatePolicy(ctx, Scope{TenantID: 1}, d.ID, updatePolicyGroupToken(scope, d.ID, &p), nil, "admin", permissions), ErrUpdatePolicyReview)
	stored, err := s.UpdatePolicy(ctx, Scope{TenantID: 1}, d.ID)
	require.NoError(t, err)
	require.Equal(t, p.Deadline, stored.Deadline)
}

func TestReviewedDeviceUpdatePolicyRollsBackLateAuditFailure(t *testing.T) {
	s, permissions, _, d := profileAssignmentAccessFixture(t)
	ctx := t.Context()
	scope := Scope{TenantID: 1, SiteID: 1}
	p := ownedUpdatePlanDefinition().Policy()
	_, err := s.db.Exec(`CREATE FUNCTION owned_reviewed_update_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.update.policy' THEN RAISE EXCEPTION 'owned reviewed update audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER owned_reviewed_update_audit_failure BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION owned_reviewed_update_audit_failure()`)
	require.NoError(t, err)
	require.Error(t, s.SetReviewedDeviceUpdatePolicy(ctx, scope, d.ID, updatePolicyGroupToken(scope, d.ID, nil), &p, "operator", permissions))
	var count int
	require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM mdm_apple_update_policies WHERE device_id=$1`, d.ID).Scan(&count))
	require.Zero(t, count)
	require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE device_id=$1 AND request_type='DeclarativeManagement'`, d.ID).Scan(&count))
	require.Zero(t, count)
}

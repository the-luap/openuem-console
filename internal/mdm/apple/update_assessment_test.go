package apple

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func TestDeviceUpdateAssessmentUsesPacketEvidenceAndIndependentErrors(t *testing.T) {
	s, permissions, _, d := profileAssignmentAccessFixture(t)
	ctx := t.Context()
	scope := Scope{TenantID: 1, SiteID: 1}
	read := func() *UpdateAssessment {
		t.Helper()
		a, err := s.AssessDeviceUpdate(ctx, "viewer", permissions, scope, d.ID)
		require.NoError(t, err)
		return a
	}
	a := read()
	require.Nil(t, a.Policy)
	require.NotNil(t, a.Observation)
	require.Equal(t, "18.6.2", a.Observation.Version)
	require.Empty(t, a.Compliance)
	policy := ownedUpdatePlanDefinition().Policy()
	require.NoError(t, s.SetUpdatePolicyWithAccess(ctx, scope, []string{d.ID}, &policy, "operator", permissions))
	require.Equal(t, "update_required", read().Compliance)
	report := func(fields map[string]any) {
		t.Helper()
		require.NoError(t, s.saveStatus(ctx, d, &StatusReport{StatusItems: map[string]any{"device": map[string]any{"operating-system": fields}}}))
	}
	require.NoError(t, s.saveStatus(ctx, d, &StatusReport{StatusItems: map[string]any{"softwareupdate": map[string]any{"install-state": "failed"}}}))
	require.Equal(t, "update_required", read().Compliance)
	report(map[string]any{"version": "18.7.1"})
	a = read()
	require.Equal(t, "unknown", a.Compliance)
	require.Equal(t, "missing_build", a.Reason)
	require.Empty(t, a.Observation.Build)
	report(map[string]any{"build-version": "22H100"})
	require.Equal(t, "unknown", read().Compliance)
	report(map[string]any{"version": "18.7.1", "build-version": "22H100"})
	a = read()
	require.Equal(t, "compliant", a.Compliance)
	old := *a.Observation
	require.NoError(t, s.saveStatus(ctx, d, &StatusReport{StatusItems: map[string]any{"softwareupdate": map[string]any{"install-state": "failed"}}}))
	a = read()
	require.Equal(t, "compliant", a.Compliance)
	require.Equal(t, "failed", a.Policy.Status)
	require.True(t, old.RecordedAt.Equal(a.Observation.RecordedAt))
	_, err := s.db.Exec(`UPDATE mdm_apple_update_policies SET error=$2 WHERE device_id=$1`, d.ID, "Owned <status details>")
	require.NoError(t, err)
	a = read()
	require.True(t, a.PolicyHasError)
	require.False(t, a.PolicyErrorTruncated)
	require.Equal(t, "Owned <status details>", a.Policy.Error)
	_, err = s.db.Exec(`UPDATE mdm_apple_update_policies SET error=repeat('x',8193) WHERE device_id=$1`, d.ID)
	require.NoError(t, err)
	a = read()
	require.True(t, a.PolicyHasError)
	require.True(t, a.PolicyErrorTruncated)
	require.Empty(t, a.Policy.Error)
	policy.TargetBuild = ""
	require.NoError(t, s.SetUpdatePolicyWithAccess(ctx, scope, []string{d.ID}, &policy, "operator", permissions))
	report(map[string]any{"version": "18.7.1"})
	require.Equal(t, "compliant", read().Compliance)
	for _, value := range []any{a, a.Observation} {
		body, err := json.Marshal(value)
		require.NoError(t, err)
		require.JSONEq(t, `{}`, string(body))
		require.NotContains(t, fmt.Sprintf("%#v", value), d.ID)
		require.NotContains(t, fmt.Sprintf("%#v", value), "18.7.1")
	}
}

func TestDeviceUpdateAssessmentRejectsInvalidSourceAndStaleAuthority(t *testing.T) {
	for _, condition := range []string{"missing", "stale", "future", "revoked", "expired", "moved-device", "moved-site", "oversized-policy", "invalid-policy", "oversized-status", "audit"} {
		t.Run(condition, func(t *testing.T) {
			s, permissions, _, d := profileAssignmentAccessFixture(t)
			ctx := t.Context()
			scope := Scope{TenantID: 1, SiteID: 1}
			policy := ownedUpdatePlanDefinition().Policy()
			require.NoError(t, s.SetUpdatePolicyWithAccess(ctx, scope, []string{d.ID}, &policy, "operator", permissions))
			var query string
			switch condition {
			case "missing":
				query = `DELETE FROM mdm_apple_os_observations WHERE device_id=$1`
			case "stale":
				query = `UPDATE mdm_apple_os_observations SET recorded_at=clock_timestamp()-INTERVAL '25 hours' WHERE device_id=$1`
			case "future":
				query = `UPDATE mdm_apple_os_observations SET recorded_at=clock_timestamp()+INTERVAL '1 hour' WHERE device_id=$1`
			case "revoked":
				query = `UPDATE mdm_apple_devices SET status='revoked' WHERE id=$1`
			case "expired":
				query = `UPDATE mdm_apple_devices SET certificate_expires_at=clock_timestamp()-INTERVAL '1 minute' WHERE id=$1`
			case "moved-device":
				query = `UPDATE mdm_apple_devices SET site_id=2 WHERE id=$1`
			case "moved-site":
				_, err := s.db.Exec(`UPDATE sites SET tenant_sites=2 WHERE id=1`)
				require.NoError(t, err)
			case "oversized-policy":
				query = `UPDATE mdm_apple_update_policies SET details_url=repeat('x',8193) WHERE device_id=$1`
			case "invalid-policy":
				query = `UPDATE mdm_apple_update_policies SET target_version='unknown' WHERE device_id=$1`
			case "oversized-status":
				query = `UPDATE mdm_apple_update_policies SET status=repeat('x',65) WHERE device_id=$1`
			case "audit":
				_, err := s.db.Exec(`CREATE FUNCTION owned_update_assessment_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.update.plan.device.assessment' THEN RAISE EXCEPTION 'owned assessment audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER owned_update_assessment_audit_failure BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION owned_update_assessment_audit_failure()`)
				require.NoError(t, err)
			}
			if query != "" {
				_, err := s.db.Exec(query, d.ID)
				require.NoError(t, err)
			}
			a, err := s.AssessDeviceUpdate(ctx, "viewer", permissions, scope, d.ID)
			switch condition {
			case "missing", "stale", "future":
				require.NoError(t, err)
				require.Equal(t, "unknown", a.Compliance)
				require.NotEmpty(t, a.Reason)
			case "revoked", "expired":
				require.NoError(t, err)
				require.Equal(t, "not_managed", a.Compliance)
			default:
				require.Error(t, err)
				require.Nil(t, a)
			}
		})
	}
}

func TestDeviceUpdateAssessmentSupportsOrganizationAndSiteScope(t *testing.T) {
	s, permissions, _, d := profileAssignmentAccessFixture(t)
	ctx := t.Context()
	a, err := s.AssessDeviceUpdate(ctx, "admin", permissions, Scope{TenantID: 1}, d.ID)
	require.NoError(t, err)
	require.Equal(t, Scope{TenantID: 1, SiteID: 1}, a.Scope)
	_, err = s.AssessDeviceUpdate(ctx, "viewer", permissions, Scope{TenantID: 1}, d.ID)
	require.ErrorIs(t, err, access.ErrDenied)
	_, err = s.AssessDeviceUpdate(ctx, "admin", nil, Scope{TenantID: 1}, d.ID)
	require.ErrorIs(t, err, access.ErrDenied)
	_, err = s.AssessDeviceUpdate(ctx, "missing", permissions, Scope{TenantID: 1, SiteID: 1}, d.ID)
	require.ErrorIs(t, err, access.ErrDenied)
	_, err = s.AssessDeviceUpdate(ctx, "admin", permissions, Scope{TenantID: 2}, d.ID)
	require.ErrorIs(t, err, ErrNotFound)
}

func TestDeviceUpdateAssessmentHoldsCurrentReadAuthorityThroughAudit(t *testing.T) {
	s, permissions, _, d := profileAssignmentAccessFixture(t)
	ctx := t.Context()
	const gate = 805035014
	blocker, err := s.db.Conn(ctx)
	require.NoError(t, err)
	defer blocker.Close()
	_, err = blocker.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, gate)
	require.NoError(t, err)
	defer blocker.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, gate)
	_, err = s.db.Exec(`CREATE FUNCTION owned_update_assessment_audit_wait() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.update.plan.device.assessment' THEN PERFORM pg_advisory_xact_lock(805035014); END IF; RETURN NEW; END $$; CREATE TRIGGER owned_update_assessment_audit_wait BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION owned_update_assessment_audit_wait()`)
	require.NoError(t, err)
	read := make(chan error, 1)
	go func() {
		_, err := s.AssessDeviceUpdate(ctx, "viewer", permissions, Scope{TenantID: 1, SiteID: 1}, d.ID)
		read <- err
	}()
	waiting := func(key int) bool {
		var found bool
		err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND objid=$1 AND NOT granted)`, key).Scan(&found)
		return err == nil && found
	}
	require.Eventually(t, func() bool { return waiting(gate) }, 3*time.Second, 10*time.Millisecond)
	revoked := make(chan error, 1)
	go func() { revoked <- permissions.ReplaceGrants(ctx, "admin", "viewer", 1, nil) }()
	require.Eventually(t, func() bool { return waiting(684627902) }, 3*time.Second, 10*time.Millisecond)
	select {
	case <-revoked:
		t.Fatal("grant replacement passed an active assessment")
	default:
	}
	_, err = blocker.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, gate)
	require.NoError(t, err)
	require.NoError(t, <-read)
	require.NoError(t, <-revoked)
	a, err := s.AssessDeviceUpdate(ctx, "viewer", permissions, Scope{TenantID: 1, SiteID: 1}, d.ID)
	require.ErrorIs(t, err, access.ErrDenied)
	require.Nil(t, a)
}

func TestDeviceUpdateAssessmentVersionPatternRejectsOverflow(t *testing.T) {
	now := time.Now().UTC()
	result, reason := assessUpdateOS("available", &OSObservation{Version: strings.Repeat("9", 32), RecordedAt: now}, "18.7.1", "22H100", time.Time{}, now)
	require.Equal(t, "unverified", result)
	require.Equal(t, "invalid_report", reason)
}

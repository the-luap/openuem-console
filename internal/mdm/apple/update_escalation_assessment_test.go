package apple

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestUpdateEscalationSeparatesActionableEvidenceFromSuppressionAndUnknowns(t *testing.T) {
	now := time.Date(2026, 10, 25, 3, 0, 0, 0, time.UTC)
	for _, tc := range []struct{ name, state, reason string }{
		{"overdue", "attention", "update_required_after_deadline"},
		{"unavailable", "unverified", "device_unavailable"},
		{"exception", "suppressed", "exception_active"},
		{"replacement", "suppressed", "policy_different"},
		{"removed", "suppressed", "policy_absent"},
		{"unknown-policy", "unverified", "policy_unverified"},
		{"compliant", "suppressed", "target_reported"},
		{"unknown-os", "unverified", "os_unverified"},
		{"unknown-zone", "unverified", "deadline_unverified"},
		{"pending", "pending", "deadline_pending"},
		{"between-fold-occurrences", "unverified", "awaiting_post_deadline_report"},
		{"before-exception-expiry", "unverified", "awaiting_post_exception_report"},
		{"before-explicit-resume", "unverified", "awaiting_post_exception_report"},
		{"after-exception-expiry", "attention", "update_required_after_deadline"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observed := now.Add(-time.Minute)
			latest := now.Add(-90 * time.Minute)
			ended := now.Add(-30 * time.Minute)
			d := UpdateGroupDeviceProgress{DeviceID: "10000000-0000-4000-8000-000000000001", Availability: "available", PolicyState: "matches", Result: "update_required", RecordedAt: &observed, Deadline: &UpdateDeadlineAssessment{State: "elapsed", Latest: &latest}}
			switch tc.name {
			case "unavailable":
				d.Availability = "unavailable"
			case "exception":
				d.ExceptionActive = true
			case "replacement":
				d.PolicyState = "different"
			case "removed":
				d.PolicyState = "absent"
			case "unknown-policy":
				d.PolicyState = "unknown"
			case "compliant":
				d.Result = "target_reported"
			case "unknown-os":
				d.Result = "unverified"
			case "unknown-zone":
				d.Deadline.State = "unverified"
			case "pending":
				d.Deadline.State = "pending"
			case "between-fold-occurrences":
				observed = latest.Add(-30 * time.Minute)
			case "before-exception-expiry":
				observed = ended.Add(-time.Minute)
				d.Exception = &UpdateException{Kind: "pause", ExpiresAt: &ended}
			case "before-explicit-resume":
				observed = ended.Add(-time.Minute)
				d.Exception = &UpdateException{Kind: "resume", CreatedAt: ended}
			case "after-exception-expiry":
				observed = ended
				d.Exception = &UpdateException{Kind: "pause", ExpiresAt: &ended}
			}
			r := assessUpdateEscalation(d)
			require.Equal(t, tc.state, r.State)
			require.Equal(t, tc.reason, r.Reason)
		})
	}
}

func TestUpdateEscalationReviewSharesOriginalPolicyAndCurrentAuthority(t *testing.T) {
	f, original := ownedUpdateRemovalFixture(t)
	ctx := t.Context()
	r, err := f.store.ReviewUpdateGroupEscalation(ctx, "operator", f.permissions, f.scope, f.plan.ID, original.ID)
	require.NoError(t, err)
	require.Equal(t, original.ID, r.Progress.Assignment.ID)
	require.Len(t, r.Decisions, 1)
	require.Equal(t, 1, r.Unverified)
	_, err = f.store.RecordUpdateException(ctx, "operator", f.permissions, f.scope, ownedExceptionRequest(t, f, "pause"))
	require.NoError(t, err)
	r, err = f.store.ReviewUpdateGroupEscalation(ctx, "operator", f.permissions, f.scope, f.plan.ID, original.ID)
	require.NoError(t, err)
	require.Equal(t, 1, r.Suppressed)
	require.Equal(t, "exception_active", r.Decisions[0].Reason)
	_, err = f.store.ReviewUpdateGroupEscalation(ctx, "viewer", f.permissions, f.scope, f.plan.ID, original.ID)
	require.Error(t, err)
}

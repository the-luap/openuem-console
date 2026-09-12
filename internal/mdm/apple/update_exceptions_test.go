package apple

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func ownedExceptionRequest(t *testing.T, f updateScheduleFixture, kind string) UpdateExceptionRequest {
	t.Helper()
	p, err := f.store.ReviewUpdateException(t.Context(), "operator", f.permissions, f.scope, f.device.ID)
	require.NoError(t, err)
	r := UpdateExceptionRequest{DeviceID: f.device.ID, RequestKey: uuid.NewString(), Kind: kind, Reason: "Owned maintenance <exception>", ReviewToken: p.ReviewToken}
	if kind == "pause" {
		expiry := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
		r.ExpiresAt = &expiry
	}
	return r
}

func TestUpdateExceptionConcurrentReplayAndReviewedResumePreserveLaterPolicy(t *testing.T) {
	f, _ := ownedUpdateRemovalFixture(t)
	ctx := t.Context()
	request := ownedExceptionRequest(t, f, "pause")
	var wg sync.WaitGroup
	results := make(chan *UpdateException, 2)
	failures := make(chan error, 2)
	for range 2 {
		wg.Go(func() {
			r, err := f.store.RecordUpdateException(ctx, "operator", f.permissions, f.scope, request)
			results <- r
			failures <- err
		})
	}
	wg.Wait()
	for range 2 {
		require.NoError(t, <-failures)
	}
	first, second := <-results, <-results
	require.Equal(t, first.ID, second.ID)
	require.NotNil(t, first.PreviousPolicy)
	require.NotEmpty(t, first.CommandID)
	require.Equal(t, 1, first.Revision)
	_, err := f.store.UpdatePolicy(ctx, f.scope, f.device.ID)
	require.ErrorIs(t, err, ErrNotFound)
	p, err := f.store.ReviewUpdateException(ctx, "operator", f.permissions, f.scope, f.device.ID)
	require.NoError(t, err)
	require.True(t, p.Current.Active(p.AssessedAt))
	require.Nil(t, p.Policy)
	policy := f.plan.Definition.Policy()
	require.ErrorIs(t, f.store.SetUpdatePolicyWithAccess(ctx, f.scope, []string{f.device.ID}, &policy, "operator", f.permissions), ErrUpdateExceptionActive)
	require.ErrorIs(t, f.store.SetReviewedDeviceUpdatePolicy(ctx, f.scope, f.device.ID, updatePolicyGroupToken(f.scope, f.device.ID, nil), &policy, "operator", f.permissions), ErrUpdateExceptionActive)
	preview, err := f.store.PreviewUpdatePlanGroup(ctx, "operator", f.permissions, f.scope, f.sources, f.plan.ID, f.plan.Revision, f.group.ID, f.group.Revision)
	require.NoError(t, err)
	require.Empty(t, preview.Targets)
	matched := 0
	for _, excluded := range preview.Excluded {
		if excluded.DeviceID == f.device.ID {
			require.Equal(t, "update_exception", excluded.Reason)
			matched++
		}
	}
	require.Equal(t, 1, matched)
	_, err = f.store.AssignUpdatePlanFromGroup(ctx, "operator", f.permissions, f.scope, f.sources, f.plan.ID, f.plan.Revision, f.group.ID, f.group.Revision, uuid.NewString(), f.selection)
	require.ErrorIs(t, err, ErrConflict)
	resume := ownedExceptionRequest(t, f, "resume")
	r, err := f.store.RecordUpdateException(ctx, "operator", f.permissions, f.scope, resume)
	require.NoError(t, err)
	require.Equal(t, 2, r.Revision)
	require.Equal(t, first.ID, r.PreviousID)
	require.Empty(t, r.CommandID)
	_, err = f.store.UpdatePolicy(ctx, f.scope, f.device.ID)
	require.ErrorIs(t, err, ErrNotFound, "Resume must not restore the old policy")
	require.NoError(t, f.store.SetUpdatePolicyWithAccess(ctx, f.scope, []string{f.device.ID}, &policy, "operator", f.permissions))
	var before, after int
	require.NoError(t, f.store.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE device_id=$1`, f.device.ID).Scan(&before))
	replayed, err := f.store.RecordUpdateException(ctx, "operator", f.permissions, f.scope, request)
	require.NoError(t, err)
	require.Equal(t, first.ID, replayed.ID)
	_, err = f.store.UpdatePolicy(ctx, f.scope, f.device.ID)
	require.NoError(t, err)
	require.NoError(t, f.store.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE device_id=$1`, f.device.ID).Scan(&after))
	require.Equal(t, before, after)
	p, err = f.store.ReviewUpdateException(ctx, "operator", f.permissions, f.scope, f.device.ID)
	require.NoError(t, err)
	require.Equal(t, "resume", p.Current.Kind)
	for _, v := range []any{first, request, p} {
		body, err := json.Marshal(v)
		require.NoError(t, err)
		require.JSONEq(t, `{}`, string(body))
		require.NotContains(t, fmt.Sprintf("%#v", v), "Owned maintenance")
	}
}

func TestUpdateExceptionBlocksScheduledActivation(t *testing.T) {
	f := ownedUpdateScheduleFixture(t)
	ctx := t.Context()
	notBefore := time.Now().UTC().Truncate(time.Second)
	r, err := f.store.ScheduleUpdatePlanFromGroup(ctx, "operator", f.permissions, f.scope, f.sources, f.plan.ID, f.plan.Revision, f.group.ID, f.group.Revision, uuid.NewString(), f.selection, notBefore, time.Hour)
	require.NoError(t, err)
	_, err = f.store.RecordUpdateException(ctx, "operator", f.permissions, f.scope, ownedExceptionRequest(t, f, "pause"))
	require.NoError(t, err)
	phase, err := f.store.processUpdateSchedule(ctx, f.permissions, f.sources, r.ID)
	require.NoError(t, err)
	require.Equal(t, "blocked", phase)
	_, err = f.store.UpdatePolicy(ctx, f.scope, f.device.ID)
	require.ErrorIs(t, err, ErrNotFound)
}

func TestUpdateExceptionRejectsStaleReviewAndRollsBackFailedAudit(t *testing.T) {
	f, _ := ownedUpdateRemovalFixture(t)
	ctx := t.Context()
	request := ownedExceptionRequest(t, f, "pause")
	policy := f.plan.Definition.Policy()
	policy.Deadline = "2026-12-01T18:00:00"
	require.NoError(t, f.store.SetUpdatePolicyWithAccess(ctx, f.scope, []string{f.device.ID}, &policy, "operator", f.permissions))
	_, err := f.store.RecordUpdateException(ctx, "operator", f.permissions, f.scope, request)
	require.ErrorIs(t, err, ErrUpdateExceptionReview)
	request = ownedExceptionRequest(t, f, "pause")
	_, err = f.store.db.Exec(`CREATE FUNCTION owned_exception_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.update.exception.recorded' THEN RAISE EXCEPTION 'owned exception late audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER owned_exception_audit_failure BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION owned_exception_audit_failure()`)
	require.NoError(t, err)
	var before, after int
	require.NoError(t, f.store.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE device_id=$1`, f.device.ID).Scan(&before))
	_, err = f.store.RecordUpdateException(ctx, "operator", f.permissions, f.scope, request)
	require.Error(t, err)
	p, err := f.store.UpdatePolicy(ctx, f.scope, f.device.ID)
	require.NoError(t, err)
	require.Equal(t, policy.Deadline, p.Deadline)
	require.NoError(t, f.store.db.QueryRow(`SELECT count(*) FROM mdm_apple_commands WHERE device_id=$1`, f.device.ID).Scan(&after))
	require.Equal(t, before, after)
	var count int
	require.NoError(t, f.store.db.QueryRow(`SELECT count(*) FROM mdm_apple_update_exceptions`).Scan(&count))
	require.Zero(t, count)
}

func TestUpdateExceptionImmutableEvidenceAndCorruptSourceFailClosed(t *testing.T) {
	f := ownedUpdateScheduleFixture(t)
	ctx := t.Context()
	request := ownedExceptionRequest(t, f, "pause")
	r, err := f.store.RecordUpdateException(ctx, "operator", f.permissions, f.scope, request)
	require.NoError(t, err)
	_, err = f.store.db.Exec(`UPDATE mdm_apple_update_exceptions SET actor=actor WHERE id=$1`, r.ID)
	require.Error(t, err)
	_, err = f.store.db.Exec(`DELETE FROM mdm_apple_update_exceptions WHERE id=$1`, r.ID)
	require.Error(t, err)
	_, err = f.store.db.Exec(`ALTER TABLE mdm_apple_update_exceptions DISABLE TRIGGER mdm_apple_keep_update_exception; UPDATE mdm_apple_update_exceptions SET encrypted_intent=decode(repeat('00',40),'hex'); ALTER TABLE mdm_apple_update_exceptions ENABLE TRIGGER mdm_apple_keep_update_exception`)
	require.NoError(t, err)
	_, err = f.store.ReviewUpdateException(ctx, "operator", f.permissions, f.scope, f.device.ID)
	require.ErrorIs(t, err, ErrUpdateExceptionIntegrity)
	_, err = f.store.RecordUpdateException(ctx, "operator", f.permissions, f.scope, request)
	require.ErrorIs(t, err, ErrUpdateExceptionIntegrity)
	policy := f.plan.Definition.Policy()
	require.ErrorIs(t, f.store.SetUpdatePolicyWithAccess(ctx, f.scope, []string{f.device.ID}, &policy, "operator", f.permissions), ErrUpdateExceptionIntegrity)
}

func TestUpdateExceptionHistoryUsesImmutableRevisionsAndCurrentAuthority(t *testing.T) {
	f := ownedUpdateScheduleFixture(t)
	ctx := t.Context()
	var firstRequest UpdateExceptionRequest
	var first *UpdateException
	for range 26 {
		request := ownedExceptionRequest(t, f, "pause")
		r, err := f.store.RecordUpdateException(ctx, "operator", f.permissions, f.scope, request)
		require.NoError(t, err)
		if first == nil {
			first, firstRequest = r, request
		}
	}
	items, next, err := f.store.UpdateExceptions(ctx, "operator", f.permissions, f.scope, f.device.ID, "")
	require.NoError(t, err)
	require.Len(t, items, 25)
	require.NotEmpty(t, next)
	for i, r := range items {
		require.Equal(t, 26-i, r.Revision)
	}
	last, cursor, err := f.store.UpdateExceptions(ctx, "operator", f.permissions, f.scope, f.device.ID, next)
	require.NoError(t, err)
	require.Len(t, last, 1)
	require.Empty(t, cursor)
	require.Equal(t, first.ID, last[0].ID)
	r, err := f.store.UpdateExceptionDetails(ctx, "operator", f.permissions, f.scope, f.device.ID, first.ID)
	require.NoError(t, err)
	require.Equal(t, first.Reason, r.Reason)
	_, _, err = f.store.UpdateExceptions(ctx, "operator", f.permissions, f.scope, uuid.NewString(), next)
	require.ErrorIs(t, err, ErrNotFound)
	_, err = f.store.UpdateExceptionDetails(ctx, "viewer", f.permissions, f.scope, f.device.ID, first.ID)
	require.ErrorIs(t, err, access.ErrDenied)
	_, err = f.store.ReviewUpdateException(ctx, "operator", f.permissions, Scope{TenantID: 1}, f.device.ID)
	require.ErrorIs(t, err, access.ErrDenied)
	_, err = f.store.RecordUpdateException(ctx, "viewer", f.permissions, f.scope, firstRequest)
	require.ErrorIs(t, err, access.ErrDenied)
	// Even equivalent grants have a new authorization revision. A request made
	// under the old grant revision must not replay through the replacement.
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "operator", 1, []access.Grant{{Role: access.Operator, Scope: access.Scope{TenantID: 1, SiteID: 1}}}))
	_, err = f.store.RecordUpdateException(ctx, "operator", f.permissions, f.scope, firstRequest)
	require.ErrorIs(t, err, ErrConflict)
	require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "operator", 2, nil))
	_, _, err = f.store.UpdateExceptions(ctx, "operator", f.permissions, f.scope, f.device.ID, "")
	require.ErrorIs(t, err, access.ErrDenied)
}

func TestUpdateExceptionExpiryLiftsAdmissionWithoutRestoringPolicy(t *testing.T) {
	f, _ := ownedUpdateRemovalFixture(t)
	ctx := t.Context()
	request := ownedExceptionRequest(t, f, "pause")
	expires := time.Now().UTC().Add(3 * time.Second).Truncate(time.Second)
	request.ExpiresAt = &expires
	_, err := f.store.RecordUpdateException(ctx, "operator", f.permissions, f.scope, request)
	require.NoError(t, err)
	policy := f.plan.Definition.Policy()
	require.ErrorIs(t, f.store.SetUpdatePolicy(ctx, f.scope, []string{f.device.ID}, &policy, "owned trusted caller"), ErrUpdateExceptionActive)
	time.Sleep(time.Until(expires) + 250*time.Millisecond)
	p, err := f.store.ReviewUpdateException(ctx, "operator", f.permissions, f.scope, f.device.ID)
	require.NoError(t, err)
	require.False(t, p.Current.Active(p.AssessedAt))
	require.Nil(t, p.Policy)
	require.NoError(t, f.store.SetUpdatePolicy(ctx, f.scope, []string{f.device.ID}, &policy, "owned trusted caller"))
}

func TestUpdateExceptionNotificationCapabilityIsPartOfReview(t *testing.T) {
	f, _ := ownedUpdateRemovalFixture(t)
	ctx := t.Context()
	request := ownedExceptionRequest(t, f, "pause")
	_, err := f.store.db.Exec(`UPDATE mdm_apple_devices SET os_version='14.0' WHERE id=$1`, f.device.ID)
	require.NoError(t, err)
	_, err = f.store.RecordUpdateException(ctx, "operator", f.permissions, f.scope, request)
	require.ErrorIs(t, err, ErrUpdateExceptionReview)
	request = ownedExceptionRequest(t, f, "pause")
	r, err := f.store.RecordUpdateException(ctx, "operator", f.permissions, f.scope, request)
	require.NoError(t, err)
	require.False(t, r.NotificationAvailable)
	require.Empty(t, r.CommandID)
	loaded, err := f.store.UpdateExceptionDetails(ctx, "operator", f.permissions, f.scope, f.device.ID, r.ID)
	require.NoError(t, err)
	require.Empty(t, loaded.CommandID)
	_, err = f.store.UpdatePolicy(ctx, f.scope, f.device.ID)
	require.ErrorIs(t, err, ErrNotFound)
}

func TestUpdateExceptionDoesNotReturnAfterDeviceScopeRoundTrip(t *testing.T) {
	f, _ := ownedUpdateRemovalFixture(t)
	ctx := t.Context()
	r, err := f.store.RecordUpdateException(ctx, "operator", f.permissions, f.scope, ownedExceptionRequest(t, f, "pause"))
	require.NoError(t, err)
	stale := ownedExceptionRequest(t, f, "pause")
	_, err = f.store.db.Exec(`UPDATE mdm_apple_devices SET site_id=2 WHERE id=$1`, f.device.ID)
	require.NoError(t, err)
	_, err = f.store.ReviewUpdateException(ctx, "operator", f.permissions, f.scope, f.device.ID)
	require.ErrorIs(t, err, ErrNotFound)
	_, err = f.store.db.Exec(`UPDATE mdm_apple_devices SET site_id=1 WHERE id=$1`, f.device.ID)
	require.NoError(t, err)
	p, err := f.store.ReviewUpdateException(ctx, "operator", f.permissions, f.scope, f.device.ID)
	require.NoError(t, err)
	require.Nil(t, p.Current)
	require.EqualValues(t, 2, p.ScopeRevision)
	a, err := f.store.AssessDeviceUpdate(ctx, "viewer", f.permissions, f.scope, f.device.ID)
	require.NoError(t, err)
	require.Nil(t, a.Exception)
	require.False(t, a.ExceptionActive)
	_, err = f.store.RecordUpdateException(ctx, "operator", f.permissions, f.scope, stale)
	require.ErrorIs(t, err, ErrUpdateExceptionReview)
	policy := f.plan.Definition.Policy()
	require.NoError(t, f.store.SetUpdatePolicyWithAccess(ctx, f.scope, []string{f.device.ID}, &policy, "operator", f.permissions))
	next, err := f.store.RecordUpdateException(ctx, "operator", f.permissions, f.scope, ownedExceptionRequest(t, f, "pause"))
	require.NoError(t, err)
	require.Equal(t, 2, next.Revision)
	require.Equal(t, r.ID, next.PreviousID)
	require.EqualValues(t, 2, next.ScopeRevision)
	loaded, err := f.store.UpdateExceptionDetails(ctx, "operator", f.permissions, f.scope, f.device.ID, r.ID)
	require.NoError(t, err)
	require.Zero(t, loaded.ScopeRevision)
	_, err = f.store.db.Exec(`UPDATE mdm_apple_devices SET update_exception_scope_revision=0 WHERE id=$1`, f.device.ID)
	require.NoError(t, err)
	p, err = f.store.ReviewUpdateException(ctx, "operator", f.permissions, f.scope, f.device.ID)
	require.NoError(t, err)
	require.EqualValues(t, 2, p.ScopeRevision)
	require.True(t, p.Current.Active(p.AssessedAt))
}

func TestUpdateExceptionCompetingReviewsAdmitOneEvent(t *testing.T) {
	f, _ := ownedUpdateRemovalFixture(t)
	ctx := t.Context()
	one := ownedExceptionRequest(t, f, "pause")
	two := one
	two.RequestKey = uuid.NewString()
	var wg sync.WaitGroup
	failures := make(chan error, 2)
	for _, request := range []UpdateExceptionRequest{one, two} {
		wg.Go(func() {
			_, err := f.store.RecordUpdateException(ctx, "operator", f.permissions, f.scope, request)
			failures <- err
		})
	}
	wg.Wait()
	accepted, changed := 0, 0
	for range 2 {
		err := <-failures
		if err == nil {
			accepted++
		} else {
			require.ErrorIs(t, err, ErrUpdateExceptionReview)
			changed++
		}
	}
	require.Equal(t, 1, accepted)
	require.Equal(t, 1, changed)
}

func TestUpdateExceptionExpiryDuringFinalAuditRollsBack(t *testing.T) {
	for _, condition := range []string{"identity", "exception"} {
		t.Run(condition, func(t *testing.T) {
			f, _ := ownedUpdateRemovalFixture(t)
			ctx := t.Context()
			request := ownedExceptionRequest(t, f, "pause")
			_, err := f.store.db.Exec(`CREATE FUNCTION owned_exception_late_expiry() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.update.exception.recorded' THEN PERFORM pg_sleep(3); END IF; RETURN NEW; END $$; CREATE TRIGGER owned_exception_late_expiry BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION owned_exception_late_expiry()`)
			require.NoError(t, err)
			if condition == "identity" {
				_, err = f.store.db.Exec(`UPDATE mdm_apple_devices SET certificate_expires_at=clock_timestamp()+interval '2 seconds' WHERE id=$1`, f.device.ID)
				require.NoError(t, err)
			} else {
				expiry := time.Now().UTC().Add(2 * time.Second).Truncate(time.Second)
				request.ExpiresAt = &expiry
			}
			started := time.Now()
			_, err = f.store.RecordUpdateException(ctx, "operator", f.permissions, f.scope, request)
			require.ErrorIs(t, err, ErrConflict)
			require.GreaterOrEqual(t, time.Since(started), 3*time.Second)
			policy, err := f.store.UpdatePolicy(ctx, f.scope, f.device.ID)
			require.NoError(t, err)
			require.Equal(t, f.plan.Definition.Deadline, policy.Deadline)
			var count int
			require.NoError(t, f.store.db.QueryRow(`SELECT count(*) FROM mdm_apple_update_exceptions`).Scan(&count))
			require.Zero(t, count)
		})
	}
}

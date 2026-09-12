package apple

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

type updateScheduleFixture struct {
	store       *Store
	permissions *access.Store
	device      *Device
	group       *inventory.DeviceGroup
	plan        *UpdatePlan
	selection   []UpdatePlanGroupSelection
	scope       Scope
	sources     inventory.DeviceSources
}

func ownedUpdateScheduleFixture(t *testing.T) updateScheduleFixture {
	t.Helper()
	s, permissions, _, d, group := profileGroupFixture(t)
	f := updateScheduleFixture{store: s, permissions: permissions, device: d, group: group, scope: Scope{TenantID: 1, SiteID: 1}, sources: inventory.DeviceSources{Apple: true}}
	var err error
	f.plan, err = s.SaveUpdatePlan(t.Context(), "operator", permissions, f.scope, "", 0, ownedUpdatePlanDefinition())
	require.NoError(t, err)
	preview, err := s.PreviewUpdatePlanGroup(t.Context(), "operator", permissions, f.scope, f.sources, f.plan.ID, f.plan.Revision, group.ID, group.Revision)
	require.NoError(t, err)
	f.selection = updateGroupSelection(preview)
	return f
}
func (f updateScheduleFixture) schedule(t *testing.T, at time.Time) *UpdateSchedule {
	t.Helper()
	r, err := f.store.ScheduleUpdatePlanFromGroup(t.Context(), "operator", f.permissions, f.scope, f.sources, f.plan.ID, f.plan.Revision, f.group.ID, f.group.Revision, uuid.NewString(), f.selection, at, time.Hour)
	require.NoError(t, err)
	return r
}
func (f updateScheduleFixture) details(t *testing.T, id string) *UpdateSchedule {
	t.Helper()
	r, err := f.store.UpdateScheduleDetails(t.Context(), "admin", f.permissions, f.scope, f.plan.ID, id)
	require.NoError(t, err)
	return r
}
func (f updateScheduleFixture) process(t *testing.T) UpdateScheduleProgress {
	t.Helper()
	p, err := f.store.ProcessDueUpdateSchedules(t.Context(), f.permissions, f.sources, 25)
	require.NoError(t, err)
	return p
}
func (f updateScheduleFixture) counts(t *testing.T) (policies, receipts, notifications int) {
	t.Helper()
	require.NoError(t, f.store.db.QueryRow(`SELECT (SELECT count(*) FROM mdm_apple_update_policies),(SELECT count(*) FROM mdm_apple_update_group_assignments),(SELECT count(*) FROM mdm_apple_commands WHERE request_type='DeclarativeManagement')`).Scan(&policies, &receipts, &notifications))
	return
}

// Simulate a valid persisted record from an earlier process. Its immutable
// timestamps and ciphertext are constructed together; no production clock hook
// or trigger bypass is used to make expiration tests fast.
func (f updateScheduleFixture) oldRecord(t *testing.T, created, notBefore, expires time.Time) *updateStoredSchedule {
	t.Helper()
	var revision int64
	require.NoError(t, f.store.db.QueryRow(`SELECT COALESCE((SELECT revision FROM uem_access_revisions WHERE user_id='operator'),0)`).Scan(&revision))
	r := &updateStoredSchedule{UpdateSchedule: UpdateSchedule{ID: uuid.NewString(), Scope: f.scope, RequestKey: uuid.NewString(), Plan: *f.plan, Group: ProfileGroupSource{ID: f.group.ID, Revision: f.group.Revision, Name: f.group.Name, Rule: f.group.Rule}, Targets: f.selection, Actor: "operator", ActorRevision: revision, CreatedAt: created, NotBefore: notBefore, ExpiresAt: expires, Phase: "scheduled", Revision: 1, UpdatedAt: created, NextAttemptAt: notBefore}, sources: f.sources, activationKey: uuid.NewString()}
	tx, err := f.store.db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer tx.Rollback()
	require.NoError(t, f.store.insertUpdateSchedule(t.Context(), tx, r))
	require.NoError(t, tx.Commit())
	return r
}

func TestUpdateScheduleFutureReplayConcurrentActivationAndOriginalEvidence(t *testing.T) {
	f := ownedUpdateScheduleFixture(t)
	ctx := t.Context()
	p0, a0, n0 := f.counts(t)
	future := f.schedule(t, time.Now().UTC().Add(time.Hour).Truncate(time.Second))
	require.Zero(t, f.process(t).Processed)
	p, a, n := f.counts(t)
	require.Equal(t, []int{p0, a0, n0}, []int{p, a, n})
	due := f.schedule(t, time.Now().UTC().Truncate(time.Second))
	failures := make(chan error, 2)
	progress := make(chan UpdateScheduleProgress, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Go(func() {
			p, err := f.store.ProcessDueUpdateSchedules(ctx, f.permissions, f.sources, 25)
			progress <- p
			failures <- err
		})
	}
	workers.Wait()
	require.NoError(t, <-failures)
	require.NoError(t, <-failures)
	require.Equal(t, 1, (<-progress).Activated+(<-progress).Activated)
	got := f.details(t, due.ID)
	require.Equal(t, "activated", got.Phase)
	require.Equal(t, 2, got.Revision)
	require.Equal(t, 1, got.Attempts)
	require.NotEmpty(t, got.AssignmentID)
	receipt, err := f.store.UpdatePlanGroupAssignmentDetails(ctx, "operator", f.permissions, f.scope, f.plan.ID, got.AssignmentID)
	require.NoError(t, err)
	require.Equal(t, f.selection[0], receipt.Commands[0].Selection)
	require.NotEqual(t, due.RequestKey, receipt.RequestKey)
	restarted, err := NewStore(f.store.db, "integration-test-master-key-32-bytes-minimum")
	require.NoError(t, err)
	pAfter, err := restarted.ProcessDueUpdateSchedules(ctx, f.permissions, f.sources, 25)
	require.NoError(t, err)
	require.Zero(t, pAfter.Processed)
	require.NoError(t, f.store.CancelUpdateSchedule(ctx, "admin", f.permissions, f.scope, f.plan.ID, future.ID, future.Revision))
	require.ErrorIs(t, f.store.CancelUpdateSchedule(ctx, "admin", f.permissions, f.scope, f.plan.ID, due.ID, due.Revision), ErrConflict)
	definition := f.plan.Definition
	definition.Archived = true
	definition.Name = "Later plan"
	_, err = f.store.SaveUpdatePlan(ctx, "operator", f.permissions, f.scope, f.plan.ID, f.plan.Revision, definition)
	require.NoError(t, err)
	groupDefinition := f.group.DeviceGroupDefinition
	groupDefinition.Archived = true
	_, err = inventory.SaveDeviceGroup(ctx, f.store.db, f.permissions, "operator", access.Scope{TenantID: 1, SiteID: 1}, f.group.ID, f.group.Revision, groupDefinition)
	require.NoError(t, err)
	require.NoError(t, f.store.SetUpdatePolicyWithAccess(ctx, f.scope, []string{f.device.ID}, nil, "operator", f.permissions))
	p, a, n = f.counts(t)
	replay, err := f.store.ScheduleUpdatePlanFromGroup(ctx, "operator", f.permissions, f.scope, inventory.DeviceSources{}, f.plan.ID, f.plan.Revision, f.group.ID, f.group.Revision, due.RequestKey, f.selection, due.NotBefore, time.Hour)
	require.NoError(t, err)
	require.Equal(t, got.AssignmentID, replay.AssignmentID)
	require.Equal(t, f.plan.Definition, replay.Plan.Definition)
	p2, a2, n2 := f.counts(t)
	require.Equal(t, []int{p, a, n}, []int{p2, a2, n2})
	data, err := json.Marshal(replay)
	require.NoError(t, err)
	require.JSONEq(t, `{}`, string(data))
	require.NotContains(t, fmt.Sprintf("%#v", replay), replay.ID)
}

func TestUpdateScheduleChangedAuthoritySourcesAndReviewBlockAllDeviceWork(t *testing.T) {
	for _, condition := range []string{"authority", "grant-revision", "scope", "sources", "plan", "group", "members", "policy", "catalog"} {
		t.Run(condition, func(t *testing.T) {
			f := ownedUpdateScheduleFixture(t)
			ctx := t.Context()
			r := f.schedule(t, time.Now().UTC().Truncate(time.Second))
			switch condition {
			case "authority":
				require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "operator", 1, []access.Grant{{Role: access.Viewer, Scope: access.Scope{TenantID: 1, SiteID: 1}}}))
			case "grant-revision":
				require.NoError(t, f.permissions.ReplaceGrants(ctx, "admin", "operator", 1, []access.Grant{{Role: access.Operator, Scope: access.Scope{TenantID: 1, SiteID: 1}}}))
			case "scope":
				_, err := f.store.db.Exec(`UPDATE sites SET tenant_sites=2 WHERE id=1`)
				require.NoError(t, err)
			case "sources":
				f.sources.Windows = true
			case "plan":
				definition := f.plan.Definition
				definition.Archived = true
				_, err := f.store.SaveUpdatePlan(ctx, "operator", f.permissions, f.scope, f.plan.ID, f.plan.Revision, definition)
				require.NoError(t, err)
			case "group":
				definition := f.group.DeviceGroupDefinition
				definition.Name = "Later group"
				_, err := inventory.SaveDeviceGroup(ctx, f.store.db, f.permissions, "operator", access.Scope{TenantID: 1, SiteID: 1}, f.group.ID, f.group.Revision, definition)
				require.NoError(t, err)
			case "members":
				second, _ := testEnroll(t, f.store, f.scope, "Owned later schedule target")
				drainCommands(t, f.store, second, nil)
			case "policy":
				policy := f.plan.Definition.Policy()
				require.NoError(t, f.store.SetUpdatePolicyWithAccess(ctx, f.scope, []string{f.device.ID}, &policy, "operator", f.permissions))
			case "catalog":
				_, err := f.store.db.Exec(`UPDATE mdm_apple_software_catalog SET fetched_at=clock_timestamp()-INTERVAL '3 days'`)
				require.NoError(t, err)
			}
			p, a, n := f.counts(t)
			require.Equal(t, 1, f.process(t).Blocked)
			p2, a2, n2 := f.counts(t)
			require.Equal(t, []int{p, a, n}, []int{p2, a2, n2})
			if condition == "scope" {
				_, err := f.store.db.Exec(`UPDATE sites SET tenant_sites=1 WHERE id=1`)
				require.NoError(t, err)
			}
			got := f.details(t, r.ID)
			require.Equal(t, "blocked", got.Phase)
			require.NotEmpty(t, got.Reason)
			require.Zero(t, f.process(t).Processed)
		})
	}
}

func TestUpdateScheduleExpirationAndLateAuditRollback(t *testing.T) {
	for _, condition := range []string{"expired", "audit-failure", "audit-expiry"} {
		t.Run(condition, func(t *testing.T) {
			f := ownedUpdateScheduleFixture(t)
			now := time.Now().UTC().Truncate(time.Microsecond)
			expires := now.Add(time.Hour)
			if condition == "expired" {
				expires = now.Add(-time.Minute)
			}
			if condition == "audit-expiry" {
				expires = now.Add(500 * time.Millisecond)
			}
			r := f.oldRecord(t, now.Add(-3*time.Minute), now.Add(-2*time.Minute), expires)
			if condition != "expired" {
				body := "PERFORM nextval('owned_schedule_audit_entered'); RAISE EXCEPTION 'owned scheduled activation audit failure';"
				if condition == "audit-expiry" {
					body = "PERFORM nextval('owned_schedule_audit_entered'); PERFORM pg_sleep(0.7);"
				}
				_, err := f.store.db.Exec(`CREATE SEQUENCE owned_schedule_audit_entered; CREATE FUNCTION owned_schedule_final_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='apple.update.plan.schedule.activated' THEN ` + body + ` END IF; RETURN NEW; END $$; CREATE TRIGGER owned_schedule_final_audit BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION owned_schedule_final_audit()`)
				require.NoError(t, err)
			}
			p, a, n := f.counts(t)
			progress, err := f.store.ProcessDueUpdateSchedules(t.Context(), f.permissions, f.sources, 25)
			if condition == "audit-failure" {
				require.Error(t, err)
				require.Equal(t, 1, progress.Failed)
				require.Equal(t, "scheduled", f.details(t, r.ID).Phase)
			} else {
				require.NoError(t, err)
				require.Equal(t, 1, progress.Expired)
				require.Equal(t, "expired", f.details(t, r.ID).Phase)
			}
			if condition != "expired" {
				var entered bool
				require.NoError(t, f.store.db.QueryRow(`SELECT is_called FROM owned_schedule_audit_entered`).Scan(&entered))
				require.True(t, entered, "activation must reach the final audit before failure or expiry")
			}
			p2, a2, n2 := f.counts(t)
			require.Equal(t, []int{p, a, n}, []int{p2, a2, n2})
			if condition == "audit-failure" {
				_, err = f.store.db.Exec(`DROP TRIGGER owned_schedule_final_audit ON mdm_apple_audit`)
				require.NoError(t, err)
				require.Equal(t, 1, f.process(t).Activated)
			}
		})
	}
}

func TestUpdateScheduleCancellationWinsLockedActivation(t *testing.T) {
	f := ownedUpdateScheduleFixture(t)
	r := f.schedule(t, time.Now().UTC().Truncate(time.Second))
	tx, err := f.store.db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer tx.Rollback()
	_, err = tx.ExecContext(t.Context(), `SELECT id FROM mdm_apple_update_schedules WHERE id=$1 FOR UPDATE`, r.ID)
	require.NoError(t, err)
	require.Zero(t, f.process(t).Processed)
	require.NoError(t, tx.Rollback())
	require.ErrorIs(t, f.store.CancelUpdateSchedule(t.Context(), "viewer", f.permissions, f.scope, f.plan.ID, r.ID, r.Revision), access.ErrDenied)
	require.ErrorIs(t, f.store.CancelUpdateSchedule(t.Context(), "operator", f.permissions, f.scope, f.plan.ID, r.ID, r.Revision+1), ErrConflict)
	require.NoError(t, f.store.CancelUpdateSchedule(t.Context(), "operator", f.permissions, f.scope, f.plan.ID, r.ID, r.Revision))
	require.Zero(t, f.process(t).Processed)
	require.Equal(t, "canceled", f.details(t, r.ID).Phase)
	p, a, _ := f.counts(t)
	require.Zero(t, p)
	require.Zero(t, a)
}

func TestUpdateScheduleReadAuthorityAndAudit(t *testing.T) {
	f := ownedUpdateScheduleFixture(t)
	r := f.schedule(t, time.Now().UTC().Add(time.Hour).Truncate(time.Second))
	for _, actor := range []string{"viewer", "missing"} {
		_, err := f.store.UpdateScheduleDetails(t.Context(), actor, f.permissions, f.scope, f.plan.ID, r.ID)
		require.ErrorIs(t, err, access.ErrDenied)
		_, _, err = f.store.UpdateSchedules(t.Context(), actor, f.permissions, f.scope, f.plan.ID, "")
		require.ErrorIs(t, err, access.ErrDenied)
	}
	_, err := f.store.db.Exec(`CREATE FUNCTION owned_schedule_read_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action IN ('apple.update.plan.schedule.read','apple.update.plan.schedule.list') THEN RAISE EXCEPTION 'owned schedule read audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER owned_schedule_read_audit BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION owned_schedule_read_audit()`)
	require.NoError(t, err)
	detail, err := f.store.UpdateScheduleDetails(t.Context(), "admin", f.permissions, f.scope, f.plan.ID, r.ID)
	require.Error(t, err)
	require.Nil(t, detail)
	list, _, err := f.store.UpdateSchedules(t.Context(), "admin", f.permissions, f.scope, f.plan.ID, "")
	require.Error(t, err)
	require.Nil(t, list)
	_, err = f.store.ProcessDueUpdateSchedules(context.Background(), nil, f.sources, 25)
	require.ErrorIs(t, err, access.ErrDenied)
}

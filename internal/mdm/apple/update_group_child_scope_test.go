package apple

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestUpdateGroupChildSourceMustMatchScheduleOrPromotionSource(t *testing.T) {
	for _, parent := range []string{"schedule", "organization-schedule", "promotion"} {
		t.Run(parent, func(t *testing.T) {
			ctx := t.Context()
			var f updateScheduleFixture
			var child *UpdatePlanGroupAssignment
			var reject func()
			if parent != "promotion" {
				var schedule *UpdateSchedule
				if parent == "organization-schedule" {
					f = ownedOrganizationUpdateFixture(t)
					schedule = ownedOrganizationSchedule(t, f, time.Now().UTC().Truncate(time.Second))
				} else {
					f = ownedUpdateScheduleFixture(t)
					schedule = f.schedule(t, time.Now().UTC().Truncate(time.Second))
				}
				require.Equal(t, 1, f.process(t).Activated)
				detail := f.details(t, schedule.ID)
				var err error
				child, err = f.store.UpdatePlanGroupAssignmentDetails(ctx, "operator", f.permissions, f.scope, f.plan.ID, detail.AssignmentID)
				require.NoError(t, err)
				reject = func() {
					detail, err := f.store.UpdateScheduleDetails(ctx, "operator", f.permissions, f.scope, f.plan.ID, schedule.ID)
					require.ErrorIs(t, err, ErrUpdateScheduleIntegrity)
					require.Nil(t, detail)
				}
			} else {
				var q UpdatePromotionRequest
				f, _, q = ownedUpdatePromotionFixture(t)
				promotion, err := f.store.PromoteUpdatePlanGroup(ctx, "operator", f.permissions, f.scope, f.sources, q)
				require.NoError(t, err)
				child = promotion.Assignment
				reject = func() {
					detail, err := f.store.UpdatePromotionDetails(ctx, "operator", f.permissions, f.scope, q.PilotPlanID, q.PilotAssignmentID, promotion.ID)
					require.ErrorIs(t, err, ErrUpdatePromotionIntegrity)
					require.Nil(t, detail)
				}
			}
			// This owned corruption fixture changes only the authenticated source
			// kind of an otherwise valid child. Parent evidence must reject it.
			if parent == "organization-schedule" {
				child.GroupScope = f.scope
			} else {
				child.GroupScope = Scope{TenantID: f.scope.TenantID}
			}
			encrypted, err := f.store.sealUpdateGroupAssignment(child)
			require.NoError(t, err)
			_, err = f.store.db.Exec(`ALTER TABLE mdm_apple_update_group_assignments DISABLE TRIGGER mdm_apple_keep_update_group_assignment`)
			require.NoError(t, err)
			_, changeErr := f.store.db.Exec(`UPDATE mdm_apple_update_group_assignments SET encrypted_intent=$1 WHERE id=$2`, encrypted, child.ID)
			_, restoreErr := f.store.db.Exec(`ALTER TABLE mdm_apple_update_group_assignments ENABLE TRIGGER mdm_apple_keep_update_group_assignment`)
			require.NoError(t, restoreErr)
			require.NoError(t, changeErr)
			reject()
		})
	}
}

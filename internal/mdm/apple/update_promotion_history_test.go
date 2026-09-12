package apple

import (
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func TestUpdatePromotionHistoryKeysetPreservesOriginalProofAfterLaterChanges(t *testing.T) {
	f, original, q := ownedUpdatePromotionFixture(t)
	ctx := t.Context()
	// A reviewed same-deadline destination leaves this original pilot eligible
	// for separate future requests, each with its own current target selection.
	q.DestinationPlanID = f.plan.ID
	q.DestinationRevision = f.plan.Revision
	record := func() *UpdatePromotion {
		t.Helper()
		preview, err := f.store.PreviewUpdatePromotion(ctx, "operator", f.permissions, f.scope, f.sources, q.PilotPlanID, q.PilotAssignmentID, q.DestinationPlanID, q.DestinationRevision, q.GroupID, q.GroupRevision)
		require.NoError(t, err)
		require.True(t, preview.Ready)
		q.RequestKey = uuid.NewString()
		q.Targets = nil
		for _, target := range preview.Destination.Targets {
			q.Targets = append(q.Targets, target.Selection)
		}
		r, err := f.store.PromoteUpdatePlanGroup(ctx, "operator", f.permissions, f.scope, f.sources, q)
		require.NoError(t, err)
		return r
	}
	var first *UpdatePromotion
	for range 28 {
		r := record()
		if first == nil {
			first = r
		}
	}
	items, next, err := f.store.UpdatePromotions(ctx, "operator", f.permissions, f.scope, q.PilotPlanID, q.PilotAssignmentID, "")
	require.NoError(t, err)
	require.Len(t, items, 25)
	require.NotEmpty(t, next)
	record()
	older, last, err := f.store.UpdatePromotions(ctx, "operator", f.permissions, f.scope, q.PilotPlanID, q.PilotAssignmentID, next)
	require.NoError(t, err)
	require.Len(t, older, 3)
	require.Empty(t, last)
	require.Equal(t, first.ID, older[2].ID)
	definition := f.plan.Definition
	definition.Archived = true
	definition.Name = "Owned later archived plan"
	_, err = f.store.SaveUpdatePlan(ctx, "operator", f.permissions, f.scope, f.plan.ID, f.plan.Revision, definition)
	require.NoError(t, err)
	_, err = f.store.db.Exec(`UPDATE mdm_apple_devices SET site_id=2,name='Owned other-site device' WHERE id=$1`, f.device.ID)
	require.NoError(t, err)
	detail, err := f.store.UpdatePromotionDetails(ctx, "operator", f.permissions, f.scope, q.PilotPlanID, q.PilotAssignmentID, first.ID)
	require.NoError(t, err)
	require.Equal(t, original.Plan.Definition.Name, detail.Pilot.Plan.Definition.Name)
	require.Equal(t, original.Plan.Definition.Name, detail.Assignment.Plan.Definition.Name)
	require.Equal(t, first.Evidence.AssessedAt, detail.Evidence.AssessedAt)
	_, _, err = f.store.UpdatePromotions(ctx, "viewer", f.permissions, f.scope, q.PilotPlanID, q.PilotAssignmentID, "")
	require.ErrorIs(t, err, access.ErrDenied)
	_, err = f.store.db.Exec(`CREATE FUNCTION owned_promotion_read_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action IN ('apple.update.plan.promotion.read','apple.update.plan.promotion.list') THEN RAISE EXCEPTION 'owned promotion read audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER owned_promotion_read_failure BEFORE INSERT ON mdm_apple_audit FOR EACH ROW EXECUTE FUNCTION owned_promotion_read_failure()`)
	require.NoError(t, err)
	detail, err = f.store.UpdatePromotionDetails(ctx, "operator", f.permissions, f.scope, q.PilotPlanID, q.PilotAssignmentID, first.ID)
	require.Error(t, err)
	require.Nil(t, detail)
	items, next, err = f.store.UpdatePromotions(ctx, "operator", f.permissions, f.scope, q.PilotPlanID, q.PilotAssignmentID, "")
	require.Error(t, err)
	require.Nil(t, items)
	require.Empty(t, next)
}

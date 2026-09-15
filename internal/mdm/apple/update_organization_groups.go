package apple

import (
	"context"

	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
)

// PreviewUpdatePlanOrganizationGroup assesses an organization rule inside the
// explicit plan site, including every eligible native device's current policy.
func (s *Store) PreviewUpdatePlanOrganizationGroup(ctx context.Context, actor string, permissions *access.Store, scope Scope, sources inventory.DeviceSources, planID string, planRevision int, groupID string, groupRevision int) (*UpdatePlanGroupPreview, error) {
	return s.previewUpdatePlanGroupSource(ctx, actor, permissions, scope, Scope{TenantID: scope.TenantID}, sources, planID, planRevision, groupID, groupRevision)
}

// AssignUpdatePlanFromOrganizationGroup admits only the reviewed site
// intersection while retaining the organization source with the original plan.
func (s *Store) AssignUpdatePlanFromOrganizationGroup(ctx context.Context, actor string, permissions *access.Store, scope Scope, sources inventory.DeviceSources, planID string, planRevision int, groupID string, groupRevision int, requestKey string, selection []UpdatePlanGroupSelection) (*UpdatePlanGroupAssignment, error) {
	return s.assignUpdatePlanFromGroupSource(ctx, actor, permissions, scope, Scope{TenantID: scope.TenantID}, sources, planID, planRevision, groupID, groupRevision, requestKey, selection)
}

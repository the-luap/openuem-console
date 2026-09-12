package apple

import (
	"context"

	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
)

// PreviewUpdatePromotionOrganizationGroup assesses the original pilot and an
// organization destination rule's intersection with the explicit target site.
func (s *Store) PreviewUpdatePromotionOrganizationGroup(ctx context.Context, actor string, permissions *access.Store, scope Scope, sources inventory.DeviceSources, pilotPlanID, pilotAssignmentID, destinationPlanID string, destinationRevision int, groupID string, groupRevision int) (*UpdatePromotionPreview, error) {
	return s.previewUpdatePromotionSource(ctx, actor, permissions, scope, Scope{TenantID: scope.TenantID}, sources, pilotPlanID, pilotAssignmentID, destinationPlanID, destinationRevision, groupID, groupRevision)
}

// PromoteUpdatePlanOrganizationGroup admits only the reviewed site intersection
// while retaining the organization source with the unchanged pilot proof rules.
func (s *Store) PromoteUpdatePlanOrganizationGroup(ctx context.Context, actor string, permissions *access.Store, scope Scope, sources inventory.DeviceSources, q UpdatePromotionRequest) (*UpdatePromotion, error) {
	return s.promoteUpdatePlanGroupSource(ctx, actor, permissions, scope, Scope{TenantID: scope.TenantID}, sources, q)
}

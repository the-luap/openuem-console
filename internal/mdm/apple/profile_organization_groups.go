package apple

import (
	"context"

	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func validProfileGroupSourceScope(source, target Scope) bool {
	return target.TenantID > 0 && target.SiteID > 0 && source.TenantID == target.TenantID && (source.SiteID == 0 || source.SiteID == target.SiteID)
}

// PreviewProfileOrganizationGroup uses an organization group as the source and
// intersects its membership with the explicitly selected target site.
func (s *Store) PreviewProfileOrganizationGroup(ctx context.Context, actor string, permissions *access.Store, scope Scope, sources inventory.DeviceSources, profileID string, profileRevision int, groupID string, groupRevision int, desired string) (*ProfileGroupPreview, error) {
	return s.previewProfileGroupSource(ctx, actor, permissions, scope, Scope{TenantID: scope.TenantID}, sources, profileID, profileRevision, groupID, groupRevision, desired)
}

// AssignProfileFromOrganizationGroup retains the organization source and target
// site separately while admitting only the complete reviewed site intersection.
func (s *Store) AssignProfileFromOrganizationGroup(ctx context.Context, actor string, permissions *access.Store, scope Scope, sources inventory.DeviceSources, profileID string, profileRevision int, groupID string, groupRevision int, requestKey string, deviceIDs []string, desired string) (*ProfileGroupAssignment, error) {
	return s.assignProfileFromGroupSource(ctx, actor, permissions, scope, Scope{TenantID: scope.TenantID}, sources, profileID, profileRevision, groupID, groupRevision, requestKey, deviceIDs, desired)
}

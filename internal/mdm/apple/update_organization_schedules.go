package apple

import (
	"context"
	"time"

	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
)

// ScheduleUpdatePlanFromOrganizationGroup retains a reviewed organization rule's
// target-site intersection. Activation rechecks the source grant and complete
// original selection before admitting device policies within the UTC window.
func (s *Store) ScheduleUpdatePlanFromOrganizationGroup(ctx context.Context, actor string, permissions *access.Store, scope Scope, sources inventory.DeviceSources, planID string, planRevision int, groupID string, groupRevision int, requestKey string, selection []UpdatePlanGroupSelection, notBefore time.Time, activationWindow time.Duration) (*UpdateSchedule, error) {
	return s.scheduleUpdatePlanFromGroupSource(ctx, actor, permissions, scope, Scope{TenantID: scope.TenantID}, sources, planID, planRevision, groupID, groupRevision, requestKey, selection, notBefore, activationWindow)
}

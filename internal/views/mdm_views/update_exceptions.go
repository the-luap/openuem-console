package mdm_views

import (
	"fmt"

	"github.com/open-uem/openuem-console/internal/mdm/apple"
)

func UpdateExceptionPath(id string) string { return "/ios/" + id + "/update-exceptions" }
func ScopedUpdateExceptionPath(scope apple.Scope, id string) string {
	return fmt.Sprintf("/tenant/%d/site/%d%s", scope.TenantID, scope.SiteID, UpdateExceptionPath(id))
}

package mdm_views

import (
	"context"
	"github.com/invopop/ctxi18n/i18n"
)

func groupSuffix(id string) string {
	if id == "" {
		return ""
	}
	return "/" + id
}
func groupPlatform(ctx context.Context, platform string) string {
	if platform == "" {
		platform = "all"
	}
	return i18n.T(ctx, "mdm.devices.platform_"+platform)
}
func groupState(ctx context.Context, archived bool) string {
	if archived {
		return i18n.T(ctx, "mdm.groups.archived")
	}
	return i18n.T(ctx, "mdm.groups.active")
}

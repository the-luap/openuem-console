package mdm_views

import (
	"context"
	"github.com/invopop/ctxi18n/i18n"
)

func deviceUpdateAssessmentReason(ctx context.Context, reason string) string {
	key := "evidence_invalid"
	switch reason {
	case "device_unavailable":
		key = "evidence_inactive"
	case "no_report":
		key = "evidence_missing"
	case "future_report":
		key = "evidence_future"
	case "stale_report":
		key = "evidence_stale"
	case "missing_build":
		key = "evidence_build"
	}
	return i18n.T(ctx, "updates."+key)
}

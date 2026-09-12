package mdm_views

import (
	"context"

	"github.com/invopop/ctxi18n/i18n"
)

func updateDeadlineState(ctx context.Context, state string) string {
	key := "deadline_unverified"
	switch state {
	case "elapsed":
		key = "deadline_elapsed"
	case "pending":
		key = "deadline_pending"
	}
	return i18n.T(ctx, "updates."+key)
}

func updateDeadlineReason(ctx context.Context, reason string) string {
	key := "deadline_invalid_zone"
	switch reason {
	case "device_unavailable":
		key = "deadline_device_unavailable"
	case "no_timezone":
		key = "deadline_no_zone"
	case "future_timezone":
		key = "deadline_future_zone"
	case "stale_timezone":
		key = "deadline_stale_zone"
	case "unresolved_local_time":
		key = "deadline_unresolved"
	}
	return i18n.T(ctx, "updates."+key)
}

package windows_views

import (
	"context"
	"time"

	"github.com/invopop/ctxi18n/i18n"
	"github.com/open-uem/openuem-console/internal/mdm/windows"
)

type UpdateScheduleTarget struct {
	ID     string                  `json:"-" xml:"-" yaml:"-"`
	Device *windows.DeviceMetadata `json:"-" xml:"-" yaml:"-"`
}

func (UpdateScheduleTarget) String() string     { return "[protected Windows scheduled target]" }
func (v UpdateScheduleTarget) GoString() string { return v.String() }

func scheduleTimestamp(value time.Time) string {
	return value.UTC().Format("2006-01-02 15:04:05.999999999 UTC")
}

func scheduleState(state string) string {
	switch state {
	case "scheduled":
		return "Scheduled; not activated"
	case "waiting":
		return "Waiting to retry activation"
	case "activated":
		return "Activated; device runs created"
	case "blocked":
		return "Blocked; a new review is required"
	case "expired":
		return "Activation window expired"
	case "canceled":
		return "Canceled before activation"
	default:
		return "Status unavailable"
	}
}

func scheduleReason(ctx context.Context, reason string) string {
	switch reason {
	case "group_changed":
		return i18n.T(ctx, "windows_groups.group_changed")
	case "group_sources_changed":
		return i18n.T(ctx, "windows_groups.sources_changed")
	case "device_queue_full":
		return "A selected device's queue is full"
	case "authority_changed":
		return "The creator's permission changed"
	case "ring_assignment_conflict":
		return "The ring revision changed or is no longer enabled for this assignment"
	case "admission_deadline_expired":
		return "A device run's admission lifetime elapsed before activation could commit"
	case "device_unavailable":
		return "A selected device is unavailable"
	case "scope_changed":
		return "The organization or site changed"
	case "activation_window_expired":
		return "The activation window closed"
	case "canceled_by_operator":
		return "An operator canceled future activation"
	default:
		return "No reason reported"
	}
}

func canCancelSchedule(schedule windows.UpdateSchedule) bool {
	return schedule.Phase == "scheduled" || schedule.Phase == "waiting"
}

type UpdateScheduleRow struct {
	Schedule windows.UpdateSchedule `json:"-" xml:"-" yaml:"-"`
	Name     string                 `json:"-" xml:"-" yaml:"-"`
}

func (UpdateScheduleRow) String() string     { return "[protected Windows schedule row]" }
func (v UpdateScheduleRow) GoString() string { return v.String() }

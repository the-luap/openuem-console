package windows_views

import (
	"github.com/open-uem/openuem-console/internal/mdm/windows"
	"net/url"
	"time"
)

type UpdateAssignmentDraft struct {
	Form             url.Values                 `json:"-" xml:"-" yaml:"-"`
	Ring             windows.UpdateRingRevision `json:"-" xml:"-" yaml:"-"`
	Devices          []windows.DeviceMetadata   `json:"-" xml:"-" yaml:"-"`
	Scheduled        bool
	NotBefore        time.Time     `json:"-" xml:"-" yaml:"-"`
	ActivationWindow time.Duration `json:"-" xml:"-" yaml:"-"`
	Error            string
}

func (UpdateAssignmentDraft) String() string     { return "[protected Windows assignment draft]" }
func (v UpdateAssignmentDraft) GoString() string { return v.String() }

type UpdateRolloutRow struct {
	Device windows.DeviceMetadata  `json:"-" xml:"-" yaml:"-"`
	Detail windows.UpdateRunDetail `json:"-" xml:"-" yaml:"-"`
}

func (UpdateRolloutRow) String() string     { return "[protected Windows rollout row]" }
func (v UpdateRolloutRow) GoString() string { return v.String() }

func assignmentPath(draft UpdateAssignmentDraft) string {
	action := "assign"
	if draft.Scheduled {
		action = "schedule"
	}
	return "/windows/update-rings/" + draft.Ring.RingID + "/" + action
}

func assignmentTitle(draft UpdateAssignmentDraft, preview bool) string {
	if draft.Scheduled {
		if preview {
			return "Review Windows update schedule"
		}
		return "Schedule Windows update ring"
	}
	if preview {
		return "Review ring assignment"
	}
	return "Assign Windows update ring"
}

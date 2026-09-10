package windows_views

import (
	"github.com/open-uem/openuem-console/internal/mdm/windows"
	"net/url"
)

type UpdateAssignmentDraft struct {
	Form    url.Values                 `json:"-" xml:"-" yaml:"-"`
	Ring    windows.UpdateRingRevision `json:"-" xml:"-" yaml:"-"`
	Devices []windows.DeviceMetadata   `json:"-" xml:"-" yaml:"-"`
	Error   string
}

func (UpdateAssignmentDraft) String() string     { return "[protected Windows assignment draft]" }
func (v UpdateAssignmentDraft) GoString() string { return v.String() }

type UpdateRolloutRow struct {
	Device windows.DeviceMetadata  `json:"-" xml:"-" yaml:"-"`
	Detail windows.UpdateRunDetail `json:"-" xml:"-" yaml:"-"`
}

func (UpdateRolloutRow) String() string     { return "[protected Windows rollout row]" }
func (v UpdateRolloutRow) GoString() string { return v.String() }

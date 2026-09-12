package apple

import (
	"context"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

type UpdatePilotDeviceReadiness struct {
	DeviceID string `json:"-" xml:"-" yaml:"-"`
	Ready    bool   `json:"-" xml:"-" yaml:"-"`
	Reason   string `json:"-" xml:"-" yaml:"-"`
}

func (UpdatePilotDeviceReadiness) String() string {
	return "[protected Apple update pilot device readiness]"
}
func (r UpdatePilotDeviceReadiness) GoString() string { return r.String() }

type UpdatePilotReadiness struct {
	Progress UpdateGroupProgress          `json:"-" xml:"-" yaml:"-"`
	Devices  []UpdatePilotDeviceReadiness `json:"-" xml:"-" yaml:"-"`
	Ready    int                          `json:"-" xml:"-" yaml:"-"`
	Blocked  int                          `json:"-" xml:"-" yaml:"-"`
	AllReady bool                         `json:"-" xml:"-" yaml:"-"`
}

func (UpdatePilotReadiness) String() string     { return "[protected Apple update pilot readiness]" }
func (r UpdatePilotReadiness) GoString() string { return r.String() }

// Readiness is observed success for every original enrollment, independent of
// notification acknowledgment and deadline timing. It does not attribute an OS
// installation to the pilot assignment or approve any destination group.
func assessUpdatePilotDevice(d UpdateGroupDeviceProgress) UpdatePilotDeviceReadiness {
	r := UpdatePilotDeviceReadiness{DeviceID: d.DeviceID}
	switch {
	case d.Availability != "available":
		r.Reason = "device_unavailable"
	case d.ExceptionActive:
		r.Reason = "exception_active"
	case d.PolicyState == "absent":
		r.Reason = "policy_absent"
	case d.PolicyState == "different":
		r.Reason = "policy_different"
	case d.PolicyState != "matches":
		r.Reason = "policy_unverified"
	case d.PolicyHasError:
		r.Reason = "policy_error"
	case d.RecordedAt == nil:
		r.Reason = "os_unverified"
	case d.Result == "update_required":
		r.Reason = "update_required"
	case d.Result != "target_reported":
		r.Reason = "os_unverified"
	case d.RecordedAt.Before(updatePilotExceptionEnd(d.Exception)):
		r.Reason = "awaiting_post_exception_report"
	default:
		r.Ready = true
	}
	return r
}
func updatePilotExceptionEnd(e *UpdateException) time.Time {
	if e != nil {
		if e.Kind == "resume" {
			return e.CreatedAt
		}
		if e.Kind == "pause" && e.ExpiresAt != nil {
			return *e.ExpiresAt
		}
	}
	return time.Time{}
}
func assessUpdatePilotReadiness(p *UpdateGroupProgress) *UpdatePilotReadiness {
	r := &UpdatePilotReadiness{Progress: *p, Devices: make([]UpdatePilotDeviceReadiness, 0, len(p.Devices))}
	for _, d := range p.Devices {
		result := assessUpdatePilotDevice(d)
		r.Devices = append(r.Devices, result)
		if result.Ready {
			r.Ready++
		} else {
			r.Blocked++
		}
	}
	// An empty or incomplete cohort cannot provide positive rollout evidence.
	r.AllReady = len(p.Devices) > 0 && len(p.Devices) == len(p.Assignment.Commands) && r.Blocked == 0
	return r
}
func (s *Store) ReviewUpdatePilotReadiness(ctx context.Context, actor string, permissions *access.Store, scope Scope, planID, assignmentID string) (*UpdatePilotReadiness, error) {
	if !profileRevisionUUID(planID) || !profileRevisionUUID(assignmentID) {
		return nil, ErrUpdatePlanGroup
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = updateExceptionAuthority(ctx, tx, permissions, actor, scope); err != nil {
		return nil, err
	}
	p, err := s.assessUpdateGroupProgressTransaction(ctx, tx, scope, planID, assignmentID)
	if err != nil {
		return nil, err
	}
	r := assessUpdatePilotReadiness(p)
	if err = auditUpdatePlan(ctx, tx, scope, actor, "pilot.readiness", assignmentID, p.Assignment.Plan.Revision); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return r, nil
}

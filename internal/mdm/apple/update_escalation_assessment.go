package apple

import (
	"context"
	"errors"
	"time"

	"github.com/open-uem/openuem-console/internal/security/access"
)

type UpdateEscalationDecision struct {
	DeviceID string `json:"-" xml:"-" yaml:"-"`
	State    string `json:"-" xml:"-" yaml:"-"`
	Reason   string `json:"-" xml:"-" yaml:"-"`
}

func (UpdateEscalationDecision) String() string {
	return "[protected Apple update escalation decision]"
}
func (v UpdateEscalationDecision) GoString() string { return v.String() }

type UpdateGroupEscalationReview struct {
	PreviewUnavailable bool                       `json:"-" xml:"-" yaml:"-"`
	Current            *UpdateEscalation          `json:"-" xml:"-" yaml:"-"`
	Progress           UpdateGroupProgress        `json:"-" xml:"-" yaml:"-"`
	Decisions          []UpdateEscalationDecision `json:"-" xml:"-" yaml:"-"`
	NeedsAttention     int                        `json:"-" xml:"-" yaml:"-"`
	Suppressed         int                        `json:"-" xml:"-" yaml:"-"`
	Pending            int                        `json:"-" xml:"-" yaml:"-"`
	Unverified         int                        `json:"-" xml:"-" yaml:"-"`
}

func (UpdateGroupEscalationReview) String() string {
	return "[protected Apple update escalation review]"
}
func (v UpdateGroupEscalationReview) GoString() string { return v.String() }

// The input is the locked, current original-cohort assessment. Unknown evidence
// cannot establish recovery or an actionable overdue result. A report from
// before an approved exception ended cannot establish a new escalation either.
func assessUpdateEscalation(d UpdateGroupDeviceProgress) UpdateEscalationDecision {
	r := UpdateEscalationDecision{DeviceID: d.DeviceID, State: "unverified"}
	switch {
	case d.Availability != "available":
		r.Reason = "device_unavailable"
	case d.ExceptionActive:
		r.State, r.Reason = "suppressed", "exception_active"
	case d.PolicyState == "different":
		r.State, r.Reason = "suppressed", "policy_different"
	case d.PolicyState == "absent":
		r.State, r.Reason = "suppressed", "policy_absent"
	case d.PolicyState != "matches":
		r.Reason = "policy_unverified"
	case d.Result == "target_reported":
		r.State, r.Reason = "suppressed", "target_reported"
	case d.Result != "update_required" || d.RecordedAt == nil:
		r.Reason = "os_unverified"
	case d.Deadline == nil || d.Deadline.State == "unverified" || d.Deadline.Latest == nil:
		r.Reason = "deadline_unverified"
	case d.Deadline.State == "pending":
		r.State, r.Reason = "pending", "deadline_pending"
	case d.Deadline.State != "elapsed":
		r.Reason = "deadline_unverified"
	case d.RecordedAt.Before(*d.Deadline.Latest):
		r.Reason = "awaiting_post_deadline_report"
	default:
		var exceptionEnded time.Time
		if d.Exception != nil {
			if d.Exception.Kind == "resume" {
				exceptionEnded = d.Exception.CreatedAt
			}
			if d.Exception.Kind == "pause" && d.Exception.ExpiresAt != nil {
				exceptionEnded = *d.Exception.ExpiresAt
			}
		}
		if d.RecordedAt.Before(exceptionEnded) {
			r.Reason = "awaiting_post_exception_report"
		} else {
			r.State, r.Reason = "attention", "update_required_after_deadline"
		}
	}
	return r
}

func assessUpdateGroupEscalation(progress *UpdateGroupProgress) *UpdateGroupEscalationReview {
	r := &UpdateGroupEscalationReview{Progress: *progress, Decisions: make([]UpdateEscalationDecision, 0, len(progress.Devices))}
	for _, device := range progress.Devices {
		d := assessUpdateEscalation(device)
		r.Decisions = append(r.Decisions, d)
		switch d.State {
		case "attention":
			r.NeedsAttention++
		case "suppressed":
			r.Suppressed++
		case "pending":
			r.Pending++
		default:
			r.Unverified++
		}
	}
	return r
}

func (s *Store) ReviewUpdateGroupEscalation(ctx context.Context, actor string, permissions *access.Store, scope Scope, planID, id string) (*UpdateGroupEscalationReview, error) {
	if !profileRevisionUUID(planID) || !profileRevisionUUID(id) {
		return nil, ErrUpdatePlanGroup
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = updatePlanAuthority(ctx, tx, permissions, actor, scope, access.ManageUpdates); err != nil {
		return nil, err
	}
	if err = permissions.AuthorizeTransaction(ctx, tx, actor, access.ReadDevices, access.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID}); err != nil {
		return nil, err
	}
	current, err := s.escalationForAssignment(ctx, tx, scope, planID, id, " FOR SHARE")
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `SAVEPOINT apple_update_escalation_preview`); err != nil {
		return nil, err
	}
	p, err := s.assessUpdateGroupProgressTransaction(ctx, tx, scope, planID, id)
	unavailable := err != nil
	if err != nil {
		if current == nil || !escalationSourceUnavailable(err) {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT apple_update_escalation_preview`); err != nil {
			return nil, err
		}
		p = &UpdateGroupProgress{Assignment: *current.Assignment}
		if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&p.AssessedAt); err != nil {
			return nil, err
		}
	}
	r := assessUpdateGroupEscalation(p)
	r.PreviewUnavailable = unavailable
	r.Current = current
	if err = auditUpdatePlan(ctx, tx, scope, actor, "group.escalation.preview", id, p.Assignment.Plan.Revision); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return r, nil
}

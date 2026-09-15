package apple

import (
	"slices"
	"time"
	"unicode/utf8"
)

type UpdateEscalationEvidence struct {
	Decision         UpdateEscalationDecision  `json:"-" xml:"-" yaml:"-"`
	Observation      *OSObservation            `json:"-" xml:"-" yaml:"-"`
	Deadline         *UpdateDeadlineAssessment `json:"-" xml:"-" yaml:"-"`
	ExceptionEndedAt *time.Time                `json:"-" xml:"-" yaml:"-"`
}

func (UpdateEscalationEvidence) String() string {
	return "[protected Apple update escalation evidence]"
}
func (v UpdateEscalationEvidence) GoString() string { return v.String() }

type UpdateEscalationSnapshot struct {
	AssessedAt time.Time                  `json:"-" xml:"-" yaml:"-"`
	Devices    []UpdateEscalationEvidence `json:"-" xml:"-" yaml:"-"`
}

func (UpdateEscalationSnapshot) String() string {
	return "[protected Apple update escalation snapshot]"
}
func (v UpdateEscalationSnapshot) GoString() string { return v.String() }

type updateEscalationEvidenceWire struct {
	DeviceID, State, Reason       string
	Version, Build, Source        string
	RecordedAt                    *time.Time
	DeadlineState, DeadlineReason string
	TimeZone, TimeZoneSource      string
	TimeZoneRecordedAt            *time.Time
	Earliest, Latest              *time.Time
	Ambiguous                     bool
	ExceptionEndedAt              *time.Time
}
type updateEscalationSnapshotWire struct {
	AssessedAt time.Time
	Devices    []updateEscalationEvidenceWire
}

func escalationSnapshot(review *UpdateGroupEscalationReview) *UpdateEscalationSnapshot {
	r := &UpdateEscalationSnapshot{AssessedAt: review.Progress.AssessedAt, Devices: make([]UpdateEscalationEvidence, 0, len(review.Decisions))}
	for i, d := range review.Progress.Devices {
		e := UpdateEscalationEvidence{Decision: review.Decisions[i], Deadline: d.Deadline}
		if d.RecordedAt != nil {
			e.Observation = &OSObservation{Version: d.ReportedVersion, Build: d.ReportedBuild, Source: d.ReportSource, RecordedAt: *d.RecordedAt}
		}
		if d.Exception != nil && !d.ExceptionActive {
			if d.Exception.Kind == "pause" {
				e.ExceptionEndedAt = d.Exception.ExpiresAt
			} else if d.Exception.Kind == "resume" {
				e.ExceptionEndedAt = &d.Exception.CreatedAt
			}
		}
		r.Devices = append(r.Devices, e)
	}
	return r
}

func escalationSnapshotWire(snapshot *UpdateEscalationSnapshot) *updateEscalationSnapshotWire {
	if snapshot == nil {
		return nil
	}
	wire := &updateEscalationSnapshotWire{AssessedAt: snapshot.AssessedAt, Devices: make([]updateEscalationEvidenceWire, 0, len(snapshot.Devices))}
	for _, e := range snapshot.Devices {
		w := updateEscalationEvidenceWire{DeviceID: e.Decision.DeviceID, State: e.Decision.State, Reason: e.Decision.Reason, ExceptionEndedAt: e.ExceptionEndedAt}
		if o := e.Observation; o != nil {
			w.Version, w.Build, w.Source, w.RecordedAt = o.Version, o.Build, o.Source, &o.RecordedAt
		}
		if d := e.Deadline; d != nil {
			w.DeadlineState, w.DeadlineReason, w.Earliest, w.Latest, w.Ambiguous = d.State, d.Reason, d.Earliest, d.Latest, d.Ambiguous
			if z := d.TimeZone; z != nil {
				w.TimeZone, w.TimeZoneSource, w.TimeZoneRecordedAt = z.Name, z.Source, &z.RecordedAt
			}
		}
		wire.Devices = append(wire.Devices, w)
	}
	return wire
}

func validUpdateEscalationDecision(state, reason string) bool {
	want := ""
	switch reason {
	case "update_required_after_deadline":
		want = "attention"
	case "exception_active", "policy_different", "policy_absent", "target_reported":
		want = "suppressed"
	case "deadline_pending":
		want = "pending"
	case "device_unavailable", "policy_unverified", "os_unverified", "deadline_unverified", "awaiting_post_deadline_report", "awaiting_post_exception_report":
		want = "unverified"
	}
	return want != "" && state == want
}

// Historical estimates retain the server rules used at assessment time. Loading
// an older receipt must not recalculate its UTC deadline with newer zone rules.
func decodeEscalationSnapshot(wire *updateEscalationSnapshotWire, original []string) (*UpdateEscalationSnapshot, error) {
	if wire == nil {
		return nil, nil
	}
	if wire.AssessedAt.IsZero() || len(wire.Devices) != len(original) || len(original) < 1 || len(original) > 100 || !slices.IsSorted(original) {
		return nil, ErrUpdateEscalationIntegrity
	}
	for i, id := range original {
		if !profileRevisionUUID(id) || (i > 0 && id == original[i-1]) {
			return nil, ErrUpdateEscalationIntegrity
		}
	}
	r := &UpdateEscalationSnapshot{AssessedAt: wire.AssessedAt, Devices: make([]UpdateEscalationEvidence, 0, len(original))}
	for i, w := range wire.Devices {
		if w.DeviceID != original[i] || !validUpdateEscalationDecision(w.State, w.Reason) || len(w.Version) > 32 || len(w.Build) > 32 || !utf8.ValidString(w.Version) || !utf8.ValidString(w.Build) {
			return nil, ErrUpdateEscalationIntegrity
		}
		e := UpdateEscalationEvidence{Decision: UpdateEscalationDecision{DeviceID: w.DeviceID, State: w.State, Reason: w.Reason}, ExceptionEndedAt: w.ExceptionEndedAt}
		if w.ExceptionEndedAt != nil && w.ExceptionEndedAt.After(wire.AssessedAt) {
			return nil, ErrUpdateEscalationIntegrity
		}
		if w.RecordedAt != nil {
			if w.Source != "device_information" && w.Source != "declarative_status" {
				return nil, ErrUpdateEscalationIntegrity
			}
			e.Observation = &OSObservation{Version: w.Version, Build: w.Build, Source: w.Source, RecordedAt: *w.RecordedAt}
		} else if w.Version != "" || w.Build != "" || w.Source != "" {
			return nil, ErrUpdateEscalationIntegrity
		}
		d := &UpdateDeadlineAssessment{State: w.DeadlineState, Reason: w.DeadlineReason, Earliest: w.Earliest, Latest: w.Latest, Ambiguous: w.Ambiguous, AssessedAt: wire.AssessedAt}
		if w.TimeZoneRecordedAt != nil {
			if len(w.TimeZone) < 1 || len(w.TimeZone) > 128 || !utf8.ValidString(w.TimeZone) || w.TimeZoneSource != "device_information" {
				return nil, ErrUpdateEscalationIntegrity
			}
			d.TimeZone = &TimeZoneObservation{Name: w.TimeZone, Source: w.TimeZoneSource, RecordedAt: *w.TimeZoneRecordedAt}
		} else if w.TimeZone != "" || w.TimeZoneSource != "" {
			return nil, ErrUpdateEscalationIntegrity
		}
		switch w.DeadlineState {
		case "unverified":
			if w.Earliest != nil || w.Latest != nil || w.Ambiguous {
				return nil, ErrUpdateEscalationIntegrity
			}
			switch w.DeadlineReason {
			case "device_unavailable", "no_timezone", "future_timezone", "stale_timezone", "invalid_timezone", "unresolved_local_time":
			default:
				return nil, ErrUpdateEscalationIntegrity
			}
		case "elapsed", "pending":
			if d.TimeZone == nil || w.Earliest == nil || w.Latest == nil || w.Latest.Before(*w.Earliest) || w.Latest.Sub(*w.Earliest) > 48*time.Hour || w.Ambiguous != w.Earliest.Before(*w.Latest) || w.DeadlineReason != "" || d.TimeZone.RecordedAt.After(wire.AssessedAt) || wire.AssessedAt.Sub(d.TimeZone.RecordedAt) > 24*time.Hour || (w.DeadlineState == "elapsed") != !wire.AssessedAt.Before(*w.Latest) {
				return nil, ErrUpdateEscalationIntegrity
			}
		default:
			return nil, ErrUpdateEscalationIntegrity
		}
		e.Deadline = d
		if w.State == "attention" {
			if e.Observation == nil || !versionPattern.MatchString(e.Observation.Version) || e.Observation.RecordedAt.After(wire.AssessedAt) || wire.AssessedAt.Sub(e.Observation.RecordedAt) > 24*time.Hour || d.State != "elapsed" || e.Observation.RecordedAt.Before(*d.Latest) || (e.ExceptionEndedAt != nil && e.Observation.RecordedAt.Before(*e.ExceptionEndedAt)) {
				return nil, ErrUpdateEscalationIntegrity
			}
		}
		r.Devices = append(r.Devices, e)
	}
	return r, nil
}

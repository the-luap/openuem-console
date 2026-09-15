package apple

import (
	"regexp"
	"strings"
	"time"
	_ "time/tzdata"
)

type TimeZoneObservation struct {
	Name       string    `json:"-" xml:"-" yaml:"-"`
	Source     string    `json:"-" xml:"-" yaml:"-"`
	RecordedAt time.Time `json:"-" xml:"-" yaml:"-"`
}

type UpdateDeadlineAssessment struct {
	State      string               `json:"-" xml:"-" yaml:"-"`
	Reason     string               `json:"-" xml:"-" yaml:"-"`
	TimeZone   *TimeZoneObservation `json:"-" xml:"-" yaml:"-"`
	Earliest   *time.Time           `json:"-" xml:"-" yaml:"-"`
	Latest     *time.Time           `json:"-" xml:"-" yaml:"-"`
	Ambiguous  bool                 `json:"-" xml:"-" yaml:"-"`
	AssessedAt time.Time            `json:"-" xml:"-" yaml:"-"`
}

func (TimeZoneObservation) String() string     { return "[protected Apple time zone observation]" }
func (v TimeZoneObservation) GoString() string { return v.String() }
func (UpdateDeadlineAssessment) String() string {
	return "[protected Apple update deadline assessment]"
}
func (v UpdateDeadlineAssessment) GoString() string { return v.String() }

var reportedTimeZoneName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_+\-]*(/[A-Za-z0-9_+\-]+)*$`)

func reportedTimeZoneLocation(name string) (*time.Location, bool) {
	if len(name) > 128 || !reportedTimeZoneName.MatchString(name) || name == "Local" || name == "localtime" || name == "Factory" || name == "posixrules" || strings.HasPrefix(name, "posix/") || strings.HasPrefix(name, "right/") {
		return nil, false
	}
	location, err := time.LoadLocation(name)
	return location, err == nil
}

// localDeadlineWindow enumerates zone transitions instead of accepting
// ParseInLocation's arbitrary choice for a repeated or nonexistent wall time.
// The bounded window exceeds every IANA civil offset; a gap has no candidate.
func localDeadlineWindow(raw string, location *time.Location) (first, last time.Time, ambiguous, ok bool) {
	const layout = "2006-01-02T15:04:05"
	wall, err := time.Parse(layout, raw)
	if err != nil || len(raw) != 19 || wall.Format(layout) != raw || location == nil {
		return first, last, false, false
	}
	cursor, limit := wall.Add(-48*time.Hour), wall.Add(48*time.Hour)
	offsets := map[int]bool{}
	for range 16 {
		_, offset := cursor.In(location).Zone()
		offsets[offset] = true
		_, end := cursor.In(location).ZoneBounds()
		if end.IsZero() || end.After(limit) {
			for offset := range offsets {
				candidate := wall.Add(-time.Duration(offset) * time.Second)
				if candidate.In(location).Format(layout) != raw {
					continue
				}
				if !ok {
					first, last, ok = candidate, candidate, true
					continue
				}
				if candidate.Before(first) {
					first = candidate
				}
				if candidate.After(last) {
					last = candidate
				}
			}
			return first, last, ok && !first.Equal(last), ok
		}
		if !end.After(cursor) {
			return first, last, false, false
		}
		cursor = end
	}
	return first, last, false, false
}

// This is an estimate using the last reported zone and server time-zone rules.
// OS evidence remains independent, and no device-local clock value is invented.
func assessUpdateDeadline(available bool, policy *UpdatePolicy, zone *TimeZoneObservation, now time.Time) *UpdateDeadlineAssessment {
	if policy == nil {
		return nil
	}
	a := &UpdateDeadlineAssessment{State: "unverified", TimeZone: zone, AssessedAt: now}
	switch {
	case !available:
		a.Reason = "device_unavailable"
	case zone == nil:
		a.Reason = "no_timezone"
	case zone.RecordedAt.After(now):
		a.Reason = "future_timezone"
	case now.Sub(zone.RecordedAt) > 24*time.Hour:
		a.Reason = "stale_timezone"
	default:
		location, valid := reportedTimeZoneLocation(zone.Name)
		if !valid {
			a.Reason = "invalid_timezone"
			return a
		}
		first, last, ambiguous, valid := localDeadlineWindow(policy.Deadline, location)
		if !valid {
			a.Reason = "unresolved_local_time"
			return a
		}
		a.Earliest, a.Latest, a.Ambiguous = &first, &last, ambiguous
		a.State = "pending"
		if !now.Before(last) {
			a.State = "elapsed"
		}
	}
	return a
}

package mdm_views

import (
	"strings"
	"time"

	"github.com/open-uem/openuem-console/internal/mdm/apple"
)

// These fixed render fixtures accompany the real time-zone/DST and protocol
// assessments in the Apple package. They do not substitute for those checks.
func ownedDeadlineViewFixture(state string, now time.Time) (*apple.UpdateDeadlineAssessment, string) {
	a := &apple.UpdateDeadlineAssessment{State: "unverified", Reason: "no_timezone", AssessedAt: now}
	if !strings.HasPrefix(state, "deadline-") {
		if state == "unmanaged" || state == "unavailable" {
			a.Reason = "device_unavailable"
		}
		return a, ""
	}
	a.TimeZone = &apple.TimeZoneObservation{Name: "UTC", Source: "device_information", RecordedAt: now.Add(-time.Minute)}
	deadline := now.Add(time.Hour)
	local := deadline.Format("2006-01-02T15:04:05")
	switch state {
	case "deadline-pending":
		a.State, a.Reason, a.Earliest, a.Latest = "pending", "", &deadline, &deadline
	case "deadline-elapsed":
		deadline = now.Add(-time.Hour)
		local = deadline.Format("2006-01-02T15:04:05")
		a.State, a.Reason, a.Earliest, a.Latest = "elapsed", "", &deadline, &deadline
	case "deadline-stale":
		a.Reason, a.TimeZone.RecordedAt = "stale_timezone", now.Add(-25*time.Hour)
	case "deadline-future":
		a.Reason, a.TimeZone.RecordedAt = "future_timezone", now.Add(time.Hour)
	case "deadline-invalid":
		a.Reason, a.TimeZone.Name = "invalid_timezone", strings.Repeat("Z", 110)+"<script>"
	case "deadline-gap":
		a.Reason, a.TimeZone.Name = "unresolved_local_time", "Europe/Berlin"
		local = "2026-03-29T02:30:00"
	case "deadline-fold":
		first := time.Date(2026, 10, 25, 0, 30, 0, 0, time.UTC)
		last := first.Add(time.Hour)
		a.State, a.Reason, a.TimeZone.Name = "pending", "", "Europe/Berlin"
		a.Earliest, a.Latest, a.Ambiguous = &first, &last, true
		local = "2026-10-25T02:30:00"
	}
	return a, local
}

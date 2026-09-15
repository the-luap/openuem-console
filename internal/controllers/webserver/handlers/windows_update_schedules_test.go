package handlers

import (
	"net/url"
	"testing"
	"time"
)

func TestWindowsScheduleTimingIsExplicitUTCAndIndependentOfCurrentTime(t *testing.T) {
	form := url.Values{"not_before": {"2020-02-29T23:45"}, "activation_minutes": {"90"}}
	start, window, err := parseWindowsScheduleTiming(form)
	if err != nil || start.Location() != time.UTC || start.Format(time.RFC3339) != "2020-02-29T23:45:00Z" || window != 90*time.Minute || start.Add(window).Format(time.RFC3339) != "2020-03-01T01:15:00Z" {
		t.Fatal("UTC activation intent changed", err)
	}
	// Static parsing must preserve an old request for the store's exact replay
	// check; new admission, unlike replay, checks the current database clock.
	for _, value := range []string{"1", "10080"} {
		form.Set("activation_minutes", value)
		if _, _, err := parseWindowsScheduleTiming(form); err != nil {
			t.Fatal("supported window rejected", value, err)
		}
	}
}

func TestWindowsScheduleTimingRejectsAmbiguousOrOutOfRangeInput(t *testing.T) {
	for _, value := range []string{"", "2026-09-10", "2026-09-10 12:00", "2026-09-10T12:00Z", "2026-09-10T12:00+02:00", "2026-09-10T12:00:00", "2026-09-10T12:00:00.001", "2026-02-29T12:00", "2026-09-10T24:00", "0000-01-01T12:00", "0001-01-01T00:00", "2026-9-10T12:00"} {
		if _, _, err := parseWindowsScheduleTiming(url.Values{"not_before": {value}, "activation_minutes": {"60"}}); err == nil {
			t.Fatal("ambiguous activation time admitted", value)
		}
	}
	for _, value := range []string{"", "0", "-1", "10081", "060", "1.5", "1e2", "+60", "99999999999999999999999999"} {
		if _, _, err := parseWindowsScheduleTiming(url.Values{"not_before": {"2026-09-10T12:00"}, "activation_minutes": {value}}); err == nil {
			t.Fatal("ambiguous activation window admitted", value)
		}
	}
}

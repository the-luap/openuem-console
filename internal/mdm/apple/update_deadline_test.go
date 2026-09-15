package apple

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAppleLocalDeadlineResolvesDSTGapsAndRepeatedTimes(t *testing.T) {
	for _, tc := range []struct{ zone, local, first, last string }{
		{"UTC", "2026-10-01T18:00:00", "2026-10-01T18:00:00Z", "2026-10-01T18:00:00Z"},
		{"Europe/Berlin", "2026-10-25T02:30:00", "2026-10-25T00:30:00Z", "2026-10-25T01:30:00Z"},
		{"Europe/Berlin", "2026-03-29T02:30:00", "", ""},
		{"Australia/Lord_Howe", "2026-04-05T01:45:00", "2026-04-04T14:45:00Z", "2026-04-04T15:15:00Z"},
		{"Pacific/Kiritimati", "1994-12-31T12:00:00", "", ""},
		{"Asia/Kathmandu", "2026-10-01T18:00:00", "2026-10-01T12:15:00Z", "2026-10-01T12:15:00Z"},
		{"UTC", "2026-02-30T18:00:00", "", ""},
		{"UTC", "2026-10-01T18:00:00.5", "", ""},
	} {
		t.Run(tc.zone+"/"+tc.local, func(t *testing.T) {
			location, ok := reportedTimeZoneLocation(tc.zone)
			require.True(t, ok)
			first, last, ambiguous, ok := localDeadlineWindow(tc.local, location)
			if tc.first == "" {
				require.False(t, ok)
				return
			}
			require.True(t, ok)
			require.Equal(t, tc.first, first.Format(time.RFC3339))
			require.Equal(t, tc.last, last.Format(time.RFC3339))
			require.Equal(t, tc.first != tc.last, ambiguous)
		})
	}
}

func TestAppleDeadlineUsesFreshZoneAndLatestAmbiguousInstant(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	zone := &TimeZoneObservation{Name: "Europe/Berlin", RecordedAt: now.Add(-time.Minute)}
	policy := &UpdatePolicy{Deadline: "2026-10-25T02:30:00"}
	a := assessUpdateDeadline(true, policy, zone, now)
	require.Equal(t, "pending", a.State)
	require.True(t, a.Ambiguous)
	require.Equal(t, "elapsed", assessUpdateDeadline(true, policy, zone, now.Add(30*time.Minute)).State)
	require.Nil(t, assessUpdateDeadline(true, nil, zone, now))
	require.Equal(t, "device_unavailable", assessUpdateDeadline(false, policy, zone, now).Reason)
	require.Equal(t, "no_timezone", assessUpdateDeadline(true, policy, nil, now).Reason)
	zone.RecordedAt = now.Add(time.Second)
	require.Equal(t, "future_timezone", assessUpdateDeadline(true, policy, zone, now).Reason)
	zone.RecordedAt = now.Add(-25 * time.Hour)
	require.Equal(t, "stale_timezone", assessUpdateDeadline(true, policy, zone, now).Reason)
	zone.RecordedAt = now
	zone.Name = "Local"
	require.Equal(t, "invalid_timezone", assessUpdateDeadline(true, policy, zone, now).Reason)
	for _, value := range []any{a, zone} {
		body, err := json.Marshal(value)
		require.NoError(t, err)
		require.JSONEq(t, `{}`, string(body))
		require.NotContains(t, fmt.Sprintf("%#v", value), "Europe/Berlin")
	}
}

func TestAppleReportedTimeZoneRejectsServerAliasesAndPaths(t *testing.T) {
	for _, name := range []string{"", "Local", "localtime", "Factory", "posixrules", "posix/UTC", "right/UTC", "../UTC", "/Europe/Berlin", ":UTC", "Europe\\Berlin", "Unknown/Zone", strings.Repeat("a", 129)} {
		_, ok := reportedTimeZoneLocation(name)
		require.False(t, ok, "unusable device time zone was accepted")
	}
}

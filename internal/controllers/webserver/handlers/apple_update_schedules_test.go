package handlers

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

func TestAppleUpdateScheduleTimingRequiresExactUTCAndBoundedWindow(t *testing.T) {
	for _, raw := range []string{"2026-09-15T18:00:00Z", "2026-09-15T18:00:00", "2026-09-15T18:00:00+02:00", "2026-09-15T18:00:00.1Z", "2026-02-30T18:00:00Z", "2026-09-15T18:00Z", " 2026-09-15T18:00:00Z"} {
		at, window, err := appleUpdateScheduleTiming(url.Values{"not_before": {raw}, "activation_window_minutes": {"60"}})
		if raw == "2026-09-15T18:00:00Z" {
			require.NoError(t, err)
			require.Equal(t, time.Hour, window)
			require.Equal(t, raw, at.Format(time.RFC3339))
		} else {
			require.Error(t, err)
		}
	}
	for _, raw := range []string{"0", "-1", "1.5", "10081", "01", "", "9999999999999"} {
		_, _, err := appleUpdateScheduleTiming(url.Values{"not_before": {"2026-09-15T18:00:00Z"}, "activation_window_minutes": {raw}})
		require.Error(t, err)
	}
}
func TestAppleUpdateScheduleFormsRejectAmbiguousAndOversizedBodies(t *testing.T) {
	allowed := []string{"csrf", "expected_revision", "group_id", "group_revision", "request_key", "devices", "confirmed", "not_before", "activation_window_minutes"}
	valid := url.Values{"csrf": {"owned-csrf"}, "expected_revision": {"1"}, "group_id": {"20000000-0000-4000-8000-000000000001"}, "group_revision": {"1"}, "request_key": {"30000000-0000-4000-8000-000000000001"}, "devices": {"10000000-0000-4000-8000-000000000001:" + strings.Repeat("a", 64)}, "confirmed": {"yes"}, "not_before": {"2026-09-15T18:00:00Z"}, "activation_window_minutes": {"60"}}
	for _, condition := range []string{"valid", "duplicate", "unknown", "query", "oversized", "encoding"} {
		body, path := valid.Encode(), "/ios/update-plans/owned/schedules"
		switch condition {
		case "duplicate":
			body += "&not_before=2026-09-16T18%3A00%3A00Z"
		case "unknown":
			body += "&remove=true"
		case "query":
			path += "?confirmed=yes"
		case "oversized":
			body += strings.Repeat("&", 16385)
		case "encoding":
			body += "&bad=%xx"
		}
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		c := echo.New().NewContext(r, httptest.NewRecorder())
		c.Set("csrf", "owned-csrf")
		f, err := boundedDeviceManagementForm(c, "apple_update_schedules.invalid", allowed, 16<<10)
		if condition == "valid" {
			require.NoError(t, err)
			require.Equal(t, valid, f)
		} else {
			require.Error(t, err)
			require.Nil(t, f)
		}
	}
}

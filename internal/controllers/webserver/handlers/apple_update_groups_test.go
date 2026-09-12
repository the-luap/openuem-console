package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

func TestAppleUpdateGroupFormFitsCompleteReviewedSelection(t *testing.T) {
	targets := make([]string, 100)
	for i := range targets {
		targets[i] = fmt.Sprintf("10000000-0000-4000-8000-%012d:%s", i, strings.Repeat("a", 64))
	}
	fields := url.Values{"csrf": {"owned-csrf"}, "expected_revision": {"1"}, "group_id": {"20000000-0000-4000-8000-000000000001"}, "group_revision": {"1"}, "request_key": {"30000000-0000-4000-8000-000000000001"}, "devices": {strings.Join(targets, "\n")}, "confirmed": {"yes"}}
	body := fields.Encode()
	require.Greater(t, len(body), 8192)
	require.Less(t, len(body), 16384)
	for _, limit := range []int64{8192, 16384} {
		r := httptest.NewRequest(http.MethodPost, "/ios/update-plans/owned/group-assignments", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		c := echo.New().NewContext(r, httptest.NewRecorder())
		c.Set("csrf", "owned-csrf")
		f, err := boundedDeviceManagementForm(c, "apple_update_groups.invalid", []string{"csrf", "expected_revision", "group_id", "group_revision", "request_key", "devices", "confirmed"}, limit)
		if limit == 16384 {
			require.NoError(t, err)
			require.Equal(t, fields, f)
		} else {
			require.Error(t, err)
		}
	}
}

package handlers

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func exerciseDeviceExports(t *testing.T, tenant, site, otherTenant, otherSite int, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	base := fmt.Sprintf("/tenant/%d/site/%d/devices/export", tenant, site)
	for _, actor := range []string{"apple-console-admin", "organization-admin", "scoped-operator", "scoped-viewer"} {
		for _, format := range []string{"csv", "json"} {
			w := request(actor, "POST", base, url.Values{"format": {format}, "q": {"Finance Windows"}, "platform": {"windows"}, "sort": {"recent"}})
			require.Equal(t, 200, w.Code, "export failed for %s/%s", actor, format)
			require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
			require.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
			require.True(t, strings.HasPrefix(w.Header().Get("Content-Disposition"), `attachment; filename="openuem-devices-`))
			require.True(t, strings.HasSuffix(w.Header().Get("Content-Disposition"), "."+format+`"`))
			for _, canary := range []string{"private-inventory-notes", "private-inventory-description", "private-inventory-task-output"} {
				require.NotContains(t, w.Body.String(), canary)
			}
			if format == "json" {
				var rows []map[string]any
				require.NoError(t, json.Unmarshal(w.Body.Bytes(), &rows))
				require.Len(t, rows, 1)
				require.Equal(t, "windows-fixture", rows[0]["device_id"])
				require.Equal(t, float64(site), rows[0]["site_id"])
			}
		}
	}
	for _, form := range []url.Values{{"format": {"yaml"}}, {"format": {"csv", "json"}}, {"format": {"json"}, "after": {"owned-position"}}, {"format": {"json"}, "sort": {"invalid"}}, {"format": {"json"}, "q": {"a", "b"}}} {
		w := request("scoped-viewer", "POST", base, form)
		require.Equal(t, 400, w.Code)
		require.Empty(t, w.Header().Get("Content-Disposition"))
	}
	w := request("scoped-viewer", "POST", base+"?q=another", url.Values{"format": {"json"}})
	require.Equal(t, 400, w.Code)
	w = request("scoped-viewer", "POST", base, url.Values{"format": {"json"}, "csrf": {"wrong"}})
	require.Equal(t, 403, w.Code)
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	w = request("scoped-viewer", "POST", fmt.Sprintf("/tenant/%d/site/%d/devices/export", otherTenant, otherSite), url.Values{"format": {"json"}})
	require.Equal(t, 404, w.Code, "a foreign organization must remain hidden")
	require.Empty(t, w.Header().Get("Content-Disposition"))
	w = request("apple-console-admin", "GET", base, nil)
	require.Equal(t, 405, w.Code)
	require.Equal(t, "POST", w.Header().Get("Allow"))
}

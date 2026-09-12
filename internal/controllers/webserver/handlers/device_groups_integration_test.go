package handlers

import (
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func exerciseDeviceGroups(t *testing.T, tenant, site, sibling, otherTenant, otherSite int, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	base := fmt.Sprintf("/tenant/%d/site/%d/device-groups", tenant, site)
	form := func(revision string) url.Values {
		v := url.Values{"name": {"Owned <group>"}, "description": {"Rule for Windows"}, "platform": {"windows"}, "q": {"Finance Windows"}}
		if revision != "" {
			v.Set("revision", revision)
		}
		return v
	}
	w := request("scoped-operator", "POST", base, form(""))
	require.Equal(t, 303, w.Code)
	detail := w.Header().Get("Location")
	require.True(t, strings.HasPrefix(detail, base+"/"))
	for _, actor := range []string{"apple-console-admin", "organization-admin", "scoped-operator", "scoped-viewer"} {
		w = request(actor, "GET", detail, nil)
		require.Equal(t, 200, w.Code, "group read failed for %s", actor)
		require.Contains(t, w.Body.String(), "Owned &lt;group&gt;")
		require.Contains(t, w.Body.String(), "Finance Windows")
		require.NotContains(t, w.Body.String(), "private-inventory-notes")
		require.Equal(t, actor != "scoped-viewer", strings.Contains(w.Body.String(), `name="revision" value="1"`))
		require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
		require.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
		w = request(actor, "GET", base, nil)
		require.Equal(t, 200, w.Code)
		require.Contains(t, w.Body.String(), "Owned &lt;group&gt;")
	}
	require.Equal(t, 403, request("scoped-viewer", "POST", base, form("")).Code)
	require.Equal(t, 403, request("scoped-viewer", "POST", detail, form("1")).Code)
	revised := form("1")
	revised.Set("archived", "true")
	require.Equal(t, 303, request("scoped-operator", "POST", detail, revised).Code)
	require.Equal(t, 409, request("scoped-operator", "POST", detail, form("1")).Code)
	require.Equal(t, 409, request("scoped-viewer", "GET", detail+"?revision=1", nil).Code)
	w = request("scoped-viewer", "GET", detail, nil)
	require.Equal(t, 200, w.Code)
	require.Contains(t, w.Body.String(), "This group is archived.")
	require.NotContains(t, w.Body.String(), "windows-fixture</a>")
	require.Equal(t, 303, request("organization-admin", "POST", detail, form("2")).Code)
	for _, query := range []string{"?revision=0", "?revision=01", "?revision=1&revision=2", "?revision=%zz", "?platform=linux", "?after=x", "?history=-1", "?history=1"} {
		require.Equal(t, 400, request("scoped-viewer", "GET", detail+query, nil).Code, query)
	}
	for _, change := range []struct{ key, value string }{{"tenant_id", "99"}, {"name", ""}, {"revision", "+3"}, {"archived", "false"}, {"platform", "android"}} {
		v := form("3")
		v.Set(change.key, change.value)
		require.Equal(t, 400, request("scoped-operator", "POST", detail, v).Code)
	}
	duplicate := form("3")
	duplicate.Add("q", "another")
	require.Equal(t, 400, request("scoped-operator", "POST", detail, duplicate).Code)
	wrong := form("3")
	wrong.Set("csrf", "wrong")
	w = request("scoped-operator", "POST", detail, wrong)
	require.Equal(t, 403, w.Code)
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	require.Equal(t, 400, request("scoped-operator", "POST", detail+"?q=override", form("3")).Code)
	id := strings.TrimPrefix(detail, base+"/")
	for _, path := range []string{fmt.Sprintf("/tenant/%d/device-groups/%s", tenant, id), fmt.Sprintf("/tenant/%d/site/%d/device-groups/%s", tenant, sibling, id), fmt.Sprintf("/tenant/%d/site/%d/device-groups/%s", otherTenant, otherSite, id)} {
		require.Equal(t, 404, request("apple-console-admin", "GET", path, nil).Code)
		require.Equal(t, 404, request("apple-console-admin", "POST", path, form("3")).Code)
	}
	organization := fmt.Sprintf("/tenant/%d/device-groups", tenant)
	require.Equal(t, 403, request("scoped-operator", "POST", organization, form("")).Code)
	require.Equal(t, 303, request("organization-admin", "POST", organization, form("")).Code)
}

package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent/agent"
	"github.com/open-uem/ent/release"
	routerMiddleware "github.com/open-uem/openuem-console/internal/controllers/router/middleware"
	"github.com/stretchr/testify/require"
)

func exerciseDesktopTagAssignments(t *testing.T, h *Handler, e *echo.Echo, ctx context.Context, tenant, site, foreignTenant int) {
	t.Helper()
	device := "owned-desktop-tag-route"
	require.NoError(t, h.Model.Client.Agent.Create().SetID(device).SetHostname("Owned tagged desktop").SetOs("windows").SetAgentStatus(agent.AgentStatusEnabled).AddSiteIDs(site).Exec(ctx))
	defer h.Model.Client.Agent.DeleteOneID(device).Exec(ctx)
	tag, err := h.Model.Client.Tag.Create().SetTag("Owned route membership tag").SetColor("blue").SetTenantID(tenant).Save(ctx)
	require.NoError(t, err)
	defer h.Model.Client.Tag.DeleteOneID(tag.ID).Exec(ctx)
	foreign, err := h.Model.Client.Tag.Create().SetTag("Private route membership tag").SetColor("red").SetTenantID(foreignTenant).Save(ctx)
	require.NoError(t, err)
	defer h.Model.Client.Tag.DeleteOneID(foreign.ID).Exec(ctx)
	// The shared role fixture supplies a fixed form token. Wrap these HTMX
	// requests with the production header/cookie middleware as well.
	outer := echo.New()
	gate := routerMiddleware.CSRF()(func(c echo.Context) error {
		e.ServeHTTP(c.Response(), c.Request())
		return nil
	})
	request := func(actor, method, path string, form url.Values, token string) *httptest.ResponseRecorder {
		t.Helper()
		stampOwnedConsoleSession(t, h, ctx, actor)
		r := httptest.NewRequest(method, path, strings.NewReader(form.Encode())).WithContext(ctx)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		cookie := strings.Repeat("t", 32)
		if token == "console-test-token" {
			token = cookie
		}
		r.AddCookie(&http.Cookie{Name: "__Host-openuem-csrf", Value: cookie})
		r.Header.Set("X-CSRF-Token", token)
		r.Header.Set("HX-Request", "true")
		w := httptest.NewRecorder()
		c := outer.NewContext(r, w)
		if err := gate(c); err != nil {
			outer.HTTPErrorHandler(err, c)
		}
		return w
	}
	form := url.Values{"agentId": {device}, "tagId": {strconv.Itoa(tag.ID)}, "page": {"1"}, "pageSize": {"5"}, "sortBy": {"hostname"}, "sortOrder": {"asc"}}
	base := fmt.Sprintf("/tenant/%d/site/%d", tenant, site)
	count := func() int {
		var n int
		require.NoError(t, h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM agent_tags WHERE agent_id=$1`, device).Scan(&n))
		return n
	}
	for _, list := range []string{"/agents", "/computers"} {
		path := base + list
		for _, actor := range []string{"organization-admin", "scoped-operator", "scoped-viewer"} {
			require.Equal(t, 403, request(actor, "POST", path, form, "console-test-token").Code)
			require.Equal(t, 403, request(actor, "DELETE", path+"?"+form.Encode(), nil, "console-test-token").Code)
		}
		require.Equal(t, 403, request("apple-console-admin", "POST", path, form, "wrong").Code)
		require.Equal(t, 403, request("apple-console-admin", "DELETE", path+"?"+form.Encode(), nil, "wrong").Code)
		require.Equal(t, 200, request("apple-console-admin", "POST", path, form, "console-test-token").Code)
		require.Equal(t, 1, count())
		duplicate := url.Values{"agentId": {device}, "tagId": {strconv.Itoa(tag.ID), strconv.Itoa(foreign.ID)}}
		require.Equal(t, 400, request("apple-console-admin", "POST", path, duplicate, "console-test-token").Code)
		require.Equal(t, 400, request("apple-console-admin", "DELETE", path+"?"+duplicate.Encode(), nil, "console-test-token").Code)
		require.Equal(t, 400, request("apple-console-admin", "POST", path+"?tagId=1", form, "console-test-token").Code)
		require.Equal(t, 400, request("apple-console-admin", "DELETE", path+"?"+form.Encode(), form, "console-test-token").Code)
		other := url.Values{"agentId": {device}, "tagId": {strconv.Itoa(foreign.ID)}}
		w := request("apple-console-admin", "POST", path, other, "console-test-token")
		require.Equal(t, 404, w.Code)
		require.NotContains(t, w.Body.String(), foreign.Tag)
		require.Equal(t, 1, count())
		require.Equal(t, 200, request("apple-console-admin", "DELETE", path+"?"+form.Encode(), nil, "console-test-token").Code)
		require.Zero(t, count())
	}
	// The update list exposes removal only and uses the organization scope.
	require.Equal(t, 200, request("apple-console-admin", "POST", base+"/agents", form, "console-test-token").Code)
	updatePath := fmt.Sprintf("/tenant/%d/admin/update-agents?%s", tenant, form.Encode())
	require.Equal(t, 403, request("organization-admin", "DELETE", updatePath, nil, "console-test-token").Code)
	require.Equal(t, 200, request("apple-console-admin", "DELETE", updatePath, nil, "console-test-token").Code)
	require.Zero(t, count())
	// Missing installed release evidence must also render when a catalog exists.
	available, err := h.Model.Client.Release.Create().SetReleaseType(release.ReleaseTypeAgent).SetArch("amd64").SetOs("windows").SetChannel("stable").SetChecksum("owned-checksum").SetFileURL("https://example.test/owned-agent").SetReleaseDate(time.Now()).SetReleaseNotes("https://example.test/owned-notes").SetVersion("0.0.0-owned").Save(ctx)
	require.NoError(t, err)
	defer h.Model.Client.Release.DeleteOneID(available.ID).Exec(ctx)
	w := request("apple-console-admin", "GET", fmt.Sprintf("/tenant/%d/admin/update-agents", tenant), nil, "console-test-token")
	require.Equal(t, 200, w.Code)
	require.Contains(t, w.Body.String(), "Installed agent versions have not been reported.")
	var events int
	require.NoError(t, h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM uem_inventory_audit WHERE action IN ('inventory.tags.assign','inventory.tags.unassign') AND tenant_id=$1 AND site_id=$2 AND resource_id LIKE $3`, tenant, site, device+"/%").Scan(&events))
	require.Equal(t, 6, events)
}

package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func exerciseProfileEditor(t *testing.T, h *Handler, e *echo.Echo, ctx context.Context, tenant, site, otherTenant int) {
	request := ownedTagHTTPRequest(t, h, e, ctx)
	panelRequest := ownedTagHTTPRequest(t, h, e, ctx, func(r *http.Request) { r.Header.Set("HX-Target", "profile-tag-panel") })
	own, err := h.Model.Client.Tag.Create().SetTag("Editor <route> tag").SetColor("blue").SetTenantID(tenant).Save(ctx)
	require.NoError(t, err)
	defer h.Model.Client.Tag.DeleteOneID(own.ID).Exec(ctx)
	foreign, err := h.Model.Client.Tag.Create().SetTag("Editor other organization tag").SetColor("red").SetTenantID(otherTenant).Save(ctx)
	require.NoError(t, err)
	defer h.Model.Client.Tag.DeleteOneID(foreign.ID).Exec(ctx)
	for _, scope := range []access.Scope{{}, {TenantID: tenant}, {TenantID: tenant, SiteID: site}} {
		q := h.Model.Client.Profile.Create().SetName("Owned editor <profile>").SetApplyToAll(true)
		prefix := ""
		if scope.TenantID != 0 {
			q.AddTenantIDs(tenant)
			prefix = fmt.Sprintf("/tenant/%d", tenant)
		}
		if scope.SiteID != 0 {
			q.AddSiteIDs(site)
			prefix += fmt.Sprintf("/site/%d", site)
		}
		p, err := q.Save(ctx)
		require.NoError(t, err)
		defer h.Model.Client.Profile.DeleteOneID(p.ID).Exec(ctx)
		task, err := h.Model.Client.Task.Create().SetName("Editor task summary").SetType("unix_script").SetScript("private-editor-script").SetLocalUserPassword("private-editor-password").SetProfileID(p.ID).Save(ctx)
		require.NoError(t, err)
		defer h.Model.Client.Task.DeleteOneID(task.ID).Exec(ctx)
		path := fmt.Sprintf("%s/profiles/%d", prefix, p.ID)
		for _, actor := range []string{"organization-admin", "scoped-operator", "scoped-viewer"} {
			for _, suffix := range []string{"", "/tags"} {
				require.Equal(t, 403, request(actor, "GET", path+suffix, nil, "console-test-token").Code)
			}
		}
		wrong := fmt.Sprintf("/profiles/%d", p.ID)
		if prefix == "" {
			wrong = fmt.Sprintf("/tenant/%d/profiles/%d", tenant, p.ID)
		}
		for _, suffix := range []string{"", "/tags"} {
			w := request("apple-console-admin", "GET", wrong+suffix, nil, "console-test-token")
			require.Equal(t, 404, w.Code)
			require.NotContains(t, w.Body.String(), p.Name)
		}
		for _, query := range []string{"page=0", "page=01", "page=1&page=2", "pageSize=1001", "script=x", "page=1000001", "q=unexpected"} {
			require.Equal(t, 400, request("apple-console-admin", "GET", path+"?"+query, nil, "console-test-token").Code)
		}
		w := request("apple-console-admin", "GET", path+"?page=99&pageSize=2", nil, "console-test-token")
		require.Equal(t, 200, w.Code)
		require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
		require.Contains(t, w.Body.String(), "Owned editor &lt;profile&gt;")
		require.Contains(t, w.Body.String(), "Editor task summary")
		require.NotContains(t, w.Body.String(), "private-editor-")
		require.Contains(t, w.Body.String(), "Editor &lt;route&gt; tag")
		if prefix == "" {
			require.Contains(t, w.Body.String(), foreign.Tag)
		} else {
			require.NotContains(t, w.Body.String(), foreign.Tag)
		}
		for _, query := range []string{"q=a&q=b", "page=0", "pageSize=1", "q=" + strings.Repeat("x", 257)} {
			require.Equal(t, 400, request("apple-console-admin", "GET", path+"/tags?"+query, nil, "console-test-token").Code)
		}
		w = request("apple-console-admin", "GET", path+"/tags?q="+strconv.Itoa(own.ID), nil, "console-test-token")
		require.Equal(t, 200, w.Code)
		require.Contains(t, w.Body.String(), "Editor &lt;route&gt; tag")
		require.NotContains(t, w.Body.String(), "profile-assignment-field")
		require.NotContains(t, w.Body.String(), "profile-description")
		form := url.Values{"agentId": {strconv.Itoa(p.ID)}, "tagId": {strconv.Itoa(own.ID)}, "page": {"1"}, "q": {"Editor"}}
		for _, method := range []string{"POST", "DELETE"} {
			invalid := url.Values{"agentId": {strconv.Itoa(p.ID)}, "tagId": {strconv.Itoa(own.ID)}, "unknown": {"x"}}
			target := path + "/tags"
			body := invalid
			if method == "DELETE" {
				target += "?" + invalid.Encode()
				body = nil
			}
			require.Equal(t, 400, panelRequest("apple-console-admin", method, target, body, "console-test-token").Code)
		}
		w = panelRequest("apple-console-admin", "POST", path+"/tags", form, "console-test-token")
		require.Equal(t, 200, w.Code)
		require.Contains(t, w.Body.String(), `id="profile-tag-panel"`)
		require.Contains(t, w.Body.String(), `hx-swap-oob="outerHTML"`)
		require.NotContains(t, w.Body.String(), "profile-description")
		require.NotContains(t, w.Body.String(), "profile-task-list")
		w = panelRequest("apple-console-admin", "DELETE", path+"/tags?"+form.Encode(), nil, "console-test-token")
		require.Equal(t, 200, w.Code)
		require.Contains(t, w.Body.String(), "No tags are assigned.")
		// A successful metadata save does not depend on a later read/audit receipt.
		_, err = h.Model.DB.ExecContext(ctx, `CREATE FUNCTION reject_owned_editor_route() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='inventory.profiles.read' THEN RAISE EXCEPTION 'private editor read failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_owned_editor_route BEFORE INSERT ON uem_inventory_audit FOR EACH ROW EXECUTE FUNCTION reject_owned_editor_route()`)
		require.NoError(t, err)
		w = request("apple-console-admin", "POST", path, url.Values{"profile-description": {"Saved editor"}, "profile-assignment": {"dontApplyToAll"}}, "console-test-token")
		require.Equal(t, 204, w.Code)
		require.Equal(t, path, w.Header().Get("HX-Redirect"))
		w = request("apple-console-admin", "GET", path, nil, "console-test-token")
		require.Equal(t, 503, w.Code)
		require.NotContains(t, w.Body.String(), "private editor read failure")
		require.NotContains(t, w.Body.String(), "Saved editor")
		_, err = h.Model.DB.ExecContext(ctx, `DROP TRIGGER reject_owned_editor_route ON uem_inventory_audit; DROP FUNCTION reject_owned_editor_route()`)
		require.NoError(t, err)
	}
}

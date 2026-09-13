package handlers

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent/task"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/utils"
	"github.com/stretchr/testify/require"
)

func exerciseTaskEditingScope(t *testing.T, h *Handler, e *echo.Echo, ctx context.Context, tenant, site int) {
	t.Helper()
	request := ownedTagHTTPRequest(t, h, e, ctx)
	for _, scope := range []access.Scope{{}, {TenantID: tenant}, {TenantID: tenant, SiteID: site}} {
		prefix := ""
		create := h.Model.Client.Profile.Create().SetName("Owned task edit parent")
		if scope.TenantID != 0 {
			create.AddTenantIDs(tenant)
			prefix = fmt.Sprintf("/tenant/%d", tenant)
		}
		if scope.SiteID != 0 {
			create.AddSiteIDs(site)
			prefix += fmt.Sprintf("/site/%d", site)
		}
		p, err := create.Save(ctx)
		require.NoError(t, err)
		defer h.Model.Client.Profile.DeleteOneID(p.ID).Exec(ctx)
		current, err := h.Model.Client.Task.Create().SetProfileID(p.ID).SetType(task.TypePowershellScript).SetAgentType(task.AgentTypeWindows).SetVersion(3).SetOrder(7).SetName("Owned <edit> task").SetScript("Write-Output 'owned'").SetScriptRun(task.ScriptRunAlways).Save(ctx)
		require.NoError(t, err)
		path := fmt.Sprintf("%s/tasks/%d", prefix, current.ID)
		form := url.Values{"profile": {fmt.Sprint(p.ID)}, "task-version": {"3"}, "task-agent-type": {"windows"}, "selected-task-type": {"powershell_script"}, "task-description": {"Owned changed task"}, "powershell-script": {"Write-Output 'changed'"}, "powershell-run": {"always"}}
		for _, actor := range []string{"organization-admin", "scoped-operator", "scoped-viewer"} {
			require.Equal(t, 403, request(actor, "GET", path, nil, "").Code)
			require.Equal(t, 403, request(actor, "POST", path, form, "console-test-token").Code)
		}
		require.Equal(t, 403, request("apple-console-admin", "POST", path, form, "wrong").Code)
		require.Equal(t, 400, request("apple-console-admin", "GET", path+"?profile=1", nil, "").Code)
		require.Equal(t, 400, request("apple-console-admin", "POST", path+"?profile=1", form, "console-test-token").Code)
		for _, change := range []func(url.Values){func(v url.Values) { v["task-version"] = []string{"3", "4"} }, func(v url.Values) { v.Set("task-agent-type", "linux") }, func(v url.Values) { v.Set("task-description", "") }, func(v url.Values) { v.Set("unknown", "owned") }, func(v url.Values) { v.Set("task-password-action", "clear") }} {
			bad := url.Values{}
			for key, values := range form {
				bad[key] = append([]string{}, values...)
			}
			change(bad)
			require.Equal(t, 400, request("apple-console-admin", "POST", path, bad, "console-test-token").Code)
		}
		w := request("apple-console-admin", "GET", path, nil, "")
		require.Equal(t, 200, w.Code)
		require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
		require.Contains(t, w.Body.String(), "Owned &lt;edit&gt; task")
		require.Contains(t, w.Body.String(), `name="task-version" value="3"`)
		require.NotContains(t, w.Body.String(), "MISSING")
		require.Equal(t, 1, strings.Count(w.Body.String(), `id="main"`))
		w = request("apple-console-admin", "POST", path, form, "console-test-token")
		require.Equal(t, 204, w.Code)
		require.Equal(t, fmt.Sprintf("%s/profiles/%d", prefix, p.ID), w.Header().Get("HX-Redirect"))
		require.Equal(t, 409, request("apple-console-admin", "POST", path, form, "console-test-token").Code)
		stored, err := h.Model.Client.Task.Get(ctx, current.ID)
		require.NoError(t, err)
		require.Equal(t, 4, stored.Version)
		require.Equal(t, 7, stored.Order)
		require.Equal(t, "Write-Output 'changed'", stored.Script)
		if scope.TenantID != 0 {
			require.Equal(t, 404, request("apple-console-admin", "GET", fmt.Sprintf("/tasks/%d", current.ID), nil, "").Code)
			require.Equal(t, 404, request("apple-console-admin", "POST", fmt.Sprintf("/tasks/%d", current.ID), form, "console-test-token").Code)
		}
	}
	// Secrets stay absent from GET and unchanged by a default save.
	p, err := h.Model.Client.Profile.Create().SetName("Owned private task parent").AddTenantIDs(tenant).AddSiteIDs(site).Save(ctx)
	require.NoError(t, err)
	defer h.Model.Client.Profile.DeleteOneID(p.ID).Exec(ctx)
	key := strings.Repeat("k", 32)
	encrypted, err := utils.EncryptSensitiveField("owned-private-password", key)
	require.NoError(t, err)
	current, err := h.Model.Client.Task.Create().SetProfileID(p.ID).SetName("Owned private user").SetType(task.TypeAddUnixLocalUser).SetAgentType(task.AgentTypeLinux).SetVersion(1).SetLocalUserUsername("owned").SetLocalUserPassword(encrypted).SetLocalUserSSHKeyPassphrase("owned-private-passphrase").Save(ctx)
	require.NoError(t, err)
	path := fmt.Sprintf("/tenant/%d/site/%d/tasks/%d", tenant, site, current.ID)
	w := request("apple-console-admin", "GET", path, nil, "")
	require.Equal(t, 200, w.Code)
	require.NotContains(t, w.Body.String(), encrypted)
	require.NotContains(t, w.Body.String(), "owned-private-password")
	require.NotContains(t, w.Body.String(), "owned-private-passphrase")
	form := url.Values{"profile": {fmt.Sprint(p.ID)}, "task-version": {"1"}, "task-agent-type": {"linux"}, "selected-task-type": {"add_unix_local_user"}, "task-description": {"Owned renamed user"}, "local-user-username": {"owned"}, "task-password-action": {"keep"}, "task-passphrase-action": {"keep"}}
	require.Equal(t, 204, request("apple-console-admin", "POST", path, form, "console-test-token").Code)
	stored, err := h.Model.Client.Task.Get(ctx, current.ID)
	require.NoError(t, err)
	require.Equal(t, encrypted, stored.LocalUserPassword)
	require.Equal(t, "owned-private-passphrase", stored.LocalUserSSHKeyPassphrase)
	// NetBird settings use an owned HTTPS provider; missing saved IDs stay selected.
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Token owned-provider-token", r.Header.Get("Authorization"))
		_, _ = io.WriteString(w, `[{"id":"new-ID","name":"Owned new group"}]`)
	}))
	defer provider.Close()
	previous := h.taskWizardHTTPTransport
	h.taskWizardHTTPTransport = provider.Client().Transport
	defer func() { h.taskWizardHTTPTransport = previous }()
	settings, err := h.Model.Client.NetbirdSettings.Create().SetManagementURL(provider.URL).SetAccessToken("owned-provider-token").AddTenantIDs(tenant).Save(ctx)
	require.NoError(t, err)
	defer func() {
		// This legacy FK cascades tenant deletion when settings are removed. Detach
		// the owned fixture first, preserving the shared route-test tenant.
		_, err := h.Model.DB.ExecContext(ctx, "UPDATE tenants SET tenant_netbird=NULL WHERE id=$1 AND tenant_netbird=$2", tenant, settings.ID)
		require.NoError(t, err)
		require.NoError(t, h.Model.Client.NetbirdSettings.DeleteOneID(settings.ID).Exec(ctx))
	}()
	registration, err := h.Model.Client.Task.Create().SetProfileID(p.ID).SetName("Owned registration edit").SetType(task.TypeNetbirdRegister).SetAgentType(task.AgentTypeAny).SetTenant(tenant).SetVersion(1).SetNetbirdGroups(`"saved-ID"`).SetNetbirdAllowExtraDNSLabels(true).Save(ctx)
	require.NoError(t, err)
	path = fmt.Sprintf("/tenant/%d/site/%d/tasks/%d", tenant, site, registration.ID)
	w = request("apple-console-admin", "GET", path, nil, "")
	require.Equal(t, 200, w.Code)
	require.Contains(t, w.Body.String(), "Saved group ID: saved-ID")
	require.Contains(t, w.Body.String(), `value="saved-ID" selected`)
	form = url.Values{"profile": {fmt.Sprint(p.ID)}, "task-version": {"1"}, "task-agent-type": {"any"}, "selected-task-type": {"netbird_register"}, "task-description": {"Owned registration edit"}, "netbird-group-id": {"saved-ID", "new-ID"}, "netbird-allow-extra-dns-labels": {"on"}}
	require.Equal(t, 204, request("apple-console-admin", "POST", path, form, "console-test-token").Code)
	stored, err = h.Model.Client.Task.Get(ctx, registration.ID)
	require.NoError(t, err)
	require.Equal(t, `"saved-ID","new-ID"`, stored.NetbirdGroups)
	require.True(t, stored.NetbirdAllowExtraDNSLabels)
	require.Equal(t, tenant, stored.Tenant)
}

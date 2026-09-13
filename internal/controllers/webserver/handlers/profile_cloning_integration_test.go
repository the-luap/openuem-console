package handlers

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	entprofile "github.com/open-uem/ent/profile"
	"github.com/open-uem/ent/task"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func exerciseProfileCloningScope(t *testing.T, h *Handler, e *echo.Echo, ctx context.Context, tenant, site int) {
	t.Helper()
	request := ownedTagHTTPRequest(t, h, e, ctx)
	p, err := h.Model.Client.Profile.Create().SetName("Owned foreign clone source").AddTenantIDs(tenant).AddSiteIDs(site).Save(ctx)
	require.NoError(t, err)
	defer h.Model.Client.Profile.DeleteOneID(p.ID).Exec(ctx)
	require.Equal(t, 404, request("apple-console-admin", "GET", fmt.Sprintf("/profiles/%d/clone", p.ID), nil, "").Code)
	require.Equal(t, 404, request("apple-console-admin", "POST", fmt.Sprintf("/profiles/%d/clone", p.ID), url.Values{"profile-description": {"Foreign clone"}, "tenant-id": {""}}, "console-test-token").Code)
	prefix := func(scope access.Scope) string {
		value := ""
		if scope.TenantID != 0 {
			value = fmt.Sprintf("/tenant/%d", scope.TenantID)
		}
		if scope.SiteID != 0 {
			value += fmt.Sprintf("/site/%d", scope.SiteID)
		}
		return value
	}
	scopes := []access.Scope{{}, {TenantID: tenant}, {TenantID: tenant, SiteID: site}}
	for _, source := range scopes {
		create := h.Model.Client.Profile.Create().SetName("Owned scoped clone source").SetApplyToAll(true).SetDisabled(true)
		if source.TenantID != 0 {
			create.AddTenantIDs(tenant)
		}
		if source.SiteID != 0 {
			create.AddSiteIDs(site)
		}
		original, err := create.Save(ctx)
		require.NoError(t, err)
		defer h.Model.Client.Profile.DeleteOneID(original.ID).Exec(ctx)
		_, err = h.Model.Client.Task.Create().SetName("Owned clone task").SetType(task.TypeAptInstall).SetAptName("owned-package").SetVersion(4).SetProfileID(original.ID).Save(ctx)
		require.NoError(t, err)
		path := fmt.Sprintf("%s/profiles/%d/clone", prefix(source), original.ID)
		form := url.Values{"profile-description": {"Owned route clone"}, "tenant-id": {""}}
		for _, actor := range []string{"organization-admin", "scoped-operator", "scoped-viewer"} {
			require.Equal(t, 403, request(actor, "GET", path, nil, "").Code)
			require.Equal(t, 403, request(actor, "POST", path, form, "console-test-token").Code)
		}
		review := request("apple-console-admin", "GET", path, nil, "")
		require.Equal(t, 200, review.Code)
		require.Contains(t, review.Body.String(), "Copy the tasks into a new, unassigned profile.")
		require.NotContains(t, review.Body.String(), "!(MISSING:profile_cloning")
		require.Equal(t, 1, strings.Count(review.Body.String(), `id="main"`))
		require.Contains(t, review.Body.String(), `hx-params="tenant-id"`)
		require.Equal(t, 403, request("apple-console-admin", "POST", path, form, "wrong").Code)
		require.Equal(t, 400, request("apple-console-admin", "POST", path+"?tenant-id=1", form, "console-test-token").Code)
		for _, invalid := range []url.Values{
			nil, {"profile-description": {"Missing destination"}}, {"tenant-id": {""}},
			{"profile-description": {" "}, "tenant-id": {""}},
			{"profile-description": {"Duplicate", "Duplicate"}, "tenant-id": {""}},
			{"profile-description": {"Duplicate"}, "tenant-id": {"", "1"}},
			{"profile-description": {"Noncanonical"}, "tenant-id": {"01"}},
			{"profile-description": {"Orphan site"}, "tenant-id": {""}, "site-id": {strconv.Itoa(site)}},
			{"profile-description": {"Assignment"}, "tenant-id": {""}, "profile-assignment": {"applyToAll"}},
		} {
			require.Equal(t, 400, request("apple-console-admin", "POST", path, invalid, "console-test-token").Code)
		}
		for _, destination := range scopes {
			name := fmt.Sprintf("Owned <clone> %d/%d to %d/%d\n第二行", source.TenantID, source.SiteID, destination.TenantID, destination.SiteID)
			form := url.Values{"profile-description": {name}, "tenant-id": {""}}
			if destination.TenantID != 0 {
				form.Set("tenant-id", strconv.Itoa(tenant))
			}
			if destination.SiteID != 0 {
				form.Set("site-id", strconv.Itoa(site))
			}
			response := request("apple-console-admin", "POST", path, form, "console-test-token")
			require.Equal(t, 200, response.Code)
			cloned, err := h.Model.Client.Profile.Query().Where(entprofile.NameEQ(name)).WithTasks().WithTenant().WithSite().Only(ctx)
			require.NoError(t, err)
			defer h.Model.Client.Profile.DeleteOneID(cloned.ID).Exec(ctx)
			require.Equal(t, fmt.Sprintf("%s/profiles/%d", prefix(destination), cloned.ID), response.Header().Get("HX-Redirect"))
			require.False(t, cloned.ApplyToAll)
			require.False(t, cloned.Disabled)
			require.Len(t, cloned.Edges.Tasks, 1)
			require.Equal(t, "owned-package", cloned.Edges.Tasks[0].AptName)
			require.Equal(t, 1, cloned.Edges.Tasks[0].Version)
			if destination.TenantID == 0 {
				require.Empty(t, cloned.Edges.Tenant)
			} else {
				require.Len(t, cloned.Edges.Tenant, 1)
				require.Equal(t, tenant, cloned.Edges.Tenant[0].ID)
			}
			if destination.SiteID == 0 {
				require.Empty(t, cloned.Edges.Site)
			} else {
				require.Len(t, cloned.Edges.Site, 1)
				require.Equal(t, site, cloned.Edges.Site[0].ID)
			}
		}
	}
	for _, actor := range []string{"organization-admin", "scoped-operator", "scoped-viewer"} {
		require.Equal(t, 403, request(actor, "POST", "/tenant/sites", url.Values{"tenant-id": {strconv.Itoa(tenant)}}, "console-test-token").Code)
	}
	require.Equal(t, 400, request("apple-console-admin", "POST", "/tenant/sites", url.Values{"tenant-id": {"-1"}}, "console-test-token").Code)
	require.Equal(t, 400, request("apple-console-admin", "POST", "/tenant/sites", url.Values{"tenant-id": {strconv.Itoa(tenant)}, "profile-description": {"unexpected"}}, "console-test-token").Code)
	require.Equal(t, 403, request("apple-console-admin", "POST", "/tenant/sites", url.Values{"tenant-id": {strconv.Itoa(tenant)}}, "wrong").Code)
	selected := request("apple-console-admin", "POST", "/tenant/sites", url.Values{"tenant-id": {strconv.Itoa(tenant)}}, "console-test-token")
	require.Equal(t, 200, selected.Code)
	require.Contains(t, selected.Body.String(), `id="site-id"`)
	cleared := request("apple-console-admin", "POST", "/tenant/sites", url.Values{"tenant-id": {""}}, "console-test-token")
	require.Equal(t, 200, cleared.Code)
	require.NotContains(t, cleared.Body.String(), `name="site-id"`)
}

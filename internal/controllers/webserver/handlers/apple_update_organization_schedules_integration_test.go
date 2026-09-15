package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func exerciseAppleUpdateOrganizationSchedules(t *testing.T, h *Handler, ctx context.Context, tenant, site int, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	scope := apple.Scope{TenantID: tenant, SiteID: site}
	other, err := h.Model.Client.Site.Create().SetDescription("Owned other organization-group site").SetTenantID(tenant).Save(ctx)
	require.NoError(t, err)
	var ids []string
	for _, scope := range []apple.Scope{scope, {TenantID: tenant, SiteID: other.ID}} {
		invite, err := h.Apple.Invite(ctx, scope, "Owned organization schedule target", "apple-console-admin")
		require.NoError(t, err)
		_, err = h.Model.DB.ExecContext(ctx, `UPDATE mdm_apple_devices SET status='enrolled',udid=id::text,model='iPhone16,1',os_version='18.6',supervised=true,certificate_expires_at=clock_timestamp()+interval '1 year' WHERE id=$1`, invite.DeviceID)
		require.NoError(t, err)
		ids = append(ids, invite.DeviceID)
	}
	var original []byte
	var fetched *time.Time
	require.NoError(t, h.Model.DB.QueryRowContext(ctx, `SELECT document,fetched_at FROM mdm_apple_software_catalog WHERE singleton=true`).Scan(&original, &fetched))
	defer func() {
		_, err := h.Model.DB.ExecContext(ctx, `UPDATE mdm_apple_software_catalog SET document=$1,fetched_at=$2 WHERE singleton=true`, original, fetched)
		require.NoError(t, err)
	}()
	catalog, err := json.Marshal(apple.SoftwareCatalog{PublicAssetSets: map[string][]apple.OSRelease{"iOS": {{Version: "18.7.1", Build: "22H100", PostingDate: time.Now().AddDate(0, -1, 0).Format("2006-01-02"), ExpirationDate: time.Now().AddDate(1, 0, 0).Format("2006-01-02"), SupportedDevices: []string{"iPhone16,1"}}}}})
	require.NoError(t, err)
	_, err = h.Model.DB.ExecContext(ctx, `UPDATE mdm_apple_software_catalog SET document=$1,fetched_at=clock_timestamp() WHERE singleton=true`, catalog)
	require.NoError(t, err)
	p, err := h.Apple.SaveUpdatePlan(ctx, "scoped-operator", h.Access, scope, "", 0, apple.UpdatePlanDefinition{Name: "Owned <organization scheduled update>", Platform: "ios", TargetVersion: "18.7.1", TargetBuild: "22H100", Deadline: time.Now().UTC().Add(-time.Hour).Format("2006-01-02T15:04:05")})
	require.NoError(t, err)
	definition := inventory.DeviceGroupDefinition{Name: "Owned <organization schedule group>", Rule: inventory.DeviceGroupRule{Search: "Owned organization schedule target"}}
	group, err := inventory.SaveDeviceGroup(ctx, h.Model.DB, h.Access, "organization-admin", access.Scope{TenantID: tenant}, "", 0, definition)
	require.NoError(t, err)
	base := fmt.Sprintf("/tenant/%d/site/%d/ios/update-plans/%s", tenant, site, p.ID)
	page := request("organization-admin", "GET", base+"/groups/"+group.ID+"/preview?revision=1&group_revision=1&source=organization", nil)
	require.Equal(t, 200, page.Code)
	markup := regexp.MustCompile(`(?s)<form[^>]*data-update-schedule-confirm[^>]*>(.*?)</form>`).FindStringSubmatch(page.Body.String())
	require.Len(t, markup, 2)
	form := url.Values{}
	for _, field := range []string{"expected_revision", "group_id", "group_revision", "group_source", "request_key", "devices", "not_before", "activation_window_minutes"} {
		m := regexp.MustCompile(`name="` + field + `" value="([^"]*)"`).FindStringSubmatch(markup[1])
		require.Len(t, m, 2)
		form.Set(field, html.UnescapeString(m[1]))
	}
	require.Equal(t, "organization", form.Get("group_source"))
	require.True(t, strings.HasPrefix(form.Get("devices"), ids[0]+":"))
	require.NotContains(t, form.Get("devices"), ids[1])
	path := base + "/schedules"
	require.Equal(t, 400, request("organization-admin", "POST", path, form).Code)
	form.Set("confirmed", "yes")
	require.Equal(t, 403, request("scoped-operator", "POST", path, form).Code)
	require.Equal(t, 403, request("scoped-viewer", "POST", path, form).Code)
	form.Del("group_source")
	require.Equal(t, 404, request("organization-admin", "POST", path, form).Code)
	form.Set("group_source", "unknown")
	require.Equal(t, 400, request("organization-admin", "POST", path, form).Code)
	form.Set("group_source", "organization")
	form.Add("group_source", "site")
	require.Equal(t, 400, request("organization-admin", "POST", path, form).Code)
	form.Set("group_source", "organization")
	orgPath := fmt.Sprintf("/tenant/%d/ios/update-plans/%s/schedules", tenant, p.ID)
	require.Equal(t, 400, request("organization-admin", "POST", orgPath, form).Code)
	form.Set("not_before", time.Now().UTC().Add(time.Hour).Format("2006-01-02T15:04:05Z"))
	var before, after int
	require.NoError(t, h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM mdm_apple_commands WHERE device_id=$1`, ids[0]).Scan(&before))
	saved := request("organization-admin", "POST", path, form)
	require.Equal(t, 303, saved.Code)
	location := saved.Header().Get("Location")
	require.True(t, strings.HasPrefix(location, path+"/"))
	require.NoError(t, h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM mdm_apple_commands WHERE device_id=$1`, ids[0]).Scan(&after))
	require.Equal(t, before, after)
	for _, actor := range []string{"organization-admin", "scoped-operator"} {
		page = request(actor, "GET", location, nil)
		require.Equal(t, 200, page.Code)
		require.Equal(t, "no-store", page.Header().Get("Cache-Control"))
		require.Contains(t, page.Body.String(), "Only the selected target site's members")
		require.Contains(t, page.Body.String(), "data-update-schedule-cancel")
		require.Equal(t, actor == "organization-admin", strings.Contains(page.Body.String(), "Open the current organization group and its history"))
		require.NotContains(t, page.Body.String(), fmt.Sprintf(`/tenant/%d/site/%d/device-groups/%s`, tenant, site, group.ID))
	}
	require.Equal(t, 403, request("scoped-viewer", "GET", location, nil).Code)
	replay := request("organization-admin", "POST", path, form)
	require.Equal(t, 303, replay.Code)
	require.Equal(t, location, replay.Header().Get("Location"))
	form.Set("group_source", "site")
	require.Equal(t, 409, request("organization-admin", "POST", path, form).Code)
	form.Set("group_source", "organization")
	cancel := url.Values{"expected_revision": {"1"}, "confirmed": {"yes"}}
	require.Equal(t, 303, request("scoped-operator", "POST", location+"/cancel", cancel).Code)
	require.Equal(t, 409, request("scoped-operator", "POST", location+"/cancel", cancel).Code)
	form.Set("request_key", uuid.NewString())
	form.Set("not_before", time.Now().UTC().Format("2006-01-02T15:04:05Z"))
	due := request("organization-admin", "POST", path, form)
	require.Equal(t, 303, due.Code)
	progress, err := h.Apple.ProcessDueUpdateSchedules(ctx, h.Access, inventory.DeviceSources{Apple: true, Windows: h.Windows != nil}, 25)
	require.NoError(t, err)
	require.Equal(t, 1, progress.Activated)
	dueLocation := due.Header().Get("Location")
	detail, err := h.Apple.UpdateScheduleDetails(ctx, "scoped-operator", h.Access, scope, p.ID, strings.TrimPrefix(dueLocation, path+"/"))
	require.NoError(t, err)
	require.Equal(t, apple.Scope{TenantID: tenant}, detail.GroupScope)
	receipt, err := h.Apple.UpdatePlanGroupAssignmentDetails(ctx, "scoped-operator", h.Access, scope, p.ID, detail.AssignmentID)
	require.NoError(t, err)
	require.Equal(t, detail.GroupScope, receipt.GroupScope)
	require.Len(t, receipt.Commands, 1)
	require.Equal(t, ids[0], receipt.Commands[0].Selection.DeviceID)
	page = request("scoped-operator", "GET", dueLocation, nil)
	require.Equal(t, 200, page.Code)
	require.Contains(t, page.Body.String(), "Open activation receipt")
	require.NotContains(t, page.Body.String(), "data-update-schedule-cancel")
	definition.Archived = true
	_, err = inventory.SaveDeviceGroup(ctx, h.Model.DB, h.Access, "organization-admin", access.Scope{TenantID: tenant}, group.ID, 1, definition)
	require.NoError(t, err)
	require.NoError(t, h.Apple.SetUpdatePolicyWithAccess(ctx, scope, []string{ids[0]}, nil, "scoped-operator", h.Access))
	replay = request("organization-admin", "POST", path, form)
	require.Equal(t, 303, replay.Code)
	require.Equal(t, dueLocation, replay.Header().Get("Location"))
	_, err = h.Apple.UpdatePolicy(ctx, scope, ids[0])
	require.ErrorIs(t, err, apple.ErrNotFound)
	_, err = h.Apple.UpdatePolicy(ctx, apple.Scope{TenantID: tenant, SiteID: other.ID}, ids[1])
	require.ErrorIs(t, err, apple.ErrNotFound)
	page = request("scoped-operator", "GET", path, nil)
	require.Equal(t, 200, page.Code)
	require.Contains(t, page.Body.String(), "Source: organization group")
}

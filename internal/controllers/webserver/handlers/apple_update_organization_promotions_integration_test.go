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

func exerciseAppleUpdateOrganizationPromotions(t *testing.T, h *Handler, ctx context.Context, tenant, site int, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	scope := apple.Scope{TenantID: tenant, SiteID: site}
	other, err := h.Model.Client.Site.Create().SetDescription("Owned other organization-group site").SetTenantID(tenant).Save(ctx)
	require.NoError(t, err)
	var ids []string
	for i, scope := range []apple.Scope{scope, scope, {TenantID: tenant, SiteID: other.ID}} {
		invite, err := h.Apple.Invite(ctx, scope, fmt.Sprintf("Owned organization promotion target %d", i), "apple-console-admin")
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
	definition := apple.UpdatePlanDefinition{Name: "Owned <organization promotion pilot>", Platform: "ios", TargetVersion: "18.7.1", TargetBuild: "22H100", Deadline: time.Now().UTC().Add(time.Hour).Format("2006-01-02T15:04:05")}
	pilotPlan, err := h.Apple.SaveUpdatePlan(ctx, "scoped-operator", h.Access, scope, "", 0, definition)
	require.NoError(t, err)
	pilotGroup, err := inventory.SaveDeviceGroup(ctx, h.Model.DB, h.Access, "scoped-operator", access.Scope{TenantID: tenant, SiteID: site}, "", 0, inventory.DeviceGroupDefinition{Name: "Owned organization promotion original pilot", Rule: inventory.DeviceGroupRule{Search: "Owned organization promotion target 0"}})
	require.NoError(t, err)
	sources := inventory.DeviceSources{Apple: true, Windows: h.Windows != nil}
	initial, err := h.Apple.PreviewUpdatePlanGroup(ctx, "scoped-operator", h.Access, scope, sources, pilotPlan.ID, 1, pilotGroup.ID, 1)
	require.NoError(t, err)
	require.Len(t, initial.Targets, 1)
	require.Equal(t, ids[0], initial.Targets[0].Selection.DeviceID)
	pilot, err := h.Apple.AssignUpdatePlanFromGroup(ctx, "scoped-operator", h.Access, scope, sources, pilotPlan.ID, 1, pilotGroup.ID, 1, uuid.NewString(), []apple.UpdatePlanGroupSelection{initial.Targets[0].Selection})
	require.NoError(t, err)
	// Owned projections exercise registered console routes; authenticated report
	// ingestion and admission races are covered separately by the Apple package.
	_, err = h.Model.DB.ExecContext(ctx, `INSERT INTO mdm_apple_os_observations(device_id,version,build,source,recorded_at) VALUES($1,'18.7.1','22H100','declarative_status',clock_timestamp())`, ids[0])
	require.NoError(t, err)
	definition.Name = "Owned <organization promotion destination>"
	definition.Deadline = time.Now().UTC().Add(24 * time.Hour).Format("2006-01-02T15:04:05")
	destination, err := h.Apple.SaveUpdatePlan(ctx, "scoped-operator", h.Access, scope, "", 0, definition)
	require.NoError(t, err)
	groupDefinition := inventory.DeviceGroupDefinition{Name: "Owned <organization promotion group>", Rule: inventory.DeviceGroupRule{Search: "Owned organization promotion target"}}
	group, err := inventory.SaveDeviceGroup(ctx, h.Model.DB, h.Access, "organization-admin", access.Scope{TenantID: tenant}, "", 0, groupDefinition)
	require.NoError(t, err)
	base := fmt.Sprintf("/tenant/%d/site/%d/ios/update-plans/%s/group-assignments/%s", tenant, site, pilotPlan.ID, pilot.ID)
	query := url.Values{"destination_plan": {destination.ID}, "revision": {"1"}, "source": {"organization"}}
	chooser := base + "/promotion/groups?" + query.Encode()
	page := request("organization-admin", "GET", chooser, nil)
	require.Equal(t, 200, page.Code)
	require.Contains(t, page.Body.String(), "only within the selected target site")
	require.Contains(t, page.Body.String(), "Owned &lt;organization promotion group&gt;")
	query.Set("group", group.ID)
	query.Set("group_revision", "1")
	reviewPath := base + "/promotion/review?" + query.Encode()
	for _, path := range []string{chooser, reviewPath} {
		for _, actor := range []string{"scoped-operator", "scoped-viewer"} {
			require.Equal(t, 403, request(actor, "GET", path, nil).Code)
		}
		require.Equal(t, 400, request("organization-admin", "GET", path+"&source=organization", nil).Code)
		require.Equal(t, 400, request("organization-admin", "GET", strings.Replace(path, "source=organization", "source=unknown", 1), nil).Code)
	}
	require.Equal(t, 404, request("organization-admin", "GET", strings.Replace(reviewPath, "source=organization", "source=site", 1), nil).Code)
	review := func() url.Values {
		t.Helper()
		page := request("organization-admin", "GET", reviewPath, nil)
		require.Equal(t, 200, page.Code)
		require.Equal(t, "no-store", page.Header().Get("Cache-Control"))
		require.Contains(t, page.Body.String(), "Every original pilot enrollment currently meets")
		require.Contains(t, page.Body.String(), "Overlapping pilot devices are included")
		markup := regexp.MustCompile(`(?s)<form[^>]*data-promotion-confirm[^>]*>(.*?)</form>`).FindStringSubmatch(page.Body.String())
		require.Len(t, markup, 2)
		form := url.Values{}
		for _, field := range []string{"destination_plan", "expected_revision", "group_id", "group_revision", "group_source", "request_key", "devices"} {
			m := regexp.MustCompile(`name="` + field + `" value="([^"]*)"`).FindStringSubmatch(markup[1])
			require.Len(t, m, 2)
			form.Set(field, html.UnescapeString(m[1]))
		}
		require.Equal(t, "organization", form.Get("group_source"))
		require.Len(t, strings.Split(form.Get("devices"), "\n"), 2)
		for _, id := range ids[:2] {
			require.Contains(t, form.Get("devices"), id+":")
		}
		require.NotContains(t, page.Body.String(), ids[2])
		return form
	}
	form := review()
	history := base + "/promotions"
	require.Equal(t, 400, request("organization-admin", "POST", history, form).Code)
	form.Set("confirmed", "yes")
	for _, actor := range []string{"scoped-operator", "scoped-viewer"} {
		require.Equal(t, 403, request(actor, "POST", history, form).Code)
	}
	form.Del("group_source")
	require.Equal(t, 404, request("organization-admin", "POST", history, form).Code)
	form.Set("group_source", "unknown")
	require.Equal(t, 400, request("organization-admin", "POST", history, form).Code)
	form.Set("group_source", "organization")
	form.Add("group_source", "site")
	require.Equal(t, 400, request("organization-admin", "POST", history, form).Code)
	form.Set("group_source", "organization")
	require.Equal(t, 400, request("organization-admin", "POST", strings.Replace(history, fmt.Sprintf("/site/%d", site), "", 1), form).Code)
	_, err = h.Model.DB.ExecContext(ctx, `UPDATE mdm_apple_os_observations SET recorded_at=clock_timestamp()-interval '25 hours' WHERE device_id=$1`, ids[0])
	require.NoError(t, err)
	page = request("organization-admin", "GET", reviewPath, nil)
	require.Equal(t, 200, page.Code)
	require.NotContains(t, page.Body.String(), "data-promotion-confirm")
	require.Equal(t, 409, request("organization-admin", "POST", history, form).Code)
	_, err = h.Model.DB.ExecContext(ctx, `UPDATE mdm_apple_os_observations SET recorded_at=clock_timestamp() WHERE device_id=$1`, ids[0])
	require.NoError(t, err)
	policy := pilotPlan.Definition.Policy()
	require.NoError(t, h.Apple.SetUpdatePolicyWithAccess(ctx, scope, []string{ids[1]}, &policy, "scoped-operator", h.Access))
	require.Equal(t, 409, request("organization-admin", "POST", history, form).Code)
	form = review()
	form.Set("confirmed", "yes")
	saved := request("organization-admin", "POST", history, form)
	require.Equal(t, 303, saved.Code)
	location := saved.Header().Get("Location")
	require.True(t, strings.HasPrefix(location, history+"/"))
	for _, actor := range []string{"organization-admin", "scoped-operator"} {
		page = request(actor, "GET", location, nil)
		require.Equal(t, 200, page.Code)
		require.Equal(t, "no-store", page.Header().Get("Cache-Control"))
		require.Contains(t, page.Body.String(), "Saved original pilot evidence")
		require.Contains(t, page.Body.String(), "Only the selected target site's members")
		require.Equal(t, actor == "organization-admin", strings.Contains(page.Body.String(), "Open the current organization group and its history"))
		require.NotContains(t, page.Body.String(), fmt.Sprintf(`/tenant/%d/site/%d/device-groups/%s`, tenant, site, group.ID))
		page = request(actor, "GET", history, nil)
		require.Equal(t, 200, page.Code)
		require.Contains(t, page.Body.String(), "Source: organization group")
	}
	require.Equal(t, 403, request("scoped-viewer", "GET", location, nil).Code)
	receipt, err := h.Apple.UpdatePromotionDetails(ctx, "scoped-operator", h.Access, scope, pilotPlan.ID, pilot.ID, strings.TrimPrefix(location, history+"/"))
	require.NoError(t, err)
	require.Equal(t, apple.Scope{TenantID: tenant}, receipt.GroupScope)
	require.Equal(t, receipt.GroupScope, receipt.Assignment.GroupScope)
	require.Equal(t, scope, receipt.Pilot.GroupScope)
	require.Len(t, receipt.Assignment.Commands, 2)
	require.Len(t, receipt.Evidence.Devices, 1)
	groupDefinition.Archived = true
	_, err = inventory.SaveDeviceGroup(ctx, h.Model.DB, h.Access, "organization-admin", access.Scope{TenantID: tenant}, group.ID, 1, groupDefinition)
	require.NoError(t, err)
	require.NoError(t, h.Apple.SetUpdatePolicyWithAccess(ctx, scope, ids[:2], nil, "scoped-operator", h.Access))
	var before, after int
	require.NoError(t, h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM mdm_apple_commands WHERE device_id IN ($1,$2)`, ids[0], ids[1]).Scan(&before))
	replay := request("organization-admin", "POST", history, form)
	require.Equal(t, 303, replay.Code)
	require.Equal(t, location, replay.Header().Get("Location"))
	require.NoError(t, h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM mdm_apple_commands WHERE device_id IN ($1,$2)`, ids[0], ids[1]).Scan(&after))
	require.Equal(t, before, after)
	for _, id := range ids[:2] {
		_, err = h.Apple.UpdatePolicy(ctx, scope, id)
		require.ErrorIs(t, err, apple.ErrNotFound)
	}
	_, err = h.Apple.UpdatePolicy(ctx, apple.Scope{TenantID: tenant, SiteID: other.ID}, ids[2])
	require.ErrorIs(t, err, apple.ErrNotFound)
	form.Set("group_source", "site")
	require.Equal(t, 409, request("organization-admin", "POST", history, form).Code)
	form.Set("group_source", "organization")
	require.Equal(t, 403, request("scoped-operator", "POST", history, form).Code)
}

package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func exerciseAppleUpdateRemovals(t *testing.T, h *Handler, ctx context.Context, tenant, site int, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	scope := apple.Scope{TenantID: tenant, SiteID: site}
	sources := inventory.DeviceSources{Apple: true, Windows: h.Windows != nil}
	invite, err := h.Apple.Invite(ctx, scope, "Owned removal update target", "apple-console-admin")
	require.NoError(t, err)
	_, err = h.Model.DB.ExecContext(ctx, `UPDATE mdm_apple_devices SET status='enrolled',udid=id::text,model='iPhone16,1',os_version='18.6',supervised=true,certificate_expires_at=clock_timestamp()+interval '1 year' WHERE id=$1`, invite.DeviceID)
	require.NoError(t, err)
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
	plan, err := h.Apple.SaveUpdatePlan(ctx, "scoped-operator", h.Access, scope, "", 0, apple.UpdatePlanDefinition{Name: "Owned <removal update>", Platform: "ios", TargetVersion: "18.7.1", TargetBuild: "22H100", Deadline: "2026-10-01T18:00:00"})
	require.NoError(t, err)
	group, err := inventory.SaveDeviceGroup(ctx, h.Model.DB, h.Access, "scoped-operator", access.Scope{TenantID: tenant, SiteID: site}, "", 0, inventory.DeviceGroupDefinition{Name: "Owned <removal group>", Rule: inventory.DeviceGroupRule{Search: "Owned removal update target"}})
	require.NoError(t, err)
	base := fmt.Sprintf("/tenant/%d/site/%d/ios/update-plans/%s", tenant, site, plan.ID)
	preview, err := h.Apple.PreviewUpdatePlanGroup(ctx, "scoped-operator", h.Access, scope, sources, plan.ID, 1, group.ID, 1)
	require.NoError(t, err)
	require.Len(t, preview.Targets, 1)
	selection := []apple.UpdatePlanGroupSelection{preview.Targets[0].Selection}
	originalAssignment, err := h.Apple.AssignUpdatePlanFromGroup(ctx, "scoped-operator", h.Access, scope, sources, plan.ID, 1, group.ID, 1, uuid.NewString(), selection)
	require.NoError(t, err)
	base += "/group-assignments/" + originalAssignment.ID
	path := base + "/removals"
	previewPath := base + "/removal"
	require.Equal(t, 403, request("scoped-viewer", "GET", previewPath, nil).Code)
	view := request("scoped-operator", "GET", previewPath, nil)
	require.Equal(t, 200, view.Code)
	require.Equal(t, "no-store", view.Header().Get("Cache-Control"))
	require.True(t, strings.Contains(view.Body.String(), "data-update-removal-confirm"))
	p, err := h.Apple.PreviewUpdateGroupRemoval(ctx, "scoped-operator", h.Access, scope, plan.ID, originalAssignment.ID)
	require.NoError(t, err)
	require.Len(t, p.Devices, 1)
	form := url.Values{"request_key": {uuid.NewString()}, "devices": {invite.DeviceID + ":" + p.Devices[0].Selection.PolicyToken}}
	require.True(t, strings.Contains(view.Body.String(), p.Devices[0].Selection.PolicyToken))
	require.Equal(t, 403, request("scoped-viewer", "POST", path, form).Code)
	require.Equal(t, 400, request("scoped-operator", "POST", path, form).Code)
	form.Set("confirmed", "yes")
	form.Add("request_key", form.Get("request_key"))
	require.Equal(t, 400, request("scoped-operator", "POST", path, form).Code)
	form.Set("request_key", uuid.NewString())
	require.Equal(t, 400, request("scoped-operator", "POST", path+"?confirmed=yes", form).Code)
	changed := originalAssignment.Plan.Definition.Policy()
	changed.Deadline = "2026-11-01T18:00:00"
	require.NoError(t, h.Apple.SetUpdatePolicyWithAccess(ctx, scope, []string{invite.DeviceID}, &changed, "scoped-operator", h.Access))
	require.Equal(t, 409, request("scoped-operator", "POST", path, form).Code)
	excluded := request("scoped-operator", "GET", previewPath, nil)
	require.Equal(t, 200, excluded.Code)
	require.True(t, strings.Contains(excluded.Body.String(), "different configured update policy"))
	require.False(t, strings.Contains(excluded.Body.String(), "data-update-removal-confirm"))
	changed = originalAssignment.Plan.Definition.Policy()
	require.NoError(t, h.Apple.SetUpdatePolicyWithAccess(ctx, scope, []string{invite.DeviceID}, &changed, "scoped-operator", h.Access))
	removed := request("scoped-operator", "POST", path, form)
	require.Equal(t, 303, removed.Code)
	location := removed.Header().Get("Location")
	require.True(t, strings.HasPrefix(location, path+"/"))
	_, err = h.Apple.UpdatePolicy(ctx, scope, invite.DeviceID)
	require.ErrorIs(t, err, apple.ErrNotFound)
	detail := request("scoped-operator", "GET", location, nil)
	require.Equal(t, 200, detail.Code)
	require.Equal(t, "no-store", detail.Header().Get("Cache-Control"))
	require.True(t, strings.Contains(detail.Body.String(), "Original removal notification:"))
	require.Equal(t, 403, request("scoped-viewer", "GET", location, nil).Code)
	require.Equal(t, 403, request("scoped-viewer", "GET", path, nil).Code)
	require.Equal(t, 400, request("scoped-operator", "GET", location+"?unexpected=yes", nil).Code)
	require.Equal(t, 200, request("scoped-operator", "GET", path, nil).Code)
	require.Equal(t, 400, request("scoped-operator", "GET", path+"?before=invalid", nil).Code)
	var before, after int
	require.NoError(t, h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM mdm_apple_commands WHERE device_id=$1`, invite.DeviceID).Scan(&before))
	replay := request("scoped-operator", "POST", path, form)
	require.Equal(t, 303, replay.Code)
	require.Equal(t, location, replay.Header().Get("Location"))
	require.NoError(t, h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM mdm_apple_commands WHERE device_id=$1`, invite.DeviceID).Scan(&after))
	require.Equal(t, before, after)
	view = request("scoped-operator", "GET", previewPath, nil)
	require.Equal(t, 200, view.Code)
	require.True(t, strings.Contains(view.Body.String(), "no configured update policy to remove"))
	require.False(t, strings.Contains(view.Body.String(), "data-update-removal-confirm"))
}

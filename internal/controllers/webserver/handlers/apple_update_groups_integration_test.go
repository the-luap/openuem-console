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

func exerciseAppleUpdateGroups(t *testing.T, h *Handler, ctx context.Context, tenant, site int, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	scope := apple.Scope{TenantID: tenant, SiteID: site}
	sources := inventory.DeviceSources{Apple: true, Windows: h.Windows != nil}
	invite, err := h.Apple.Invite(ctx, scope, "Owned group update target", "apple-console-admin")
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
	plan, err := h.Apple.SaveUpdatePlan(ctx, "scoped-operator", h.Access, scope, "", 0, apple.UpdatePlanDefinition{Name: "Owned <group update>", Platform: "ios", TargetVersion: "18.7.1", TargetBuild: "22H100", Deadline: time.Now().UTC().Add(-time.Hour).Format("2006-01-02T15:04:05")})
	require.NoError(t, err)
	group, err := inventory.SaveDeviceGroup(ctx, h.Model.DB, h.Access, "scoped-operator", access.Scope{TenantID: tenant, SiteID: site}, "", 0, inventory.DeviceGroupDefinition{Name: "Owned <update group>", Rule: inventory.DeviceGroupRule{Search: "Owned group update target"}})
	require.NoError(t, err)
	base := fmt.Sprintf("/tenant/%d/site/%d/ios/update-plans/%s", tenant, site, plan.ID)
	previewPath := base + "/groups/" + group.ID + "/preview?revision=1&group_revision=1"
	for _, path := range []string{base + "/groups?revision=1", previewPath, base + "/group-assignments"} {
		require.Equal(t, 403, request("scoped-viewer", "GET", path, nil).Code)
		require.Equal(t, 200, request("scoped-operator", "GET", path, nil).Code)
	}
	page := request("scoped-operator", "GET", previewPath, nil)
	require.Contains(t, page.Body.String(), "No existing update policy.")
	require.Contains(t, page.Body.String(), "Owned &lt;update group&gt;")
	preview, err := h.Apple.PreviewUpdatePlanGroup(ctx, "scoped-operator", h.Access, scope, sources, plan.ID, 1, group.ID, 1)
	require.NoError(t, err)
	require.Len(t, preview.Targets, 1)
	f := url.Values{"expected_revision": {"1"}, "group_id": {group.ID}, "group_revision": {"1"}, "request_key": {uuid.NewString()}, "devices": {invite.DeviceID + ":" + preview.Targets[0].Selection.PolicyToken}}
	require.Equal(t, 400, request("scoped-operator", "POST", base+"/group-assignments", f).Code)
	f.Set("confirmed", "yes")
	policy := plan.Definition.Policy()
	policy.Deadline = "2026-11-01T18:00:00"
	require.NoError(t, h.Apple.SetUpdatePolicyWithAccess(ctx, scope, []string{invite.DeviceID}, &policy, "scoped-operator", h.Access))
	require.Equal(t, 409, request("scoped-operator", "POST", base+"/group-assignments", f).Code)
	page = request("scoped-operator", "GET", previewPath, nil)
	require.Contains(t, page.Body.String(), "Existing policy will be replaced:")
	preview, err = h.Apple.PreviewUpdatePlanGroup(ctx, "scoped-operator", h.Access, scope, sources, plan.ID, 1, group.ID, 1)
	require.NoError(t, err)
	f.Set("devices", invite.DeviceID+":"+preview.Targets[0].Selection.PolicyToken)
	f.Set("request_key", uuid.NewString())
	saved := request("scoped-operator", "POST", base+"/group-assignments", f)
	require.Equal(t, 303, saved.Code)
	location := saved.Header().Get("Location")
	require.True(t, strings.HasPrefix(location, base+"/group-assignments/"))
	detail := request("scoped-operator", "GET", location, nil)
	require.Equal(t, 200, detail.Code)
	require.Contains(t, detail.Body.String(), "Original group update assignment")
	require.Contains(t, detail.Body.String(), "Owned &lt;group update&gt;")
	require.Equal(t, 403, request("scoped-viewer", "GET", location, nil).Code)
	progressPath := location + "/progress"
	require.Equal(t, 403, request("scoped-viewer", "GET", progressPath, nil).Code)
	progressPage := request("scoped-operator", "GET", progressPath, nil)
	require.Equal(t, 200, progressPage.Code)
	require.Equal(t, "no-store", progressPage.Header().Get("Cache-Control"))
	require.Contains(t, progressPage.Body.String(), "Current cohort progress")
	require.Contains(t, progressPage.Body.String(), "No usable OS observation")
	require.Contains(t, progressPage.Body.String(), `data-deadline-reason="no_timezone"`)
	require.Equal(t, 400, request("scoped-operator", "GET", progressPath+"?record=yes", nil).Code)
	// Owned protocol-observation projection for the actual registered read path.
	// The Apple package separately exercises authenticated status ingestion.
	_, err = h.Model.DB.ExecContext(ctx, `INSERT INTO mdm_apple_os_observations(device_id,version,build,source,recorded_at) VALUES($1,'18.7.1','22H100','declarative_status',clock_timestamp())`, invite.DeviceID)
	require.NoError(t, err)
	progressPage = request("scoped-operator", "GET", progressPath, nil)
	require.Equal(t, 200, progressPage.Code)
	require.Contains(t, progressPage.Body.String(), "Target or newer OS reported")
	require.Contains(t, progressPage.Body.String(), "Reported OS: 18.7.1")
	_, err = h.Model.DB.ExecContext(ctx, `INSERT INTO mdm_apple_timezone_observations(device_id,name,source,recorded_at) VALUES($1,'UTC','device_information',clock_timestamp())`, invite.DeviceID)
	require.NoError(t, err)
	policy.Deadline = time.Now().UTC().Add(time.Hour).Format("2006-01-02T15:04:05")
	require.NoError(t, h.Apple.SetUpdatePolicyWithAccess(ctx, scope, []string{invite.DeviceID}, &policy, "scoped-operator", h.Access))
	progressPage = request("scoped-operator", "GET", progressPath, nil)
	require.Equal(t, 200, progressPage.Code)
	require.Contains(t, progressPage.Body.String(), `data-update-deadline="elapsed"`)
	require.Contains(t, progressPage.Body.String(), "A different update policy is currently configured.")
	require.Contains(t, progressPage.Body.String(), "Original target still required after estimated deadline: <strong>0</strong>")
	currentPage := request("scoped-viewer", "GET", fmt.Sprintf("/tenant/%d/site/%d/ios/%s", tenant, site, invite.DeviceID), nil)
	require.Equal(t, 200, currentPage.Code)
	require.Contains(t, currentPage.Body.String(), `data-update-deadline="pending"`)

	exerciseAppleUpdateEscalations(t, h, ctx, scope, plan, location, invite.DeviceID, request)

	definition := plan.Definition
	definition.Archived = true
	_, err = h.Apple.SaveUpdatePlan(ctx, "scoped-operator", h.Access, scope, plan.ID, 1, definition)
	require.NoError(t, err)
	require.NoError(t, h.Apple.SetUpdatePolicyWithAccess(ctx, scope, []string{invite.DeviceID}, nil, "scoped-operator", h.Access))
	var before, after int
	require.NoError(t, h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM mdm_apple_commands WHERE device_id=$1`, invite.DeviceID).Scan(&before))
	replay := request("scoped-operator", "POST", base+"/group-assignments", f)
	require.Equal(t, 303, replay.Code)
	require.Equal(t, location, replay.Header().Get("Location"))
	_, err = h.Apple.UpdatePolicy(ctx, scope, invite.DeviceID)
	require.ErrorIs(t, err, apple.ErrNotFound)
	f.Set("request_key", uuid.NewString())
	require.Equal(t, 409, request("scoped-operator", "POST", base+"/group-assignments", f).Code)
	f.Add("group_revision", "1")
	require.Equal(t, 400, request("scoped-operator", "POST", base+"/group-assignments", f).Code)
	require.NoError(t, h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM mdm_apple_commands WHERE device_id=$1`, invite.DeviceID).Scan(&after))
	require.Equal(t, before, after)
}

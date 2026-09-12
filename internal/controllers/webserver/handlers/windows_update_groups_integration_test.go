package handlers

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/mdm/windows"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func exerciseWindowsGroupAssignments(t *testing.T, h *Handler, ctx context.Context, scope access.Scope, original string, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	device := windowsAssignmentSecondDevice(t, h, ctx, scope, original, "Owned group target")
	group, err := inventory.SaveDeviceGroup(ctx, h.Model.DB, h.Access, "scoped-operator", scope, "", 0, inventory.DeviceGroupDefinition{Name: "Owned <Windows group>", Rule: inventory.DeviceGroupRule{Search: "Owned group target"}})
	require.NoError(t, err)
	zero := 0
	ring, err := h.Windows.SaveUpdateRing(ctx, "scoped-operator", scope, uuid.NewString(), uuid.NewString(), 0, "Owned group ring", windows.UpdatePolicy{QualityDeferralDays: &zero}, true)
	require.NoError(t, err)
	base := fmt.Sprintf("/tenant/%d/site/%d/windows/update-rings/%s/assign", scope.TenantID, scope.SiteID, ring.RingID)
	source := url.Values{"revision": {"1"}, "group": {group.ID}, "group_revision": {"1"}}
	w := request("scoped-operator", "GET", base+"/groups?revision=1", nil)
	require.Equal(t, 200, w.Code)
	require.Contains(t, w.Body.String(), "Owned &lt;Windows group&gt;")
	require.Equal(t, 403, request("scoped-viewer", "GET", base+"/groups?revision=1", nil).Code)
	w = request("scoped-operator", "GET", base+"?"+source.Encode(), nil)
	require.Equal(t, 200, w.Code)
	require.Contains(t, w.Body.String(), `name="group_id" value="`+group.ID+`"`)
	require.Contains(t, w.Body.String(), device)
	form := windowsAssignmentTestForm(device)
	form.Set("group_id", group.ID)
	form.Set("group_revision", "1")
	w = request("scoped-operator", "POST", base+"/preview", form)
	require.Equal(t, 200, w.Code)
	require.Contains(t, w.Body.String(), "Source device group")
	require.Contains(t, w.Body.String(), "Owned group target")
	bad, _ := url.ParseQuery(form.Encode())
	bad.Set("devices", original)
	require.Equal(t, 409, request("scoped-operator", "POST", base+"/preview", bad).Code)
	require.Equal(t, 400, request("scoped-operator", "POST", base+"/create", form).Code)
	form.Set("confirm_assignment", "yes")
	w = request("scoped-operator", "POST", base+"/create", form)
	require.Equal(t, 303, w.Code)
	location := w.Header().Get("Location")
	w = request("scoped-operator", "GET", location, nil)
	require.Equal(t, 200, w.Code)
	require.Contains(t, w.Body.String(), "Owned &lt;Windows group&gt;")
	definition := group.DeviceGroupDefinition
	definition.Archived = true
	_, err = inventory.SaveDeviceGroup(ctx, h.Model.DB, h.Access, "scoped-operator", scope, group.ID, 1, definition)
	require.NoError(t, err)
	require.Equal(t, 409, request("scoped-operator", "POST", base+"/preview", form).Code)
	w = request("scoped-operator", "POST", base+"/create", form)
	require.Equal(t, 303, w.Code)
	require.Equal(t, location, w.Header().Get("Location"))
	fresh, _ := url.ParseQuery(form.Encode())
	fresh.Set("request_key", uuid.NewString())
	require.Equal(t, 409, request("scoped-operator", "POST", base+"/create", fresh).Code)
	manual, _ := url.ParseQuery(form.Encode())
	manual.Del("group_id")
	manual.Del("group_revision")
	require.Equal(t, 409, request("scoped-operator", "POST", base+"/create", manual).Code)
	for _, field := range []string{"group_id", "group_revision"} {
		invalid, _ := url.ParseQuery(form.Encode())
		invalid.Del(field)
		require.Equal(t, 400, request("scoped-operator", "POST", base+"/create", invalid).Code)
	}
	for _, query := range []string{"?revision=1&group=%zz", "?revision=1&group_revision=1", "?revision=1&group=" + group.ID, "?revision=1&group_revision=1&group_revision=2&group=" + group.ID} {
		require.Equal(t, 400, request("scoped-operator", "GET", base+query, nil).Code)
	}
	// Schedules have their own fixed-target review; group fields cannot be ignored.
	scheduled := strings.TrimSuffix(base, "assign") + "schedule/preview"
	form.Set("not_before", time.Now().UTC().Add(time.Hour).Format(windowsScheduleTimeLayout))
	form.Set("activation_minutes", "60")
	require.Equal(t, 400, request("scoped-operator", "POST", scheduled, form).Code)
}

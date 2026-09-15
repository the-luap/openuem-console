package handlers

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/mdm/windows"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func exerciseWindowsGroupSchedules(t *testing.T, h *Handler, ctx context.Context, scope access.Scope, original string, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	previous := h.Windows
	h.Windows = h.Windows.WithGroupInventorySources(inventory.DeviceSources{Apple: h.Apple != nil, Windows: true})
	defer func() { h.Windows = previous }()
	device := windowsAssignmentSecondDevice(t, h, ctx, scope, original, "Owned group schedule target")
	group, err := inventory.SaveDeviceGroup(ctx, h.Model.DB, h.Access, "scoped-operator", scope, "", 0, inventory.DeviceGroupDefinition{Name: "Owned <schedule group>", Rule: inventory.DeviceGroupRule{Search: "Owned group schedule target"}})
	require.NoError(t, err)
	zero := 0
	ring, err := h.Windows.SaveUpdateRing(ctx, "scoped-operator", scope, uuid.NewString(), uuid.NewString(), 0, "Owned group schedule ring", windows.UpdatePolicy{QualityDeferralDays: &zero}, true)
	require.NoError(t, err)
	base := fmt.Sprintf("/tenant/%d/site/%d/windows/update-rings/%s/schedule", scope.TenantID, scope.SiteID, ring.RingID)
	w := request("scoped-operator", "GET", base+"/groups?revision=1", nil)
	require.Equal(t, 200, w.Code)
	require.Contains(t, w.Body.String(), "/schedule?group=")
	require.Equal(t, 403, request("scoped-viewer", "GET", base+"/groups?revision=1", nil).Code)
	q := url.Values{"revision": {"1"}, "group": {group.ID}, "group_revision": {"1"}}
	w = request("scoped-operator", "GET", base+"?"+q.Encode(), nil)
	require.Equal(t, 200, w.Code)
	require.Contains(t, w.Body.String(), `name="group_id" value="`+group.ID+`"`)
	form := windowsAssignmentTestForm(device)
	form.Set("group_id", group.ID)
	form.Set("group_revision", "1")
	form.Set("not_before", time.Now().UTC().Add(time.Hour).Format(windowsScheduleTimeLayout))
	form.Set("activation_minutes", "60")
	w = request("scoped-operator", "POST", base+"/preview", form)
	require.Equal(t, 200, w.Code)
	require.Contains(t, w.Body.String(), "checked again when the activation window opens")
	require.Contains(t, w.Body.String(), "Owned &lt;schedule group&gt;")
	require.Equal(t, 400, request("scoped-operator", "POST", base+"/create", form).Code)
	form.Set("confirm_schedule", "yes")
	w = request("scoped-operator", "POST", base+"/create", form)
	require.Equal(t, 303, w.Code)
	location := w.Header().Get("Location")
	w = request("scoped-operator", "GET", location, nil)
	require.Equal(t, 200, w.Code)
	require.Contains(t, w.Body.String(), "Owned &lt;schedule group&gt;")
	changed := group.DeviceGroupDefinition
	changed.Archived = true
	_, err = inventory.SaveDeviceGroup(ctx, h.Model.DB, h.Access, "scoped-operator", scope, group.ID, 1, changed)
	require.NoError(t, err)
	w = request("scoped-operator", "POST", base+"/create", form)
	require.Equal(t, 303, w.Code)
	require.Equal(t, location, w.Header().Get("Location"))
	fresh, _ := url.ParseQuery(form.Encode())
	fresh.Set("request_key", uuid.NewString())
	require.Equal(t, 409, request("scoped-operator", "POST", base+"/create", fresh).Code)
	for _, field := range []string{"group_id", "group_revision"} {
		bad, _ := url.ParseQuery(form.Encode())
		bad.Del(field)
		require.Equal(t, 400, request("scoped-operator", "POST", base+"/create", bad).Code)
	}
	manual, _ := url.ParseQuery(form.Encode())
	manual.Del("group_id")
	manual.Del("group_revision")
	require.Equal(t, 409, request("scoped-operator", "POST", base+"/create", manual).Code)
}

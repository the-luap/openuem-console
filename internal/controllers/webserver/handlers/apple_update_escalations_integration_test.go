package handlers

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/stretchr/testify/require"
)

func exerciseAppleUpdateEscalations(t *testing.T, h *Handler, ctx context.Context, scope apple.Scope, plan *apple.UpdatePlan, assignmentPath, deviceID string, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	policy := plan.Definition.Policy()
	require.NoError(t, h.Apple.SetUpdatePolicyWithAccess(ctx, scope, []string{deviceID}, &policy, "scoped-operator", h.Access))
	// Owned packet projections exercise registered handlers; authenticated protocol
	// ingestion and conservative clock decisions are covered in the Apple package.
	_, err := h.Model.DB.ExecContext(ctx, `UPDATE mdm_apple_os_observations SET version='18.6.2',build='22G100',recorded_at=clock_timestamp() WHERE device_id=$1`, deviceID)
	require.NoError(t, err)
	base := assignmentPath + "/escalation"
	list := fmt.Sprintf("/tenant/%d/site/%d/ios/update-alerts", scope.TenantID, scope.SiteID)
	review := func() ([]string, string) {
		t.Helper()
		page := request("scoped-operator", "GET", base, nil)
		require.Equal(t, 200, page.Code)
		require.Equal(t, "no-store", page.Header().Get("Cache-Control"))
		require.Contains(t, page.Body.String(), "Review update monitoring")
		keys := regexp.MustCompile(`name="request_key" value="([0-9a-f-]{36})"`).FindAllStringSubmatch(page.Body.String(), -1)
		revs := regexp.MustCompile(`name="configuration_revision" value="([0-9]+)"`).FindAllStringSubmatch(page.Body.String(), -1)
		require.NotEmpty(t, keys)
		require.Len(t, revs, len(keys))
		out := []string{}
		for _, key := range keys {
			out = append(out, key[1])
		}
		return out, revs[0][1]
	}
	keys, revision := review()
	require.Equal(t, "0", revision)
	require.Len(t, keys, 1)
	f := url.Values{"request_key": {keys[0]}, "configuration_revision": {revision}, "enabled": {"yes"}}
	for _, path := range []string{base, base + "/events", list} {
		require.Equal(t, 403, request("scoped-viewer", "GET", path, nil).Code)
	}
	require.Equal(t, 403, request("scoped-viewer", "POST", base, f).Code)
	require.Equal(t, 400, request("scoped-operator", "POST", base, f).Code)
	f.Set("confirmed", "yes")
	saved := request("scoped-operator", "POST", base, f)
	require.Equal(t, 303, saved.Code)
	location := saved.Header().Get("Location")
	require.True(t, strings.HasPrefix(location, base+"/events/"))
	page := request("scoped-operator", "GET", location, nil)
	require.Equal(t, 200, page.Code)
	require.Contains(t, page.Body.String(), "Monitoring configuration recorded")
	pass, err := h.Apple.ProcessDueUpdateEscalations(ctx, h.Access, 25)
	require.NoError(t, err)
	require.Equal(t, 1, pass.Attention)
	keys, revision = review()
	require.Len(t, keys, 2)
	require.Equal(t, "1", revision)
	assignmentID := assignmentPath[strings.LastIndex(assignmentPath, "/")+1:]
	current, err := h.Apple.UpdateEscalationDetails(ctx, "scoped-operator", h.Access, scope, plan.ID, assignmentID)
	require.NoError(t, err)
	ack := url.Values{"request_key": {keys[1]}, "configuration_revision": {revision}, "incident": {current.IncidentID}, "reason": {"Owned <script>acknowledgment</script>"}, "confirmed": {"yes"}}
	acknowledged := request("scoped-operator", "POST", base+"/acknowledge", ack)
	require.Equal(t, 303, acknowledged.Code)
	ackLocation := acknowledged.Header().Get("Location")
	page = request("scoped-operator", "GET", ackLocation, nil)
	require.Equal(t, 200, page.Code)
	require.NotContains(t, page.Body.String(), "<script>acknowledgment</script>")
	require.Contains(t, page.Body.String(), "Operator acknowledgment recorded")
	paused := url.Values{"request_key": {keys[0]}, "configuration_revision": {revision}, "enabled": {"no"}, "confirmed": {"yes"}}
	require.Equal(t, 303, request("scoped-operator", "POST", base, paused).Code)
	replay := request("scoped-operator", "POST", base, f)
	require.Equal(t, 303, replay.Code)
	require.Equal(t, location, replay.Header().Get("Location"))
	replay = request("scoped-operator", "POST", base+"/acknowledge", ack)
	require.Equal(t, 303, replay.Code)
	require.Equal(t, ackLocation, replay.Header().Get("Location"))
	current, err = h.Apple.UpdateEscalationDetails(ctx, "scoped-operator", h.Access, scope, plan.ID, assignmentID)
	require.NoError(t, err)
	require.False(t, current.Enabled)
	require.Equal(t, 1, current.OpenCount)
	require.Equal(t, 403, request("scoped-viewer", "GET", ackLocation, nil).Code)
	for _, path := range []string{list, base + "/events"} {
		page = request("scoped-operator", "GET", path, nil)
		require.Equal(t, 200, page.Code)
		require.Equal(t, "no-store", page.Header().Get("Cache-Control"))
	}
	for _, path := range []string{base + "?unknown=yes", list + "?before=invalid", base + "/events?before=invalid", ackLocation + "?unknown=yes"} {
		require.Equal(t, 400, request("scoped-operator", "GET", path, nil).Code)
	}
	_, err = h.Model.DB.ExecContext(ctx, `UPDATE mdm_apple_update_escalations SET encrypted_state=decode(repeat('00',40),'hex') WHERE id=$1`, current.ID)
	require.NoError(t, err)
	for _, path := range []string{base, list} {
		page = request("scoped-operator", "GET", path, nil)
		require.Equal(t, 503, page.Code)
		require.NotContains(t, page.Body.String(), "encrypted_state")
	}
	// Immutable events remain readable independently of mutable watch corruption.
	require.Equal(t, 200, request("scoped-operator", "GET", ackLocation, nil).Code)
}

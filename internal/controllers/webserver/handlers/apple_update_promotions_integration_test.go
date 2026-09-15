package handlers

import (
	"context"
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
	"github.com/stretchr/testify/require"
)

func exerciseAppleUpdatePromotions(t *testing.T, h *Handler, ctx context.Context, scope apple.Scope, plan *apple.UpdatePlan, group *inventory.DeviceGroup, assignmentPath, deviceID string, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	policy := plan.Definition.Policy()
	require.NoError(t, h.Apple.SetUpdatePolicyWithAccess(ctx, scope, []string{deviceID}, &policy, "scoped-operator", h.Access))
	// Owned projections test actual console routes. Authenticated OS report ingestion
	// and admission races are tested separately by the Apple package.
	_, err := h.Model.DB.ExecContext(ctx, `UPDATE mdm_apple_os_observations SET version='18.7.1',build='22H100',recorded_at=clock_timestamp() WHERE device_id=$1`, deviceID)
	require.NoError(t, err)
	invite, err := h.Apple.Invite(ctx, scope, "Owned group update target promotion", "apple-console-admin")
	require.NoError(t, err)
	_, err = h.Model.DB.ExecContext(ctx, `UPDATE mdm_apple_devices SET status='enrolled',udid=id::text,model='iPhone16,1',os_version='18.6.2',supervised=true,certificate_expires_at=clock_timestamp()+interval '1 year' WHERE id=$1`, invite.DeviceID)
	require.NoError(t, err)
	definition := plan.Definition
	definition.Name = "Owned <promotion destination>"
	definition.Deadline = time.Now().UTC().Add(24 * time.Hour).Format("2006-01-02T15:04:05")
	destination, err := h.Apple.SaveUpdatePlan(ctx, "scoped-operator", h.Access, scope, "", 0, definition)
	require.NoError(t, err)
	base := assignmentPath + "/promotion"
	history := assignmentPath + "/promotions"
	q := url.Values{"destination_plan": {destination.ID}, "revision": {"1"}}
	groups := base + "/groups?" + q.Encode()
	q.Set("group", group.ID)
	q.Set("group_revision", "1")
	reviewPath := base + "/review?" + q.Encode()
	for _, path := range []string{base, groups, reviewPath, history} {
		require.Equal(t, 403, request("scoped-viewer", "GET", path, nil).Code)
		page := request("scoped-operator", "GET", path, nil)
		require.Equal(t, 200, page.Code)
		require.Equal(t, "no-store", page.Header().Get("Cache-Control"))
	}
	review := func() url.Values {
		t.Helper()
		page := request("scoped-operator", "GET", reviewPath, nil)
		require.Equal(t, 200, page.Code)
		require.Contains(t, page.Body.String(), "Every original pilot enrollment currently meets")
		require.Contains(t, page.Body.String(), "Overlapping pilot devices are included")
		require.Contains(t, page.Body.String(), "Owned &lt;promotion destination&gt;")
		f := url.Values{}
		for _, field := range []string{"destination_plan", "expected_revision", "group_id", "group_revision", "request_key", "devices"} {
			match := regexp.MustCompile(`name="` + field + `" value="([^"]*)"`).FindStringSubmatch(page.Body.String())
			require.Len(t, match, 2)
			f.Set(field, html.UnescapeString(match[1]))
		}
		require.Len(t, strings.Split(f.Get("devices"), "\n"), 2)
		return f
	}
	f := review()
	require.Equal(t, 403, request("scoped-viewer", "POST", history, f).Code)
	require.Equal(t, 400, request("scoped-operator", "POST", history, f).Code)
	f.Set("confirmed", "yes")
	_, err = h.Model.DB.ExecContext(ctx, `UPDATE mdm_apple_os_observations SET recorded_at=clock_timestamp()-interval '25 hours' WHERE device_id=$1`, deviceID)
	require.NoError(t, err)
	page := request("scoped-operator", "GET", reviewPath, nil)
	require.Equal(t, 200, page.Code)
	require.NotContains(t, page.Body.String(), "data-promotion-confirm")
	require.Contains(t, page.Body.String(), "recorded before the original assignment")
	rejected := request("scoped-operator", "POST", history, f)
	require.Equal(t, 409, rejected.Code)
	require.NotContains(t, rejected.Body.String(), "MISSING")
	_, err = h.Model.DB.ExecContext(ctx, `UPDATE mdm_apple_os_observations SET recorded_at=clock_timestamp() WHERE device_id=$1`, deviceID)
	require.NoError(t, err)
	// A changed destination policy requires a fresh complete review.
	require.NoError(t, h.Apple.SetUpdatePolicyWithAccess(ctx, scope, []string{invite.DeviceID}, &policy, "scoped-operator", h.Access))
	require.Equal(t, 409, request("scoped-operator", "POST", history, f).Code)
	f = review()
	f.Set("confirmed", "yes")
	saved := request("scoped-operator", "POST", history, f)
	require.Equal(t, 303, saved.Code)
	location := saved.Header().Get("Location")
	require.True(t, strings.HasPrefix(location, history+"/"))
	for _, path := range []string{history, location} {
		page = request("scoped-operator", "GET", path, nil)
		require.Equal(t, 200, page.Code)
		require.Equal(t, "no-store", page.Header().Get("Cache-Control"))
		require.Equal(t, 403, request("scoped-viewer", "GET", path, nil).Code)
	}
	page = request("scoped-operator", "GET", location, nil)
	require.Contains(t, page.Body.String(), "Saved original pilot evidence")
	require.Contains(t, page.Body.String(), "OS report recorded")
	require.Contains(t, page.Body.String(), "does not establish destination installation")
	require.NotContains(t, page.Body.String(), "data-promotion-confirm")
	require.NoError(t, h.Apple.SetUpdatePolicyWithAccess(ctx, scope, []string{invite.DeviceID}, nil, "scoped-operator", h.Access))
	var before, after int
	require.NoError(t, h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM mdm_apple_commands WHERE device_id=$1`, invite.DeviceID).Scan(&before))
	replay := request("scoped-operator", "POST", history, f)
	require.Equal(t, 303, replay.Code)
	require.Equal(t, location, replay.Header().Get("Location"))
	_, err = h.Apple.UpdatePolicy(ctx, scope, invite.DeviceID)
	require.ErrorIs(t, err, apple.ErrNotFound)
	require.NoError(t, h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM mdm_apple_commands WHERE device_id=$1`, invite.DeviceID).Scan(&after))
	require.Equal(t, before, after)
	f.Set("request_key", uuid.NewString())
	require.Equal(t, 409, request("scoped-operator", "POST", history, f).Code)
	for _, path := range []string{base + "?unknown=yes", groups + "&revision=1", reviewPath + "&group_revision=1", location + "?unknown=yes", history + "?before=invalid"} {
		require.Equal(t, 400, request("scoped-operator", "GET", path, nil).Code)
	}
	require.Equal(t, 404, request("scoped-operator", "GET", history+"?before="+uuid.NewString(), nil).Code)
	// A valid scoped source elsewhere does not become this pilot's receipt.
	require.Equal(t, 404, request("scoped-operator", "GET", strings.Replace(location, plan.ID, destination.ID, 1), nil).Code)
}

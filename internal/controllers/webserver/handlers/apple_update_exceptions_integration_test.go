package handlers

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/stretchr/testify/require"
)

func exerciseAppleUpdateExceptions(t *testing.T, h *Handler, ctx context.Context, tenant, site int, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	scope := apple.Scope{TenantID: tenant, SiteID: site}
	invite, err := h.Apple.Invite(ctx, scope, "Owned exception route target", "apple-console-admin")
	require.NoError(t, err)
	_, err = h.Model.DB.ExecContext(ctx, `UPDATE mdm_apple_devices SET status='enrolled',udid=id::text,model='iPhone16,1',os_version='18.6',supervised=true,certificate_expires_at=clock_timestamp()+interval '1 year' WHERE id=$1`, invite.DeviceID)
	require.NoError(t, err)
	seedPolicy := func() {
		t.Helper()
		_, err := h.Model.DB.ExecContext(ctx, `INSERT INTO mdm_apple_update_policies(tenant_id,device_id,target_version,target_build,deadline) VALUES($1,$2,'18.7.1','22H100','2026-10-01T18:00:00')`, tenant, invite.DeviceID)
		require.NoError(t, err)
	}
	seedPolicy()
	devicePath := fmt.Sprintf("/tenant/%d/site/%d/ios/%s", tenant, site, invite.DeviceID)
	base := devicePath + "/update-exceptions"
	review := func() (string, []string) {
		t.Helper()
		page := request("scoped-operator", "GET", base+"/review", nil)
		require.Equal(t, 200, page.Code)
		require.Equal(t, "no-store", page.Header().Get("Cache-Control"))
		body := page.Body.String()
		tokens := regexp.MustCompile(`name="review_token" value="([0-9a-f]{64})"`).FindAllStringSubmatch(body, -1)
		keys := regexp.MustCompile(`name="request_key" value="([0-9a-f-]{36})"`).FindAllStringSubmatch(body, -1)
		require.NotEmpty(t, tokens)
		require.Len(t, keys, len(tokens))
		out := []string{}
		for i, key := range keys {
			require.Equal(t, tokens[0][1], tokens[i][1])
			out = append(out, key[1])
		}
		return tokens[0][1], out
	}
	token, keys := review()
	require.Len(t, keys, 1)
	f := url.Values{"request_key": {keys[0]}, "review_token": {token}, "kind": {"pause"}, "reason": {"Owned <script>exception</script>"}, "expires_at": {time.Now().UTC().Add(time.Hour).Format("2006-01-02T15:04")}}
	require.Equal(t, 403, request("scoped-viewer", "GET", base+"/review", nil).Code)
	require.Equal(t, 403, request("scoped-viewer", "POST", base, f).Code)
	require.Equal(t, 400, request("scoped-operator", "POST", base, f).Code)
	f.Set("confirmed", "yes")
	f.Add("reason", "duplicate")
	require.Equal(t, 400, request("scoped-operator", "POST", base, f).Code)
	f.Set("reason", "Owned <script>exception</script>")
	saved := request("scoped-operator", "POST", base, f)
	require.Equal(t, 303, saved.Code)
	location := saved.Header().Get("Location")
	require.True(t, strings.HasPrefix(location, base+"/"))
	page := request("scoped-operator", "GET", location, nil)
	require.Equal(t, 200, page.Code)
	require.Contains(t, page.Body.String(), "Original update exception event")
	require.NotContains(t, page.Body.String(), "<script>exception</script>")
	require.Equal(t, 403, request("scoped-viewer", "GET", location, nil).Code)
	current := request("scoped-viewer", "GET", devicePath, nil)
	require.Equal(t, 200, current.Code)
	require.Contains(t, current.Body.String(), `data-update-exception-active="true"`)
	require.NotContains(t, current.Body.String(), "Manage update exceptions")
	a, err := h.Apple.AssessDeviceUpdate(ctx, "scoped-operator", h.Access, scope, invite.DeviceID)
	require.NoError(t, err)
	require.Nil(t, a.Policy)
	blocked := request("scoped-operator", "POST", devicePath+"/update", url.Values{"expected_policy": {a.PolicyToken}, "target_release": {"18.7.1/22H100"}, "deadline": {"2026-10-01T18:00"}})
	require.Equal(t, 409, blocked.Code)
	require.Contains(t, blocked.Body.String(), "temporary update exception is active")
	token, keys = review()
	require.Len(t, keys, 2)
	resume := url.Values{"request_key": {keys[1]}, "review_token": {token}, "kind": {"resume"}, "reason": {"Owned completed maintenance"}, "confirmed": {"yes"}}
	ended := request("scoped-operator", "POST", base, resume)
	require.Equal(t, 303, ended.Code)
	endLocation := ended.Header().Get("Location")
	page = request("scoped-operator", "GET", endLocation, nil)
	require.Equal(t, 200, page.Code)
	require.Contains(t, page.Body.String(), "no device command was queued by this action")
	_, err = h.Apple.UpdatePolicy(ctx, scope, invite.DeviceID)
	require.ErrorIs(t, err, apple.ErrNotFound)
	seedPolicy()
	var before, after int
	require.NoError(t, h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM mdm_apple_commands WHERE device_id=$1`, invite.DeviceID).Scan(&before))
	replay := request("scoped-operator", "POST", base, f)
	require.Equal(t, 303, replay.Code)
	require.Equal(t, location, replay.Header().Get("Location"))
	_, err = h.Apple.UpdatePolicy(ctx, scope, invite.DeviceID)
	require.NoError(t, err)
	require.NoError(t, h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM mdm_apple_commands WHERE device_id=$1`, invite.DeviceID).Scan(&after))
	require.Equal(t, before, after)
	page = request("scoped-operator", "GET", base, nil)
	require.Equal(t, 200, page.Code)
	require.Equal(t, 2, strings.Count(page.Body.String(), "Open original exception event"))
	require.Equal(t, 403, request("scoped-viewer", "GET", base, nil).Code)
	for _, path := range []string{base + "/review?unknown=yes", location + "?unknown=yes", base + "?before=invalid"} {
		require.Equal(t, 400, request("scoped-operator", "GET", path, nil).Code)
	}
	_, err = h.Model.DB.ExecContext(ctx, `ALTER TABLE mdm_apple_update_exceptions DISABLE TRIGGER mdm_apple_keep_update_exception`)
	require.NoError(t, err)
	_, err = h.Model.DB.ExecContext(ctx, `UPDATE mdm_apple_update_exceptions SET encrypted_intent=decode(repeat('00',40),'hex') WHERE id=$1`, strings.TrimPrefix(endLocation, base+"/"))
	_, restoreErr := h.Model.DB.ExecContext(ctx, `ALTER TABLE mdm_apple_update_exceptions ENABLE TRIGGER mdm_apple_keep_update_exception`)
	require.NoError(t, err)
	require.NoError(t, restoreErr)
	for _, path := range []string{base, base + "/review", endLocation, devicePath} {
		response := request("scoped-operator", "GET", path, nil)
		require.Equal(t, 503, response.Code)
		require.NotContains(t, response.Body.String(), "encrypted_intent")
	}
}

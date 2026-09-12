package handlers

import (
	"context"
	"encoding/json"
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

func exerciseAppleUpdateForms(t *testing.T, h *Handler, ctx context.Context, tenant, site int, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	scope := apple.Scope{TenantID: tenant, SiteID: site}
	invite, err := h.Apple.Invite(ctx, scope, "Owned update form target", "apple-console-admin")
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
	path := fmt.Sprintf("/tenant/%d/site/%d/ios/%s/update", tenant, site, invite.DeviceID)
	reviewToken := func() string {
		t.Helper()
		response := request("scoped-operator", "GET", strings.TrimSuffix(path, "/update"), nil)
		require.Equal(t, 200, response.Code)
		matches := regexp.MustCompile(`name="expected_policy" value="([0-9a-f]{64})"`).FindAllStringSubmatch(response.Body.String(), -1)
		require.NotEmpty(t, matches)
		for _, match := range matches {
			require.Equal(t, matches[0][1], match[1])
		}
		return matches[0][1]
	}
	valid := url.Values{"expected_policy": {reviewToken()}, "target_release": {"18.7.1/22H100"}, "deadline": {"2026-10-01T18:00"}, "details_url": {"https://example.test/update"}}
	require.Equal(t, 403, request("scoped-viewer", "POST", path, valid).Code)
	require.Equal(t, 303, request("scoped-operator", "POST", path, valid).Code)
	require.Equal(t, 409, request("scoped-operator", "POST", path, valid).Code)
	require.Equal(t, 409, request("scoped-operator", "POST", path, url.Values{"expected_policy": {valid.Get("expected_policy")}, "remove": {"true"}}).Code)
	configuredToken := reviewToken()
	stored, err := h.Apple.UpdatePolicy(ctx, scope, invite.DeviceID)
	require.NoError(t, err)
	require.Equal(t, "18.7.1", stored.TargetVersion)
	devicePath := strings.TrimSuffix(path, "/update")
	readAssessment := func() string {
		t.Helper()
		response := request("scoped-viewer", "GET", devicePath, nil)
		require.Equal(t, 200, response.Code)
		body := response.Body.String()
		start := strings.Index(body, "data-device-update-assessment")
		require.GreaterOrEqual(t, start, 0)
		section := strings.SplitN(body[start:], "</section>", 2)[0]
		require.False(t, strings.Contains(section, "<form"), "Viewer received an update mutation form")
		return section
	}
	section := readAssessment()
	require.Contains(t, section, `data-update-deadline="unverified"`)
	require.Contains(t, section, "No usable device time zone was reported")
	require.True(t, strings.Contains(section, "No usable OS observation"))
	require.False(t, strings.Contains(section, "Reported OS version:"), "Merged inventory was used as packet evidence")
	_, err = h.Model.DB.ExecContext(ctx, `INSERT INTO mdm_apple_os_observations(device_id,version,build,source,recorded_at) VALUES($1,'18.7.1','22H100','declarative_status',clock_timestamp())`, invite.DeviceID)
	require.NoError(t, err)
	section = readAssessment()
	require.True(t, strings.Contains(section, "Up to date") && strings.Contains(section, "Reported build: 22H100"))
	// Owned projections exercise the registered viewer route; authenticated
	// collection and rollback are covered in the Apple protocol tests.
	_, err = h.Model.DB.ExecContext(ctx, `INSERT INTO mdm_apple_timezone_observations(device_id,name,source,recorded_at) VALUES($1,'UTC','device_information',clock_timestamp())`, invite.DeviceID)
	require.NoError(t, err)
	for _, example := range []struct {
		state  string
		offset time.Duration
	}{{"elapsed", -time.Hour}, {"pending", time.Hour}} {
		_, err = h.Model.DB.ExecContext(ctx, `UPDATE mdm_apple_update_policies SET deadline=$2 WHERE device_id=$1`, invite.DeviceID, time.Now().UTC().Add(example.offset).Format("2006-01-02T15:04:05"))
		require.NoError(t, err)
		section = readAssessment()
		require.Contains(t, section, `data-update-deadline="`+example.state+`"`)
		require.Contains(t, section, "Reported device time zone: UTC")
		require.Contains(t, section, "Up to date")
	}
	_, err = h.Model.DB.ExecContext(ctx, `UPDATE mdm_apple_update_policies SET deadline=$2 WHERE device_id=$1`, invite.DeviceID, stored.Deadline)
	require.NoError(t, err)
	_, err = h.Model.DB.ExecContext(ctx, `UPDATE mdm_apple_timezone_observations SET recorded_at=clock_timestamp()-interval '25 hours' WHERE device_id=$1`, invite.DeviceID)
	require.NoError(t, err)
	section = readAssessment()
	require.Contains(t, section, `data-deadline-reason="stale_timezone"`)
	require.NotContains(t, section, "Estimated deadline (UTC):")
	require.Contains(t, section, "Up to date")
	_, err = h.Model.DB.ExecContext(ctx, `UPDATE mdm_apple_os_observations SET build='' WHERE device_id=$1`, invite.DeviceID)
	require.NoError(t, err)
	section = readAssessment()
	require.True(t, strings.Contains(section, "build was not reported together"))
	require.False(t, strings.Contains(section, "Up to date"))
	_, err = h.Model.DB.ExecContext(ctx, `UPDATE mdm_apple_os_observations SET build='22H100' WHERE device_id=$1`, invite.DeviceID)
	require.NoError(t, err)
	_, err = h.Model.DB.ExecContext(ctx, `UPDATE mdm_apple_update_policies SET status='failed',error=$2 WHERE device_id=$1`, invite.DeviceID, "Owned <script>policy failure</script>")
	require.NoError(t, err)
	section = readAssessment()
	require.True(t, strings.Contains(section, "Up to date") && strings.Contains(section, "policy failure"))
	require.False(t, strings.Contains(section, "<script>policy failure</script>"))
	_, err = h.Model.DB.ExecContext(ctx, `UPDATE mdm_apple_update_policies SET error=repeat('owned-error',1000) WHERE device_id=$1`, invite.DeviceID)
	require.NoError(t, err)
	section = readAssessment()
	require.True(t, strings.Contains(section, "exceed the display limit"))
	require.False(t, strings.Contains(section, "owned-error"))
	_, err = h.Model.DB.ExecContext(ctx, `UPDATE mdm_apple_update_policies SET status=repeat('owned-status',1000) WHERE device_id=$1`, invite.DeviceID)
	require.NoError(t, err)
	unavailable := request("scoped-viewer", "GET", devicePath, nil)
	require.Equal(t, 503, unavailable.Code)
	require.False(t, strings.Contains(unavailable.Body.String(), "owned-status"))
	_, err = h.Model.DB.ExecContext(ctx, `UPDATE mdm_apple_update_policies SET status='waiting',error='' WHERE device_id=$1`, invite.DeviceID)
	require.NoError(t, err)
	for _, bad := range []url.Values{
		{"remove": {"true", "true"}},
		{"remove": {"true"}, "deadline": {"2026-10-01T18:00"}},
		{"target_release": {"18.7.1/22H100", "18.8/22I1"}, "deadline": {"2026-10-01T18:00"}},
		{"target_release": {"18.7.1/22H100"}, "deadline": {"2026-10-01T18:00", "2026-11-01T18:00"}},
		{"target_release": {"18.7.1/22H100"}},
	} {
		bad.Set("expected_policy", configuredToken)
		require.Equal(t, 400, request("scoped-operator", "POST", path, bad).Code)
	}
	require.Equal(t, 400, request("scoped-operator", "POST", path, url.Values{"remove": {"true"}}).Code)
	require.Equal(t, 400, request("scoped-operator", "POST", path+"?remove=true", valid).Code)
	var count int
	require.NoError(t, h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM mdm_apple_commands WHERE device_id=$1 AND request_type='DeclarativeManagement' AND status='queued'`, invite.DeviceID).Scan(&count))
	require.Equal(t, 1, count)
	require.Equal(t, 403, request("scoped-viewer", "POST", path, url.Values{"remove": {"true"}}).Code)
	require.Equal(t, 303, request("scoped-operator", "POST", path, url.Values{"remove": {"true"}, "expected_policy": {configuredToken}}).Code)
	_, err = h.Apple.UpdatePolicy(ctx, scope, invite.DeviceID)
	require.ErrorIs(t, err, apple.ErrNotFound)
	section = readAssessment()
	require.False(t, strings.Contains(section, "data-device-update-policy"))
	require.True(t, strings.Contains(section, "Reported OS version: 18.7.1"))
}

package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
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
	valid := url.Values{"target_release": {"18.7.1/22H100"}, "deadline": {"2026-10-01T18:00"}, "details_url": {"https://example.test/update"}}
	require.Equal(t, 403, request("scoped-viewer", "POST", path, valid).Code)
	require.Equal(t, 303, request("scoped-operator", "POST", path, valid).Code)
	stored, err := h.Apple.UpdatePolicy(ctx, scope, invite.DeviceID)
	require.NoError(t, err)
	require.Equal(t, "18.7.1", stored.TargetVersion)
	for _, bad := range []url.Values{
		{"remove": {"true", "true"}},
		{"remove": {"true"}, "deadline": {"2026-10-01T18:00"}},
		{"target_release": {"18.7.1/22H100", "18.8/22I1"}, "deadline": {"2026-10-01T18:00"}},
		{"target_release": {"18.7.1/22H100"}, "deadline": {"2026-10-01T18:00", "2026-11-01T18:00"}},
		{"target_release": {"18.7.1/22H100"}},
	} {
		require.Equal(t, 400, request("scoped-operator", "POST", path, bad).Code)
	}
	require.Equal(t, 400, request("scoped-operator", "POST", path+"?remove=true", valid).Code)
	var count int
	require.NoError(t, h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM mdm_apple_commands WHERE device_id=$1 AND request_type='DeclarativeManagement' AND status='queued'`, invite.DeviceID).Scan(&count))
	require.Equal(t, 1, count)
	require.Equal(t, 403, request("scoped-viewer", "POST", path, url.Values{"remove": {"true"}}).Code)
	require.Equal(t, 303, request("scoped-operator", "POST", path, url.Values{"remove": {"true"}}).Code)
	_, err = h.Apple.UpdatePolicy(ctx, scope, invite.DeviceID)
	require.ErrorIs(t, err, apple.ErrNotFound)
}

package handlers

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/stretchr/testify/require"
)

func exerciseAppleUpdatePlans(t *testing.T, h *Handler, ctx context.Context, tenant, site int, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	base := fmt.Sprintf("/tenant/%d/site/%d/ios/update-plans", tenant, site)
	scope := apple.Scope{TenantID: tenant, SiteID: site}
	f := url.Values{"expected_revision": {"0"}, "name": {"Owned <Apple pilot>"}, "description": {"Owned reviewed update source"}, "platform": {"ios"}, "target_version": {"18.7.1"}, "target_build": {"22H100"}, "deadline": {"2026-10-01T18:00"}, "details_url": {"https://example.test/owned/update"}}
	list := request("scoped-viewer", "GET", base, nil)
	require.Equal(t, 200, list.Code)
	require.NotContains(t, list.Body.String(), "Save plan revision")
	require.Equal(t, 403, request("scoped-viewer", "POST", base, f).Code)
	require.Equal(t, 400, request("organization-admin", "POST", fmt.Sprintf("/tenant/%d/ios/update-plans", tenant), f).Code)
	saved := request("scoped-operator", "POST", base, f)
	require.Equal(t, 303, saved.Code)
	location := saved.Header().Get("Location")
	require.True(t, strings.HasPrefix(location, base+"/"))
	id := strings.TrimPrefix(location, base+"/")
	original := request("scoped-viewer", "GET", location, nil)
	require.Equal(t, 200, original.Code)
	require.Contains(t, original.Body.String(), "Owned &lt;Apple pilot&gt;")
	require.NotContains(t, original.Body.String(), "Save plan revision")
	f.Set("expected_revision", "1")
	f.Set("name", "Revised <Apple pilot>")
	f.Set("archived", "yes")
	require.Equal(t, 303, request("scoped-operator", "POST", location, f).Code)
	require.Equal(t, 409, request("scoped-operator", "POST", location, f).Code)
	current, history, _, err := h.Apple.UpdatePlanHistory(ctx, "scoped-viewer", h.Access, scope, id, 0)
	require.NoError(t, err)
	require.Equal(t, 2, current.Revision)
	require.True(t, current.Definition.Archived)
	require.Len(t, history, 2)
	require.Equal(t, "Owned <Apple pilot>", history[1].Definition.Name)
	f.Set("expected_revision", "2")
	f.Add("target_build", "22H101")
	require.Equal(t, 400, request("scoped-operator", "POST", location, f).Code)
	f.Set("target_build", "22H100")
	require.Equal(t, 400, request("scoped-operator", "POST", location+"?archived=no", f).Code)
	require.Equal(t, 400, request("scoped-viewer", "GET", location+"?before=2&before=1", nil).Code)
	require.Equal(t, 400, request("scoped-viewer", "GET", location+"?before=3", nil).Code)
	require.Equal(t, 200, request("scoped-viewer", "GET", location+"?before=2", nil).Code)
	current, _, _, err = h.Apple.UpdatePlanHistory(ctx, "scoped-viewer", h.Access, scope, id, 0)
	require.NoError(t, err)
	require.Equal(t, 2, current.Revision)
}

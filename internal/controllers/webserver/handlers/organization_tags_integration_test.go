package handlers

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func exerciseOrganizationTags(t *testing.T, h *Handler, ctx context.Context, tenant, otherTenant int, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	base := fmt.Sprintf("/tenant/%d/admin/tags", tenant)
	for actor, role := range map[string]access.Role{"organization-tag-reader": access.Viewer, "organization-tag-operator": access.Operator} {
		require.NoError(t, h.Model.Client.User.Create().SetID(actor).SetName(actor).SetEmail(actor+"@example.test").SetUse2fa(false).SetRegister(nats.REGISTER_COMPLETE).Exec(ctx))
		require.NoError(t, h.Access.ReplaceGrants(ctx, "apple-console-admin", actor, 0, []access.Grant{{Role: role, Scope: access.Scope{TenantID: tenant}}}))
	}
	form := func(revision string) url.Values {
		v := url.Values{"name": {"Owned <organization tag>"}, "description": {"Scoped description"}, "color": {"#123456"}}
		if revision != "" {
			v.Set("revision", revision)
		}
		return v
	}
	w := request("organization-admin", "POST", base, form(""))
	require.Equal(t, 303, w.Code)
	detail := w.Header().Get("Location")
	require.True(t, strings.HasPrefix(detail, base+"/"))
	for _, actor := range []string{"apple-console-admin", "organization-admin", "organization-tag-reader", "organization-tag-operator"} {
		w = request(actor, "GET", detail, nil)
		require.Equal(t, 200, w.Code)
		require.Contains(t, w.Body.String(), "Owned &lt;organization tag&gt;")
		require.NotContains(t, w.Body.String(), "private-inventory-notes")
		require.Equal(t, actor == "apple-console-admin" || actor == "organization-admin", strings.Contains(w.Body.String(), `aria-label="Edit tag"`))
		require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
		require.Equal(t, 200, request(actor, "GET", base, nil).Code)
	}
	for _, actor := range []string{"scoped-viewer", "scoped-operator"} {
		require.Equal(t, 403, request(actor, "GET", base, nil).Code)
		require.Equal(t, 403, request(actor, "GET", detail, nil).Code)
	}
	for _, actor := range []string{"organization-tag-reader", "organization-tag-operator", "scoped-operator"} {
		require.Equal(t, 403, request(actor, "POST", base, form("")).Code)
	}
	revision := func() string {
		w := request("organization-admin", "GET", detail, nil)
		require.Equal(t, 200, w.Code)
		match := regexp.MustCompile(`name="revision" value="([a-f0-9-]+)"`).FindStringSubmatch(w.Body.String())
		require.Len(t, match, 2)
		return match[1]
	}
	original := revision()
	for _, bad := range []struct{ key, value string }{{"name", ""}, {"color", "red"}, {"tenant_id", "99"}, {"tagId", "1"}, {"revision", "invalid"}, {"description", "line\nbreak"}} {
		v := form(original)
		v.Set(bad.key, bad.value)
		require.Equal(t, 400, request("organization-admin", "POST", detail, v).Code)
	}
	v := form(original)
	v.Add("name", "Another")
	require.Equal(t, 400, request("organization-admin", "POST", detail, v).Code)
	v = form(original)
	v.Set("csrf", "wrong")
	require.Equal(t, 403, request("organization-admin", "POST", detail, v).Code)
	require.Equal(t, 400, request("organization-admin", "POST", detail+"?name=override", form(original)).Code)
	require.Equal(t, 400, request("organization-admin", "POST", detail, form("")).Code)
	for _, q := range []string{"?after=0", "?after=01", "?q=one&q=two", "?site_id=2", "?q=%zz"} {
		require.Equal(t, 400, request("organization-admin", "GET", base+q, nil).Code)
	}
	changed := form(original)
	changed.Set("description", "Updated definition")
	require.Equal(t, 303, request("organization-admin", "POST", detail, changed).Code)
	require.Equal(t, 409, request("organization-admin", "POST", detail, form(original)).Code)
	current := revision()
	require.NotEqual(t, original, current)
	foreign := fmt.Sprintf("/tenant/%d/admin/tags/%s", otherTenant, strings.TrimPrefix(detail, base+"/"))
	require.Equal(t, 404, request("apple-console-admin", "GET", foreign, nil).Code)
	require.Equal(t, 403, request("organization-admin", "GET", foreign, nil).Code)
	require.Equal(t, 404, request("apple-console-admin", "POST", foreign, form(current)).Code)
	remove := func(revision string) url.Values { return url.Values{"revision": {revision}, "confirm": {"delete"}} }
	require.Equal(t, 400, request("organization-admin", "POST", detail+"/delete", url.Values{"revision": {current}}).Code)
	require.Equal(t, 409, request("organization-admin", "POST", detail+"/delete", remove(original)).Code)
	id, err := strconv.Atoi(strings.TrimPrefix(detail, base+"/"))
	require.NoError(t, err)
	child, err := h.Model.Client.Tag.Create().SetTag("Owned tag child").SetColor("#123456").SetTenantID(tenant).SetParentID(id).Save(ctx)
	require.NoError(t, err)
	require.Equal(t, 409, request("organization-admin", "POST", detail+"/delete", remove(current)).Code)
	w = request("organization-admin", "GET", detail, nil)
	require.Equal(t, 200, w.Code)
	require.NotContains(t, w.Body.String(), `aria-label="Delete tag"`)
	require.NoError(t, h.Model.Client.Tag.DeleteOneID(child.ID).Exec(ctx))
	require.Equal(t, 405, request("apple-console-admin", "DELETE", base, url.Values{"tagId": {strconv.Itoa(id)}}).Code)
	require.Equal(t, 303, request("organization-admin", "POST", detail+"/delete", remove(current)).Code)
	require.Equal(t, 404, request("organization-admin", "GET", detail, nil).Code)
	var deleted int
	require.NoError(t, h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM uem_inventory_audit WHERE tenant_id=$1 AND site_id=0 AND actor='organization-admin' AND action='inventory.tags.delete'`, tenant).Scan(&deleted))
	require.Equal(t, 1, deleted)
}

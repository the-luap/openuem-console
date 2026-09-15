package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/nats"
	consolemiddleware "github.com/open-uem/openuem-console/internal/controllers/router/middleware"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func exerciseNetbirdPackageRoutes(t *testing.T, h *Handler, e *echo.Echo, ctx context.Context, tenant, foreign int) {
	t.Helper()
	// Use the registered routes with production CSRF middleware. The shared
	// legacy fixture injects a different constant form token; that cannot model
	// both native forms and cookie/header validation in one Echo context.
	e = echo.New()
	e.Use(consolemiddleware.CSRF())
	h.Register(e, 3)
	previousKey := h.EncryptionMasterKey
	h.EncryptionMasterKey = strings.Repeat("k", 32)
	defer func() { h.EncryptionMasterKey = previousKey }()
	require.NoError(t, inventory.Migrate(ctx, h.Model.DB))
	for actor, role := range map[string]access.Role{"package-viewer": access.Viewer, "package-operator": access.Operator} {
		require.NoError(t, h.Model.Client.User.Create().SetID(actor).SetName(actor).SetEmail(actor+"@example.test").SetUse2fa(false).SetRegister(nats.REGISTER_COMPLETE).Exec(ctx))
		require.NoError(t, h.Access.ReplaceGrants(ctx, "apple-console-admin", actor, 0, []access.Grant{{Role: role, Scope: access.Scope{TenantID: tenant}}}))
	}
	request := ownedTagHTTPRequest(t, h, e, ctx)
	base := fmt.Sprintf("/tenant/%d/netbird/packages", tenant)
	id := uuid.NewString()
	form := url.Values{"approval_id": {id}, "target": {"linux/arm64/deb"}, "version": {"0.78.1"}, "source_url": {"https://packages.example.invalid/netbird.deb?private=owned-route-source"}, "size": {"1234"}, "sha256": {strings.Repeat("a", 64)}, "verification": {"Owned signing review 42"}, "confirmed": {"yes"}}
	form.Set("csrf", strings.Repeat("t", 32))
	for _, actor := range []string{"apple-console-admin", "organization-admin", "package-viewer", "package-operator"} {
		response := request(actor, "GET", base, nil, "")
		require.Equal(t, 200, response.Code)
		require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
	}
	for _, actor := range []string{"scoped-viewer", "scoped-operator", "unassigned-user"} {
		require.Equal(t, 403, request(actor, "GET", base, nil, "").Code)
	}
	for _, actor := range []string{"package-viewer", "package-operator", "scoped-viewer", "scoped-operator"} {
		require.Equal(t, 403, request(actor, "GET", base+"/new", nil, "").Code)
		require.Equal(t, 403, request(actor, "POST", base, form, "console-test-token").Code)
	}
	require.Equal(t, 200, request("organization-admin", "GET", base+"/new", nil, "").Code)
	require.Equal(t, 403, request("organization-admin", "POST", base, form, "wrong").Code)
	for _, change := range []string{"confirmation", "duplicate", "unknown", "query", "target", "size", "source", "hash"} {
		bad := url.Values{}
		for k, v := range form {
			bad[k] = append([]string{}, v...)
		}
		path := base
		switch change {
		case "confirmation":
			bad.Del("confirmed")
		case "duplicate":
			bad["sha256"] = []string{form.Get("sha256"), form.Get("sha256")}
		case "unknown":
			bad.Set("tenant_id", fmt.Sprint(foreign))
		case "query":
			path += "?source_url=private"
		case "target":
			bad.Set("target", "macos/386/pkg")
		case "size":
			bad.Set("size", "01234")
		case "source":
			bad.Set("source_url", "http://packages.invalid/netbird.deb")
		case "hash":
			bad.Set("sha256", strings.Repeat("A", 64))
		}
		require.Equal(t, 400, request("organization-admin", "POST", path, bad, "console-test-token").Code, change)
	}
	var count int
	require.NoError(t, h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM uem_netbird_packages WHERE id=$1`, id).Scan(&count))
	require.Zero(t, count)
	response := request("organization-admin", "POST", base, form, "console-test-token")
	require.Equal(t, 204, response.Code)
	require.Equal(t, base+"/"+id, response.Header().Get("HX-Redirect"))
	require.Equal(t, 204, request("organization-admin", "POST", base, form, "console-test-token").Code)
	for _, actor := range []string{"organization-admin", "package-viewer", "package-operator"} {
		response = request(actor, "GET", base+"/"+id, nil, "")
		require.Equal(t, 200, response.Code)
		require.Contains(t, response.Body.String(), "Owned signing review 42")
		require.NotContains(t, response.Body.String(), "owned-route-source")
		require.NotContains(t, response.Body.String(), "packages.example.invalid")
		if actor != "organization-admin" {
			require.NotContains(t, response.Body.String(), `id="netbird-package-revoke"`)
		}
	}
	require.Equal(t, 404, request("apple-console-admin", "GET", fmt.Sprintf("/tenant/%d/netbird/packages/%s", foreign, id), nil, "").Code)
	require.Equal(t, 403, request("organization-admin", "GET", fmt.Sprintf("/tenant/%d/netbird/packages/%s", foreign, id), nil, "").Code)
	require.Equal(t, 400, request("organization-admin", "GET", base+"?after="+id+"&after="+id, nil, "").Code)
	store, err := inventory.NewNetbirdPackageStore(h.Model.DB, h.Access, h.EncryptionMasterKey)
	require.NoError(t, err)
	p, err := store.Read(ctx, "organization-admin", access.Scope{TenantID: tenant}, id)
	require.NoError(t, err)
	revoke := url.Values{"request_id": {uuid.NewString()}, "digest": {p.Digest}, "confirmed": {"yes"}}
	revoke.Set("csrf", strings.Repeat("t", 32))
	require.Equal(t, 403, request("package-viewer", "POST", base+"/"+id+"/revoke", revoke, "console-test-token").Code)
	require.Equal(t, 403, request("organization-admin", "POST", base+"/"+id+"/revoke", revoke, "wrong").Code)
	native := ownedTagHTTPRequest(t, h, e, ctx, func(r *http.Request) { r.Header.Del("X-CSRF-Token"); r.Header.Del("HX-Request") })
	revoke.Set("csrf", strings.Repeat("t", 32))
	response = native("organization-admin", "POST", base+"/"+id+"/revoke", revoke, "")
	require.Equal(t, 303, response.Code)
	require.Equal(t, base+"/"+id, response.Header().Get("Location"))
	require.Equal(t, 204, request("organization-admin", "POST", base+"/"+id+"/revoke", revoke, "console-test-token").Code)
	response = request("organization-admin", "GET", base+"/"+id, nil, "")
	require.Equal(t, 200, response.Code)
	require.Contains(t, response.Body.String(), "Revoked")
	require.NotContains(t, response.Body.String(), `id="netbird-package-revoke"`)
	var approveCount, revokeCount int
	require.NoError(t, h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FILTER(WHERE action='settings.netbird.packages.approve'),count(*) FILTER(WHERE action='settings.netbird.packages.revoke') FROM uem_settings_audit WHERE tenant_id=$1 AND resource_id LIKE $2`, tenant, id+"%").Scan(&approveCount, &revokeCount))
	require.Equal(t, 1, approveCount)
	require.Equal(t, 1, revokeCount)
}

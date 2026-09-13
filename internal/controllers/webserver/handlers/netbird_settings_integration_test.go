package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/nats/legacysecret"
	"github.com/open-uem/openuem-console/internal/security/access"
	consolesettings "github.com/open-uem/openuem-console/internal/settings"
	"github.com/stretchr/testify/require"
)

type netbirdSettingsTransport func(*http.Request) (*http.Response, error)

func (f netbirdSettingsTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func exerciseNetbirdSettingsRoutes(t *testing.T, h *Handler, e *echo.Echo, ctx context.Context, tenantID int) {
	t.Helper()
	previousKey, previousTransport := h.EncryptionMasterKey, h.netbirdHTTPTransport
	h.EncryptionMasterKey = strings.Repeat("k", 32)
	var providerCalls atomic.Int64
	h.netbirdHTTPTransport = netbirdSettingsTransport(func(*http.Request) (*http.Response, error) {
		providerCalls.Add(1)
		return nil, errors.New("owned unexpected provider call")
	})
	defer func() { h.EncryptionMasterKey = previousKey; h.netbirdHTTPTransport = previousTransport }()
	store, err := consolesettings.NewNetbirdStore(h.Model.DB, h.Access, h.EncryptionMasterKey)
	require.NoError(t, err)
	require.NoError(t, store.Migrate(ctx))
	var previousLink sql.NullInt64
	require.NoError(t, h.Model.DB.QueryRowContext(ctx, "SELECT tenant_netbird FROM tenants WHERE id=$1", tenantID).Scan(&previousLink))
	_, err = h.Model.DB.ExecContext(ctx, "UPDATE tenants SET tenant_netbird=NULL WHERE id=$1", tenantID)
	require.NoError(t, err)
	ownedID := int64(0)
	defer func() {
		_, err := h.Model.DB.ExecContext(ctx, "UPDATE tenants SET tenant_netbird=$2 WHERE id=$1", tenantID, previousLink)
		require.NoError(t, err)
		if ownedID > 0 {
			require.NoError(t, h.Model.Client.NetbirdSettings.DeleteOneID(int(ownedID)).Exec(ctx))
		}
	}()
	requests := ownedTagHTTPRequest(t, h, e, ctx)
	base := fmt.Sprintf("/tenant/%d/admin/netbird", tenantID)
	scope := access.Scope{TenantID: tenantID}
	before, err := h.Model.Client.NetbirdSettings.Query().Count(ctx)
	require.NoError(t, err)
	response := requests("apple-console-admin", "GET", base, nil, "")
	require.Equal(t, 200, response.Code)
	require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
	require.Contains(t, response.Body.String(), "Saving creates it")
	after, err := h.Model.Client.NetbirdSettings.Query().Count(ctx)
	require.NoError(t, err)
	require.Equal(t, before, after)
	configured, err := h.Model.HasNetbirdToken(ctx, tenantID)
	require.NoError(t, err)
	require.False(t, configured)
	review, err := store.Read(ctx, "apple-console-admin", scope)
	require.NoError(t, err)
	form := url.Values{"settingsId": {fmt.Sprint(review.ID)}, "revision": {review.Revision}, "management-url": {"https://provider.example.invalid/management"}, "token-action": {"replace"}, "token": {"owned-http-netbird-secret"}}
	for _, actor := range []string{"organization-admin", "scoped-operator", "scoped-viewer"} {
		require.Equal(t, 403, requests(actor, "GET", base, nil, "").Code)
		require.Equal(t, 403, requests(actor, "POST", base, form, "console-test-token").Code)
	}
	require.Equal(t, 403, requests("apple-console-admin", "POST", base, form, "wrong").Code)
	bad := url.Values{}
	for key, values := range form {
		bad[key] = append([]string{}, values...)
	}
	bad["revision"] = []string{review.Revision, review.Revision}
	require.Equal(t, 400, requests("apple-console-admin", "POST", base, bad, "console-test-token").Code)
	require.Equal(t, 400, requests("apple-console-admin", "POST", base+"?token=private", form, "console-test-token").Code)
	bad.Set("revision", review.Revision)
	bad.Set("token", strings.Repeat("x", 65<<10))
	require.Equal(t, 413, requests("apple-console-admin", "POST", base, bad, "console-test-token").Code)
	bad.Set("token", "owned")
	bad.Set("management-url", "http://provider.example.invalid")
	require.Equal(t, 400, requests("apple-console-admin", "POST", base, bad, "console-test-token").Code)
	native := ownedTagHTTPRequest(t, h, e, ctx, func(r *http.Request) { r.Header.Del("X-CSRF-Token"); r.Header.Del("HX-Request") })
	form.Set("csrf", strings.Repeat("t", 32))
	response = native("apple-console-admin", "POST", base, form, "")
	require.Equal(t, 303, response.Code)
	require.Equal(t, base+"?saved=1", response.Header().Get("Location"))
	require.Equal(t, 409, requests("apple-console-admin", "POST", base, form, "console-test-token").Code)
	review, err = store.Read(ctx, "apple-console-admin", scope)
	require.NoError(t, err)
	ownedID = review.ID
	stored, err := h.Model.Client.NetbirdSettings.Get(ctx, int(review.ID))
	require.NoError(t, err)
	plain, err := legacysecret.Open(stored.AccessToken, h.EncryptionMasterKey)
	require.NoError(t, err)
	require.True(t, plain == "owned-http-netbird-secret")
	require.NotEqual(t, plain, stored.AccessToken)
	response = requests("apple-console-admin", "GET", base+"?saved=1", nil, "")
	require.Equal(t, 200, response.Code)
	require.NotContains(t, response.Body.String(), plain)
	require.NotContains(t, response.Body.String(), stored.AccessToken)
	require.Contains(t, response.Body.String(), "NetBird settings saved")
	form.Set("settingsId", fmt.Sprint(review.ID))
	form.Set("revision", review.Revision)
	form.Set("token-action", "keep")
	form.Set("token", "")
	response = requests("apple-console-admin", "POST", base, form, "console-test-token")
	require.Equal(t, 204, response.Code)
	require.Equal(t, base+"?saved=1", response.Header().Get("HX-Redirect"))
	configured, err = h.Model.HasNetbirdToken(ctx, tenantID)
	require.NoError(t, err)
	require.True(t, configured)
	require.Zero(t, providerCalls.Load(), "settings render/save contacted the provider")
}

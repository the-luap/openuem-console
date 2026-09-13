package handlers

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent/agent"
	nats "github.com/open-uem/nats"
	"github.com/open-uem/nats/netbirdcommand"
	"github.com/open-uem/nats/netbirdstate"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/settings"
	"github.com/stretchr/testify/require"
)

func exerciseNetbirdOperationRoutes(t *testing.T, h *Handler, e *echo.Echo, ctx context.Context, tenant, site int) {
	previous := h.NetbirdOperations
	defer func() { h.NetbirdOperations = previous }()
	configured, err := settings.NewNetbirdStore(h.Model.DB, h.Access, strings.Repeat("k", 32))
	require.NoError(t, err)
	require.NoError(t, configured.Migrate(ctx))
	provider, err := h.Model.Client.NetbirdSettings.Create().SetManagementURL("https://owned-netbird.example.test").SetAccessToken("private-provider-token").Save(ctx)
	require.NoError(t, err)
	organization, err := h.Model.Client.Tenant.Get(ctx, tenant)
	require.NoError(t, err)
	oldProvider, oldErr := organization.QueryNetbird().Only(ctx)
	require.NoError(t, h.Model.Client.Tenant.UpdateOneID(tenant).SetNetbirdID(provider.ID).Exec(ctx))
	defer func() {
		if oldErr == nil {
			_ = h.Model.Client.Tenant.UpdateOneID(tenant).SetNetbirdID(oldProvider.ID).Exec(ctx)
		} else {
			_ = h.Model.Client.Tenant.UpdateOneID(tenant).ClearNetbird().Exec(ctx)
		}
		_ = h.Model.Client.NetbirdSettings.DeleteOneID(provider.ID).Exec(ctx)
	}()
	id := uuid.NewString()
	require.NoError(t, h.Model.Client.Agent.Create().SetID(id).SetHostname("Owned <NetBird endpoint>").SetOs("linux").SetAgentStatus(agent.AgentStatusEnabled).AddSiteIDs(site).Exec(ctx))
	defer h.Model.Client.Agent.DeleteOneID(id).Exec(ctx)
	profiles, err := netbirdstate.Encode(nats.Netbird{ProfileDetails: []nats.NetbirdProfile{{ID: "owned-profile", Name: "Office <Berlin>", Active: true}}})
	require.NoError(t, err)
	require.NoError(t, h.Model.Client.Netbird.Create().SetOwnerID(id).SetInstalled(true).SetVersion("owned-version").SetProfilesAvailable(profiles).SetManagementURL("https://reported.example.test").Exec(ctx))
	probes, calls := 0, 0
	store, err := inventory.NewNetbirdOperationStore(h.Model.DB, h.Access, false, func(context.Context, netbirdcommand.Identity) (netbirdcommand.State, error) {
		probes++
		return netbirdcommand.State{Status: "ready", Revision: strings.Repeat("e", 64), Remaining: 4096}, nil
	}, func(ctx context.Context, c inventory.NetbirdOperationCommand) (*inventory.NetbirdOperationResult, error) {
		calls++
		hash, err := c.Digest()
		return &inventory.NetbirdOperationResult{RequestID: c.RequestID, DeviceID: c.DeviceID, Revision: c.Revision, Operation: c.Operation, CommandHash: hash, Success: true}, err
	})
	require.NoError(t, err)
	h.NetbirdOperations = store
	request := ownedTagHTTPRequest(t, h, e, ctx)
	base := fmt.Sprintf("/tenant/%d/site/%d/computers/%s/netbird", tenant, site, id)
	path := base + "/operations"
	for _, actor := range []string{"scoped-viewer", "scoped-operator", "organization-admin", "apple-console-admin"} {
		r := request(actor, "GET", base, nil, "console-test-token")
		require.Equal(t, 200, r.Code, r.Body.String())
		require.Contains(t, r.Body.String(), "Owned &lt;NetBird endpoint&gt;")
		require.NotContains(t, r.Body.String(), "private-provider-token")
		require.Equal(t, "no-store", r.Header().Get("Cache-Control"))
		r = request(actor, "GET", path, nil, "console-test-token")
		require.Equal(t, 200, r.Code, r.Body.String())
	}
	require.Zero(t, probes, "opening a page published a live device request")
	require.Zero(t, calls)
	for _, actor := range []string{"scoped-viewer", "scoped-operator"} {
		require.Equal(t, 403, request(actor, "GET", path+"/review?operation=up", nil, "console-test-token").Code)
	}
	r := request("apple-console-admin", "GET", path+"/review?operation=switchprofile&profile=owned-profile", nil, "console-test-token")
	require.Equal(t, 200, r.Code, r.Body.String())
	require.Contains(t, r.Body.String(), "Office &lt;Berlin&gt;")
	require.Contains(t, r.Body.String(), `name="confirmed"`)
	require.NotContains(t, r.Body.String(), `name="confirmed" value="yes" checked`)
	for _, query := range []string{"operation=up&operation=down", "operation=register", "operation=up&profile=unexpected", "operation=up&secret=ignored", "operation=%00"} {
		require.Equal(t, 400, request("apple-console-admin", "GET", path+"/review?"+query, nil, "console-test-token").Code)
	}
	scope := access.Scope{TenantID: tenant, SiteID: site}
	review, err := store.Review(ctx, "apple-console-admin", scope, id, "up", "")
	require.NoError(t, err)
	form := url.Values{"csrf": {"console-test-token"}, "confirmed": {"yes"}, "request_id": {uuid.NewString()}, "operation": {"up"}, "profile": {""}, "revision": {review.Revision}}
	for _, alter := range []func(url.Values){func(v url.Values) { v.Del("confirmed") }, func(v url.Values) { v.Add("operation", "down") }, func(v url.Values) { v.Set("unexpected", "secret") }, func(v url.Values) { v.Set("request_id", "bad") }} {
		copy := url.Values{}
		for k, v := range form {
			copy[k] = append([]string(nil), v...)
		}
		alter(copy)
		require.Equal(t, 400, request("apple-console-admin", "POST", path, copy, "console-test-token").Code)
	}
	badToken := url.Values{}
	for k, v := range form {
		badToken[k] = append([]string(nil), v...)
	}
	badToken.Set("csrf", "wrong")
	require.Equal(t, 403, request("apple-console-admin", "POST", path, badToken, "console-test-token").Code)
	r = request("apple-console-admin", "POST", path, form, "console-test-token")
	require.Equal(t, 204, r.Code, r.Body.String())
	receiptPath := path + "/" + form.Get("request_id")
	require.Equal(t, receiptPath, r.Header().Get("HX-Redirect"))
	require.Zero(t, calls, "request handler executed before dispatcher")
	r = request("scoped-viewer", "GET", receiptPath, nil, "console-test-token")
	require.Equal(t, 200, r.Code)
	require.Contains(t, r.Body.String(), "Queued;")
	require.NotContains(t, r.Body.String(), "Cancel queued request")
	_, err = store.DispatchOne(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, calls)
	r = request("scoped-viewer", "GET", receiptPath, nil, "console-test-token")
	require.Equal(t, 200, r.Code, r.Body.String())
	require.Contains(t, r.Body.String(), "Command execution confirmed.")
	r = request("apple-console-admin", "POST", path, form, "console-test-token")
	require.Equal(t, 204, r.Code)
	require.Equal(t, 1, calls)
	// A newly reviewed command can be cancelled, but a completed one cannot.
	form.Set("request_id", uuid.NewString())
	r = request("apple-console-admin", "POST", path, form, "console-test-token")
	require.Equal(t, 204, r.Code)
	cancelPath := path + "/" + form.Get("request_id") + "/cancel"
	confirmation := url.Values{"csrf": {"console-test-token"}, "confirmed": {"yes"}}
	require.Equal(t, 403, request("scoped-viewer", "POST", cancelPath, confirmation, "console-test-token").Code)
	require.Equal(t, 204, request("apple-console-admin", "POST", cancelPath, confirmation, "console-test-token").Code)
	require.Equal(t, 409, request("apple-console-admin", "POST", receiptPath+"/cancel", confirmation, "console-test-token").Code)
	// Old entry points cannot deliver unreviewed envelopes or touch providers.
	for _, suffix := range []string{"connect", "disconnect", "switchprofile"} {
		require.Equal(t, 400, request("apple-console-admin", "POST", base+"/"+suffix, confirmation, "console-test-token").Code)
	}
	for _, suffix := range []string{"install", "uninstall", "register", "deletepeer"} {
		require.Equal(t, 503, request("apple-console-admin", "POST", base+"/"+suffix, confirmation, "console-test-token").Code)
	}
	require.Equal(t, 1, calls)
	exerciseNetbirdResolutionRoutes(t, h, e, ctx, scope, id, path)
	require.NoError(t, h.Model.Client.Agent.DeleteOneID(id).Exec(ctx))
	require.Equal(t, 200, request("scoped-viewer", "GET", receiptPath, nil, "console-test-token").Code)
	require.Equal(t, 200, request("scoped-viewer", "GET", path, nil, "console-test-token").Code)
}

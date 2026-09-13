package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent/agent"
	"github.com/open-uem/nats/netbirdcommand"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/settings"
	"github.com/stretchr/testify/require"
)

func exerciseNetbirdRegistrationRoutes(t *testing.T, h *Handler, e *echo.Echo, ctx context.Context, tenant, site int) {
	previous := h.NetbirdRegistrations
	defer func() { h.NetbirdRegistrations = previous }()
	migrated, err := settings.NewNetbirdStore(h.Model.DB, h.Access, strings.Repeat("k", 32))
	require.NoError(t, err)
	require.NoError(t, migrated.Migrate(ctx))
	var mu sync.Mutex
	creates, deletes, providerReads, deliveries := 0, 0, 0, 0
	var key map[string]any
	absent, retainDelete := false, false
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/groups":
			providerReads++
			_, _ = w.Write([]byte(`[{"id":"owned-group","name":"Office <Berlin>","peers_count":0}]`))
		case r.Method == "POST" && r.URL.Path == "/api/setup-keys":
			creates++
			absent = false
			var body map[string]any
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				w.WriteHeader(400)
				return
			}
			key = map[string]any{"id": "owned-key", "key": "owned-private-registration-key", "name": body["name"], "type": body["type"], "expires": time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339Nano), "auto_groups": body["auto_groups"], "usage_limit": body["usage_limit"], "used_times": 0, "allow_extra_dns_labels": body["allow_extra_dns_labels"], "ephemeral": body["ephemeral"], "valid": true, "revoked": false}
			_ = json.NewEncoder(w).Encode(key)
		case r.Method == "GET" && r.URL.Path == "/api/setup-keys/owned-key":
			providerReads++
			if absent {
				w.WriteHeader(404)
				_, _ = w.Write([]byte(`{}`))
				return
			}
			masked := map[string]any{}
			for k, v := range key {
				masked[k] = v
			}
			masked["key"] = "masked-*****"
			_ = json.NewEncoder(w).Encode(masked)
		case r.Method == "DELETE" && r.URL.Path == "/api/setup-keys/owned-key":
			deletes++
			if !retainDelete {
				absent = true
			}
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(400)
		}
	}))
	defer provider.Close()
	configured, err := h.Model.Client.NetbirdSettings.Create().SetManagementURL(provider.URL).SetAccessToken("owned-private-registration-token").Save(ctx)
	require.NoError(t, err)
	organization, err := h.Model.Client.Tenant.Get(ctx, tenant)
	require.NoError(t, err)
	old, oldErr := organization.QueryNetbird().Only(ctx)
	require.NoError(t, h.Model.Client.Tenant.UpdateOneID(tenant).SetNetbirdID(configured.ID).Exec(ctx))
	defer func() {
		if oldErr == nil {
			_ = h.Model.Client.Tenant.UpdateOneID(tenant).SetNetbirdID(old.ID).Exec(ctx)
		} else {
			_ = h.Model.Client.Tenant.UpdateOneID(tenant).ClearNetbird().Exec(ctx)
		}
		_ = h.Model.Client.NetbirdSettings.DeleteOneID(configured.ID).Exec(ctx)
	}()
	device := uuid.NewString()
	scope := access.Scope{TenantID: tenant, SiteID: site}
	require.NoError(t, h.Model.Client.Agent.Create().SetID(device).SetHostname("Owned registration <endpoint>").SetOs("linux").SetAgentStatus(agent.AgentStatusEnabled).AddSiteIDs(site).Exec(ctx))
	defer h.Model.Client.Agent.DeleteOneID(device).Exec(ctx)
	require.NoError(t, h.Model.Client.Netbird.Create().SetOwnerID(device).SetInstalled(true).Exec(ctx))
	store, err := inventory.NewNetbirdRegistrationStore(h.Model.DB, h.Access, false, strings.Repeat("k", 32), provider.Client().Transport, func(_ context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
		require.Equal(t, "registration-state", c.Kind)
		hash, err := c.Digest()
		return &netbirdcommand.ControlResponse{Version: netbirdcommand.Version, Identity: c.Identity, RequestID: c.RequestID, RequestHash: hash, Kind: c.Kind, Outcome: "ok", State: netbirdcommand.State{Status: "ready", Revision: strings.Repeat("e", 64), Remaining: 4096}}, err
	}, func(_ context.Context, c inventory.NetbirdOperationCommand) (*inventory.NetbirdOperationResult, error) {
		deliveries++
		require.Equal(t, netbirdcommand.RegistrationVersion, c.Version)
		require.Equal(t, "owned-private-registration-key", c.SetupKey)
		hash, err := c.Digest()
		return &inventory.NetbirdOperationResult{RequestID: c.RequestID, DeviceID: c.DeviceID, Revision: c.Revision, Operation: c.Operation, CommandHash: hash, Success: true}, err
	})
	require.NoError(t, err)
	h.NetbirdRegistrations = store
	request := ownedTagHTTPRequest(t, h, e, ctx)
	base := fmt.Sprintf("/tenant/%d/site/%d/computers/%s/netbird", tenant, site, device)
	path := base + "/registrations"
	for _, actor := range []string{"scoped-viewer", "scoped-operator", "apple-console-admin"} {
		require.Equal(t, 200, request(actor, "GET", path, nil, "console-test-token").Code)
	}
	for _, actor := range []string{"scoped-viewer", "scoped-operator"} {
		require.Equal(t, 403, request(actor, "GET", path+"/new", nil, "console-test-token").Code)
	}
	mu.Lock()
	require.Zero(t, providerReads)
	mu.Unlock()
	choices := request("apple-console-admin", "GET", path+"/new", nil, "console-test-token")
	require.Equal(t, 200, choices.Code, choices.Body.String())
	require.Contains(t, choices.Body.String(), "Office &lt;Berlin&gt;")
	require.NotContains(t, choices.Body.String(), "owned-private-registration-token")
	reviewed := request("apple-console-admin", "GET", path+"/review?group=owned-group&extra_dns=yes", nil, "console-test-token")
	require.Equal(t, 200, reviewed.Code, reviewed.Body.String())
	require.Equal(t, "no-store", reviewed.Header().Get("Cache-Control"))
	require.Contains(t, reviewed.Body.String(), "interrupt access")
	for _, query := range []string{"group=owned-group&group=owned-group", "extra_dns=yes&extra_dns=no", "group=%00", "token=ignored", "extra_dns=unexpected", "revision=ignored"} {
		require.Equal(t, 400, request("apple-console-admin", "GET", path+"/review?"+query, nil, "console-test-token").Code)
	}
	review, err := store.Review(ctx, "apple-console-admin", scope, device, []string{"owned-group"}, true)
	require.NoError(t, err)
	form := url.Values{"csrf": {"console-test-token"}, "confirmed": {"yes"}, "request_id": {uuid.NewString()}, "revision": {review.Revision}, "group": {"owned-group"}, "extra_dns": {"yes"}}
	for _, change := range []func(url.Values){func(v url.Values) { v.Del("confirmed") }, func(v url.Values) { v.Add("request_id", uuid.NewString()) }, func(v url.Values) { v.Set("setup_key", "injected") }, func(v url.Values) { v.Set("extra_dns", "invalid") }, func(v url.Values) { v.Set("request_id", "invalid") }} {
		copy := url.Values{}
		for k, v := range form {
			copy[k] = append([]string{}, v...)
		}
		change(copy)
		require.Equal(t, 400, request("apple-console-admin", "POST", path, copy, "console-test-token").Code)
	}
	require.Equal(t, 403, request("scoped-viewer", "POST", path, form, "console-test-token").Code)
	require.Equal(t, 403, request("apple-console-admin", "POST", path, form, "wrong-token").Code)
	r := request("apple-console-admin", "POST", path, form, "console-test-token")
	require.Equal(t, 204, r.Code, r.Body.String())
	receiptPath := path + "/" + form.Get("request_id")
	require.Equal(t, receiptPath, r.Header().Get("HX-Redirect"))
	require.Zero(t, deliveries)
	reader := request("scoped-viewer", "GET", receiptPath, nil, "console-test-token")
	require.Equal(t, 200, reader.Code)
	require.NotContains(t, reader.Body.String(), "Cancel queued registration")
	_, err = store.DispatchOne(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, deliveries)
	receipt := request("scoped-viewer", "GET", receiptPath, nil, "console-test-token")
	require.Equal(t, 200, receipt.Code, receipt.Body.String())
	require.Contains(t, receipt.Body.String(), "Command execution and setup-key removal confirmed.")
	for _, secret := range []string{"owned-private-registration-token", "owned-private-registration-key"} {
		require.NotContains(t, receipt.Body.String(), secret)
	}
	require.Equal(t, 204, request("apple-console-admin", "POST", path, form, "console-test-token").Code)
	require.Equal(t, 1, deliveries)
	// The old route only accepts the complete reviewed registration contract.
	require.Equal(t, 204, request("apple-console-admin", "POST", base+"/register", form, "console-test-token").Code)
	confirmation := url.Values{"csrf": {"console-test-token"}, "confirmed": {"yes"}}
	require.Equal(t, 400, request("apple-console-admin", "POST", base+"/register", confirmation, "console-test-token").Code)
	require.Equal(t, 409, request("apple-console-admin", "POST", receiptPath+"/cancel", confirmation, "console-test-token").Code)
	form.Set("request_id", uuid.NewString())
	require.Equal(t, 204, request("apple-console-admin", "POST", path, form, "console-test-token").Code)
	require.Equal(t, 204, request("apple-console-admin", "POST", path+"/"+form.Get("request_id")+"/cancel", confirmation, "console-test-token").Code)
	form.Set("request_id", uuid.NewString())
	require.Equal(t, 204, request("apple-console-admin", "POST", path, form, "console-test-token").Code)
	mu.Lock()
	retainDelete = true
	mu.Unlock()
	_, err = store.DispatchOne(ctx)
	require.NoError(t, err)
	uncertainPath := path + "/" + form.Get("request_id")
	require.Equal(t, 403, request("scoped-viewer", "POST", uncertainPath+"/cleanup", confirmation, "console-test-token").Code)
	mu.Lock()
	absent = true
	mu.Unlock()
	require.Equal(t, 204, request("apple-console-admin", "POST", uncertainPath+"/cleanup", confirmation, "console-test-token").Code)
	uncertain := request("scoped-viewer", "GET", uncertainPath, nil, "console-test-token")
	require.Contains(t, uncertain.Body.String(), "Registration is unconfirmed.")
	require.Contains(t, uncertain.Body.String(), "Absence confirmed at the provider")
	mu.Lock()
	require.Equal(t, 2, creates)
	require.Equal(t, 2, deletes)
	mu.Unlock()
	require.Equal(t, 2, deliveries)
	require.NoError(t, h.Model.Client.Agent.DeleteOneID(device).Exec(ctx))
	require.Equal(t, 200, request("scoped-viewer", "GET", path, nil, "console-test-token").Code)
	require.Equal(t, 200, request("scoped-viewer", "GET", receiptPath, nil, "console-test-token").Code)
}

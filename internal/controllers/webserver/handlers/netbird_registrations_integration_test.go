package handlers

import (
	"context"
	"encoding/json"
	"errors"
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
	previous, oldResolution := h.NetbirdRegistrations, h.NetbirdRegistrationResolutions
	defer func() { h.NetbirdRegistrations = previous; h.NetbirdRegistrationResolutions = oldResolution }()
	migrated, err := settings.NewNetbirdStore(h.Model.DB, h.Access, strings.Repeat("k", 32))
	require.NoError(t, err)
	require.NoError(t, migrated.Migrate(ctx))
	var mu sync.Mutex
	creates, deletes, providerReads, deliveries := 0, 0, 0, 0
	var key map[string]any
	absent, retainDelete, failRead := false, false, false
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
			if failRead {
				w.WriteHeader(503)
				return
			}
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
	var command inventory.NetbirdOperationCommand
	lostDelivery, lostRelease := false, false
	releaseID := ""
	controls, releases := 0, 0
	control := func(_ context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
		p, err := netbirdcommand.ControlResponseFor(c, "ok")
		require.NoError(t, err)
		if c.Kind == "registration-state" {
			p.State = netbirdcommand.State{Status: "ready", Revision: strings.Repeat("e", 64), Remaining: 4096}
			if lostDelivery && command.RequestID != "" && releaseID == "" {
				hash, err := command.Digest()
				require.NoError(t, err)
				p.State = netbirdcommand.State{Status: "unconfirmed", Revision: strings.Repeat("d", 64), Remaining: 4095, PendingID: command.RequestID, PendingHash: hash, CanRelease: true}
			}
			return &p, nil
		}
		controls++
		if c.Kind == "release" {
			releases++
			mu.Lock()
			require.True(t, absent)
			mu.Unlock()
			releaseID = c.RequestID
			if lostRelease {
				return nil, errors.New("owned release reply lost")
			}
		}
		status := "completed"
		if lostDelivery {
			status = "unconfirmed"
		}
		p.Receipt, err = netbirdcommand.ReceiptFor(command, status)
		p.ReleaseID = releaseID
		return &p, err
	}
	store, err := inventory.NewNetbirdRegistrationStore(h.Model.DB, h.Access, false, strings.Repeat("k", 32), provider.Client().Transport, control, func(_ context.Context, c inventory.NetbirdOperationCommand) (*inventory.NetbirdOperationResult, error) {
		deliveries++
		command = c
		require.Equal(t, netbirdcommand.RegistrationVersion, c.Version)
		require.Equal(t, "owned-private-registration-key", c.SetupKey)
		if lostDelivery {
			return nil, errors.New("owned command reply lost")
		}
		hash, err := c.Digest()
		return &inventory.NetbirdOperationResult{RequestID: c.RequestID, DeviceID: c.DeviceID, Revision: c.Revision, Operation: c.Operation, CommandHash: hash, Success: true}, err
	})
	require.NoError(t, err)
	resolver, err := inventory.NewNetbirdRegistrationResolutionStore(store, control)
	require.NoError(t, err)
	h.NetbirdRegistrations = store
	h.NetbirdRegistrationResolutions = resolver
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

	// A completed agent receipt resolves later key cleanup without sending release.
	resolutionPath := uncertainPath + "/resolution"
	confirm := url.Values{"csrf": {"console-test-token"}, "confirmed": {"yes"}, "resolution_id": {uuid.NewString()}, "revision": {strings.Repeat("a", 64)}}
	for _, actor := range []string{"scoped-viewer", "scoped-operator"} {
		require.Equal(t, 403, request(actor, "GET", resolutionPath, nil, "console-test-token").Code)
		for _, suffix := range []string{"", "/continue", "/reconcile"} {
			body := url.Values{"csrf": {"console-test-token"}, "confirmed": {"yes"}, "resolution_id": {confirm.Get("resolution_id")}}
			if suffix != "/reconcile" {
				body.Set("revision", confirm.Get("revision"))
			}
			require.Equal(t, 403, request(actor, "POST", resolutionPath+suffix, body, "console-test-token").Code)
		}
	}
	require.Zero(t, controls)
	page := request("apple-console-admin", "GET", resolutionPath, nil, "console-test-token")
	require.Equal(t, 200, page.Code, page.Body.String())
	require.Equal(t, "no-store", page.Header().Get("Cache-Control"))
	require.Contains(t, page.Body.String(), "matching completed receipt")
	require.Contains(t, page.Body.String(), "Owned registration &lt;endpoint&gt;")
	v, err := resolver.Review(ctx, "apple-console-admin", scope, device, form.Get("request_id"))
	require.NoError(t, err)
	confirm.Set("revision", v.Revision)
	for _, alter := range []func(url.Values){func(v url.Values) { v.Del("confirmed") }, func(v url.Values) { v.Add("resolution_id", uuid.NewString()) }, func(v url.Values) { v.Set("resolution_id", "bad") }, func(v url.Values) { v.Set("setup_key", "injected") }} {
		bad := url.Values{}
		for k, list := range confirm {
			bad[k] = append([]string{}, list...)
		}
		alter(bad)
		require.Equal(t, 400, request("apple-console-admin", "POST", resolutionPath, bad, "console-test-token").Code)
	}
	require.Equal(t, 400, request("apple-console-admin", "GET", resolutionPath+"?confirmed=yes", nil, "console-test-token").Code)
	require.Equal(t, 403, request("apple-console-admin", "POST", resolutionPath, confirm, "wrong-token").Code)
	response := request("apple-console-admin", "POST", resolutionPath, confirm, "console-test-token")
	require.Equal(t, 204, response.Code, response.Body.String())
	require.Equal(t, resolutionPath, response.Header().Get("HX-Redirect"))
	beforeControls := controls
	require.Equal(t, 204, request("apple-console-admin", "POST", resolutionPath, confirm, "console-test-token").Code)
	require.Equal(t, beforeControls, controls)
	require.Zero(t, releases)
	page = request("scoped-viewer", "GET", uncertainPath, nil, "console-test-token")
	require.Contains(t, page.Body.String(), "Resolution confirmed.")
	require.Contains(t, page.Body.String(), "Registration is unconfirmed.")
	require.NotContains(t, page.Body.String(), "commands remain blocked")

	// Cleanup pending after a first explicit attempt must not send release.
	command = inventory.NetbirdOperationCommand{}
	lostDelivery, lostRelease = true, true
	review, err = store.Review(ctx, "apple-console-admin", scope, device, []string{"owned-group"}, true)
	require.NoError(t, err)
	form.Set("request_id", uuid.NewString())
	form.Set("revision", review.Revision)
	require.Equal(t, 204, request("apple-console-admin", "POST", path, form, "console-test-token").Code)
	mu.Lock()
	failRead = true
	mu.Unlock()
	_, err = store.DispatchOne(ctx)
	require.NoError(t, err)
	mu.Lock()
	failRead = false
	mu.Unlock()
	resolutionPath = path + "/" + form.Get("request_id") + "/resolution"
	v, err = resolver.Review(ctx, "apple-console-admin", scope, device, form.Get("request_id"))
	require.NoError(t, err)
	require.True(t, v.CanResolve)
	require.True(t, v.CanCleanup)
	confirm.Set("resolution_id", uuid.NewString())
	confirm.Set("revision", v.Revision)
	response = request("apple-console-admin", "POST", resolutionPath, confirm, "console-test-token")
	require.Equal(t, 204, response.Code, response.Body.String())
	require.Zero(t, releases)
	check := url.Values{"csrf": {"console-test-token"}, "confirmed": {"yes"}, "resolution_id": {confirm.Get("resolution_id")}}
	mu.Lock()
	absent = true
	mu.Unlock()
	require.Equal(t, 204, request("apple-console-admin", "POST", resolutionPath+"/reconcile", check, "console-test-token").Code)
	require.Zero(t, releases)
	page = request("apple-console-admin", "GET", resolutionPath, nil, "console-test-token")
	require.Equal(t, 200, page.Code, page.Body.String())
	require.Contains(t, page.Body.String(), "Confirm continuation")
	require.Equal(t, 409, request("apple-console-admin", "POST", resolutionPath+"/continue", confirm, "console-test-token").Code)
	v, err = resolver.Review(ctx, "apple-console-admin", scope, device, form.Get("request_id"))
	require.NoError(t, err)
	require.True(t, v.CanContinue)
	confirm.Set("revision", v.Revision)
	response = request("apple-console-admin", "POST", resolutionPath+"/continue", confirm, "console-test-token")
	require.Equal(t, 204, response.Code, response.Body.String())
	require.Equal(t, 1, releases)
	retained, err := store.Read(ctx, "apple-console-admin", scope, device, form.Get("request_id"))
	require.NoError(t, err)
	require.Nil(t, retained.ReleasedAt)
	require.Equal(t, 204, request("apple-console-admin", "POST", resolutionPath+"/reconcile", check, "console-test-token").Code)
	retained, err = store.Read(ctx, "apple-console-admin", scope, device, form.Get("request_id"))
	require.NoError(t, err)
	require.NotNil(t, retained.ReleasedAt)
	require.Equal(t, "unconfirmed", retained.Status)
	require.Equal(t, 1, releases)
	mu.Lock()
	require.Equal(t, 3, creates)
	require.Equal(t, 3, deletes)
	mu.Unlock()
	require.Equal(t, 3, deliveries)
	for _, secret := range []string{"owned-private-registration-token", "owned-private-registration-key"} {
		require.NotContains(t, page.Body.String(), secret)
	}
	require.NoError(t, h.Model.Client.Agent.DeleteOneID(device).Exec(ctx))
	require.Equal(t, 200, request("scoped-viewer", "GET", path, nil, "console-test-token").Code)
	require.Equal(t, 200, request("apple-console-admin", "GET", resolutionPath, nil, "console-test-token").Code)
	require.Equal(t, 200, request("scoped-viewer", "GET", receiptPath, nil, "console-test-token").Code)
}

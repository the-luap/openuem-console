package handlers

import (
	"context"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent/agent"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/registry"
	"github.com/open-uem/nats/netbirdcommand"
	packageapi "github.com/open-uem/nats/netbirdinstall"
	consolemiddleware "github.com/open-uem/openuem-console/internal/controllers/router/middleware"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func exerciseNetbirdInstallationRoutes(t *testing.T, h *Handler, ctx context.Context, tenant, site, foreign int) {
	t.Helper()
	old, oldOps := h.NetbirdInstallations, h.NetbirdOperations
	defer func() { h.NetbirdInstallations, h.NetbirdOperations = old, oldOps }()
	e := echo.New()
	e.Use(consolemiddleware.CSRF())
	h.Register(e, 3)
	identities, err := registry.NewStore(h.Model.DB, strings.Repeat("k", 32))
	require.NoError(t, err)
	require.NoError(t, identities.Migrate(ctx))
	invitation, err := identities.Invite(ctx, registry.InvitationOptions{Scope: registry.Scope{TenantID: tenant, SiteID: site}, Platform: "macos", Architecture: "arm64", ExpiresAt: time.Now().Add(time.Hour), MaxUses: 1}, "organization-admin")
	require.NoError(t, err)
	keys, err := enrollment.GenerateKeys()
	require.NoError(t, err)
	defer keys.Broker.Wipe()
	claim, err := keys.Request(invitation.URL[strings.LastIndex(invitation.URL, "/")+1:], "macos", "arm64", "Owned native UI endpoint")
	require.NoError(t, err)
	identity, err := identities.Claim(ctx, *claim)
	require.NoError(t, err)
	device := identity.DeviceID
	require.NoError(t, h.Model.Client.Agent.Create().SetID(device).SetHostname("Owned installation <endpoint>").SetOs("macOS").SetAgentStatus(agent.AgentStatusEnabled).AddSiteIDs(site).Exec(ctx))
	_, err = h.Model.DB.ExecContext(ctx, `UPDATE uem_agent_command_consumers SET completed_revision=revision WHERE device_id=$1`, device)
	require.NoError(t, err)
	packages, err := inventory.NewNetbirdPackageStore(h.Model.DB, h.Access, strings.Repeat("k", 32))
	require.NoError(t, err)
	pkg := packageapi.Package{Schema: packageapi.Schema, ApprovalID: uuid.NewString(), TenantID: int64(tenant), Platform: "macos", Architecture: "arm64", Format: "pkg", PackageID: "io.netbird.client", Version: "0.78.1", Size: 1234, SHA256: strings.Repeat("a", 64), URL: "https://packages.example.test/netbird.pkg?private=owned-native-ui-source"}
	_, err = packages.Approve(ctx, "organization-admin", access.Scope{TenantID: tenant}, pkg, "Owned private installation verification")
	require.NoError(t, err)
	var command netbirdcommand.Command
	native, preparations, queries, mutations := 0, 0, 0, 0
	receiptState, releaseID := "completed", ""
	loseReply := false
	control := func(_ context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
		if c.Kind == "preparation-state" || c.Kind == "installation-state" || c.Kind == "state" {
			p, err := netbirdcommand.ControlResponseFor(c, "ok")
			p.State = netbirdcommand.State{Status: "ready", Revision: strings.Repeat("e", 64), Remaining: 100}
			if c.Kind == "state" && receiptState == "unconfirmed" {
				hash, e := command.Digest()
				require.NoError(t, e)
				p.State = netbirdcommand.State{Status: "unconfirmed", Revision: strings.Repeat("f", 64), Remaining: 99, PendingID: command.RequestID, PendingHash: hash, CanRelease: true}
			}
			return &p, err
		}
		queries++
		if c.Kind == "withdraw" || c.Kind == "release" {
			mutations++
			releaseID = c.RequestID
			if c.Kind == "withdraw" {
				receiptState = "withdrawn"
			}
			if loseReply {
				return nil, errors.New("owned lost recovery reply")
			}
		}
		outcome := "ok"
		if receiptState == "missing" {
			outcome = "missing"
		}
		p, err := netbirdcommand.ControlResponseFor(c, outcome)
		if outcome == "ok" {
			p.Receipt, err = netbirdcommand.ReceiptFor(command, receiptState)
			p.ReleaseID = releaseID
		}
		return &p, err
	}
	store, err := inventory.NewNetbirdInstallationDeliveryStore(h.Model.DB, h.Access, true, strings.Repeat("k", 32), control, func(_ context.Context, p netbirdcommand.PreparationRequest) (*netbirdcommand.PreparationResponse, error) {
		preparations++
		out, err := netbirdcommand.PreparationResponseFor(p, "prepared")
		return &out, err
	}, func(_ context.Context, c netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
		native++
		command = c
		if receiptState != "completed" {
			return nil, errors.New("owned lost native reply")
		}
		out, err := netbirdcommand.ReceiptFor(c, "completed")
		return &out, err
	})
	require.NoError(t, err)
	h.NetbirdInstallations = store
	h.NetbirdOperations, err = inventory.NewNetbirdOperationStore(h.Model.DB, h.Access, true, func(context.Context, netbirdcommand.Identity) (netbirdcommand.State, error) {
		t.Fatal("overview queried a journal")
		return netbirdcommand.State{}, nil
	}, func(context.Context, inventory.NetbirdOperationCommand) (*inventory.NetbirdOperationResult, error) {
		t.Fatal("native UI used the connection publisher")
		return nil, nil
	})
	require.NoError(t, err)
	request := ownedTagHTTPRequest(t, h, e, ctx)
	path := fmt.Sprintf("/tenant/%d/site/%d/computers/%s/netbird/installations", tenant, site, device)
	fieldPattern := regexp.MustCompile(`name="([a-z_]+)" value="([^"]*)"`)
	fields := func(body string) url.Values {
		v := url.Values{}
		for _, match := range fieldPattern.FindAllStringSubmatch(body, -1) {
			v.Set(match[1], html.UnescapeString(match[2]))
		}
		return v
	}
	for _, actor := range []string{"scoped-viewer", "scoped-operator"} {
		response := request(actor, "GET", path, nil, "")
		require.Equal(t, 200, response.Code, response.Body.String())
		require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
	}
	require.Equal(t, 403, request("scoped-viewer", "GET", path+"/new", nil, "").Code)
	choices := request("scoped-operator", "GET", path+"/new", nil, "")
	require.Equal(t, 200, choices.Code)
	require.Contains(t, choices.Body.String(), pkg.ApprovalID)
	for _, private := range []string{"owned-native-ui-source", "Owned private installation verification", "certificate_hash", "broker_key"} {
		require.NotContains(t, choices.Body.String(), private)
	}
	digest, err := pkg.Digest()
	require.NoError(t, err)
	reviewPath := path + "/review?" + url.Values{"approval_id": {pkg.ApprovalID}, "approval_digest": {digest}}.Encode()
	review := request("scoped-operator", "GET", reviewPath, nil, "")
	require.Equal(t, 200, review.Code)
	require.Contains(t, review.Body.String(), "Owned installation &lt;endpoint&gt;")
	form := fields(review.Body.String())
	form.Set("confirmed", "yes")
	require.NotEmpty(t, form.Get("request_id"))
	require.NotEmpty(t, form.Get("revision"))
	for _, change := range []string{"confirmation", "duplicate", "unknown", "revision", "query"} {
		bad := url.Values{}
		for k, v := range form {
			bad[k] = append([]string{}, v...)
		}
		target := path
		switch change {
		case "confirmation":
			bad.Del("confirmed")
		case "duplicate":
			bad.Add("revision", bad.Get("revision"))
		case "unknown":
			bad.Set("source_url", "private")
		case "revision":
			bad.Set("revision", "invalid")
		case "query":
			target += "?approval_id=" + pkg.ApprovalID
		}
		require.Equal(t, 400, request("scoped-operator", "POST", target, bad, "console-test-token").Code, change)
	}
	require.Equal(t, 403, request("scoped-viewer", "POST", path, form, "console-test-token").Code)
	require.Equal(t, 403, request("scoped-operator", "POST", path, form, "wrong").Code)
	require.Equal(t, 204, request("scoped-operator", "POST", path, form, "console-test-token").Code)
	receiptPath := path + "/" + form.Get("request_id")
	response := request("scoped-viewer", "GET", receiptPath, nil, "")
	require.Equal(t, 200, response.Code, response.Body.String())
	require.NotContains(t, response.Body.String(), "Cancel installation request")
	require.Contains(t, response.Body.String(), "Queued for preparation")
	require.Zero(t, native)
	require.Zero(t, preparations)
	cancel := url.Values{"revision": {form.Get("revision")}, "cancellation_id": {uuid.NewString()}, "confirmed": {"yes"}, "csrf": {strings.Repeat("t", 32)}}
	require.Equal(t, 403, request("scoped-viewer", "POST", receiptPath+"/cancel", cancel, "console-test-token").Code)
	require.Equal(t, 204, request("scoped-operator", "POST", receiptPath+"/cancel", cancel, "console-test-token").Code)
	require.Equal(t, 204, request("scoped-operator", "POST", receiptPath+"/cancel", cancel, "console-test-token").Code)
	// Native forms share the same reviewed intent and production CSRF path.
	nativeRequest := ownedTagHTTPRequest(t, h, e, ctx, func(r *http.Request) {
		r.Header.Del("HX-Request")
		r.Header.Del("X-CSRF-Token")
	})
	review = request("scoped-operator", "GET", reviewPath, nil, "")
	require.Equal(t, 200, review.Code)
	nativeForm := fields(review.Body.String())
	nativeForm.Set("confirmed", "yes")
	nativeReceipt := path + "/" + nativeForm.Get("request_id")
	nativeResponse := nativeRequest("scoped-operator", "POST", path, nativeForm, "")
	require.Equal(t, 303, nativeResponse.Code)
	require.Equal(t, nativeReceipt, nativeResponse.Header().Get("Location"))
	nativeCancel := url.Values{"revision": {nativeForm.Get("revision")}, "cancellation_id": {uuid.NewString()}, "confirmed": {"yes"}, "csrf": {strings.Repeat("t", 32)}}
	nativeResponse = nativeRequest("scoped-operator", "POST", nativeReceipt+"/cancel", nativeCancel, "")
	require.Equal(t, 303, nativeResponse.Code)
	require.Equal(t, nativeReceipt, nativeResponse.Header().Get("Location"))
	// Wire padding must be limited before token extraction normalizes PostForm,
	// including unknown-length requests carrying an otherwise valid header.
	oversized := ownedTagHTTPRequest(t, h, e, ctx, func(r *http.Request) {
		r.Body = io.NopCloser(strings.NewReader("csrf=" + strings.Repeat("t", 32) + strings.Repeat("&", 8192)))
		r.ContentLength = -1
	})
	for _, suffix := range []string{"", "/" + nativeForm.Get("request_id") + "/cancel", "/" + nativeForm.Get("request_id") + "/observe", "/" + nativeForm.Get("request_id") + "/resolution", "/" + nativeForm.Get("request_id") + "/resolution/reconcile"} {
		require.Equal(t, 413, oversized("scoped-operator", "POST", path+suffix, nil, "console-test-token").Code)
	}
	for _, scenario := range []string{"completed", "observe", "withdraw", "release"} {
		receiptState, releaseID, loseReply = "completed", "", false
		if scenario == "observe" || scenario == "release" {
			receiptState = "unconfirmed"
		}
		if scenario == "withdraw" {
			receiptState = "missing"
			loseReply = true
		}
		review = request("scoped-operator", "GET", reviewPath, nil, "")
		require.Equal(t, 200, review.Code)
		form = fields(review.Body.String())
		form.Set("confirmed", "yes")
		require.Equal(t, 204, request("scoped-operator", "POST", path, form, "console-test-token").Code)
		receiptPath = path + "/" + form.Get("request_id")
		worked, err := store.DispatchOne(ctx)
		require.NoError(t, err)
		require.True(t, worked)
		beforeQueries, beforeNative := queries, native
		response = request("scoped-viewer", "GET", receiptPath, nil, "")
		require.Equal(t, 200, response.Code, response.Body.String())
		require.Equal(t, beforeQueries, queries)
		require.Equal(t, beforeNative, native)
		require.NotContains(t, response.Body.String(), "Check retained receipt")
		require.NotContains(t, response.Body.String(), "owned-native-ui-source")
		post := url.Values{"revision": {form.Get("revision")}, "confirmed": {"yes"}, "csrf": {strings.Repeat("t", 32)}}
		if scenario == "observe" {
			receiptState = "completed"
			require.Equal(t, 403, request("scoped-viewer", "POST", receiptPath+"/observe", post, "console-test-token").Code)
			require.Equal(t, 204, request("scoped-operator", "POST", receiptPath+"/observe", post, "console-test-token").Code)
		} else if scenario != "completed" {
			require.Equal(t, 403, request("scoped-viewer", "GET", receiptPath+"/resolution", nil, "").Code)
			recovery := request("scoped-operator", "GET", receiptPath+"/resolution", nil, "")
			require.Equal(t, 200, recovery.Code)
			resolved := fields(recovery.Body.String())
			resolved.Set("confirmed", "yes")
			require.NotEmpty(t, resolved.Get("review_revision"))
			require.NotEmpty(t, resolved.Get("resolution_id"))
			require.Equal(t, 204, request("scoped-operator", "POST", receiptPath+"/resolution", resolved, "console-test-token").Code)
			count := mutations
			require.Equal(t, 204, request("scoped-operator", "POST", receiptPath+"/resolution", resolved, "console-test-token").Code)
			require.Equal(t, count, mutations)
			if scenario == "withdraw" {
				post.Set("resolution_id", resolved.Get("resolution_id"))
				require.Equal(t, 204, request("scoped-operator", "POST", receiptPath+"/resolution/reconcile", post, "console-test-token").Code)
				require.Equal(t, count, mutations)
			}
		}
		response = request("scoped-viewer", "GET", receiptPath, nil, "")
		require.Equal(t, 200, response.Code, response.Body.String())
		if scenario == "completed" || scenario == "observe" {
			require.Contains(t, response.Body.String(), "Package installation verified")
		} else {
			require.Contains(t, response.Body.String(), "Reviewed recovery confirmed")
			require.Contains(t, response.Body.String(), "unconfirmed")
		}
		require.Equal(t, beforeNative, native)
		require.Equal(t, 404, request("apple-console-admin", "GET", strings.Replace(receiptPath, fmt.Sprintf("/tenant/%d/", tenant), fmt.Sprintf("/tenant/%d/", foreign), 1), nil, "").Code)
	}
	require.Equal(t, 4, native)
	require.Equal(t, 4, preparations)
	require.Equal(t, 2, mutations)
}

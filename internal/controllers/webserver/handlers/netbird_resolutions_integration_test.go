package handlers

import (
	"context"
	"errors"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/nats/netbirdcommand"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/stretchr/testify/require"
)

func exerciseNetbirdResolutionRoutes(t *testing.T, h *Handler, e *echo.Echo, ctx context.Context, scope access.Scope, device, path string) {
	t.Helper()
	previous, oldResolution := h.NetbirdOperations, h.NetbirdResolutions
	defer func() { h.NetbirdOperations = previous; h.NetbirdResolutions = oldResolution }()
	var command inventory.NetbirdOperationCommand
	store, err := inventory.NewNetbirdOperationStore(h.Model.DB, h.Access, false, func(context.Context, netbirdcommand.Identity) (netbirdcommand.State, error) {
		if command.RequestID == "" {
			return netbirdcommand.State{Status: "ready", Revision: strings.Repeat("b", 64), Remaining: 4096}, nil
		}
		hash, _ := command.Digest()
		return netbirdcommand.State{Status: "unconfirmed", Revision: strings.Repeat("c", 64), Remaining: 4095, PendingID: command.RequestID, PendingHash: hash, CanRelease: true}, nil
	}, func(_ context.Context, c inventory.NetbirdOperationCommand) (*inventory.NetbirdOperationResult, error) {
		command = c
		return nil, errors.New("owned lost command reply")
	})
	require.NoError(t, err)
	review, err := store.Review(ctx, "apple-console-admin", scope, device, "up", "")
	require.NoError(t, err)
	op, err := store.Request(ctx, "apple-console-admin", scope, device, uuid.NewString(), "up", "", review.Revision)
	require.NoError(t, err)
	_, err = store.DispatchOne(ctx)
	require.NoError(t, err)
	controls, releases := 0, 0
	releaseID := ""
	resolution, err := inventory.NewNetbirdResolutionStore(store, func(_ context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
		controls++
		if c.Kind == "release" {
			releases++
			if releases > 1 {
				releaseID = c.RequestID
			}
			return nil, errors.New("owned lost release reply")
		}
		p, err := netbirdcommand.ControlResponseFor(c, "ok")
		require.NoError(t, err)
		hash, err := command.Digest()
		require.NoError(t, err)
		p.Receipt = netbirdcommand.Receipt{Version: netbirdcommand.Version, RequestID: op.ID, DeviceID: device, CommandHash: hash, Revision: op.Revision, Operation: op.Operation, Status: "unconfirmed"}
		p.ReleaseID = releaseID
		require.True(t, p.Matches(c))
		return &p, nil
	})
	require.NoError(t, err)
	h.NetbirdOperations, h.NetbirdResolutions = store, resolution
	request := ownedTagHTTPRequest(t, h, e, ctx)
	location := path + "/" + op.ID + "/resolution"
	confirm := url.Values{"csrf": {"console-test-token"}, "confirmed": {"yes"}, "resolution_id": {uuid.NewString()}, "revision": {strings.Repeat("a", 64)}}
	for _, actor := range []string{"scoped-viewer", "scoped-operator"} {
		require.Equal(t, 403, request(actor, "GET", location, nil, "console-test-token").Code)
		require.Equal(t, 403, request(actor, "POST", location, confirm, "console-test-token").Code)
	}
	require.Zero(t, controls)
	response := request("apple-console-admin", "GET", location, nil, "console-test-token")
	require.Equal(t, 200, response.Code, response.Body.String())
	require.Contains(t, response.Body.String(), "allow further NetBird commands")
	require.Contains(t, response.Body.String(), "Owned &lt;NetBird endpoint&gt;")
	require.Zero(t, releases)
	v, err := resolution.Review(ctx, "apple-console-admin", scope, device, op.ID)
	require.NoError(t, err)
	confirm.Set("revision", v.Revision)
	for _, alter := range []func(url.Values){func(v url.Values) { v.Del("confirmed") }, func(v url.Values) { v.Add("resolution_id", uuid.NewString()) }, func(v url.Values) { v.Set("request_id", uuid.NewString()) }, func(v url.Values) { v.Set("resolution_id", "bad") }} {
		bad := url.Values{}
		for k, values := range confirm {
			bad[k] = append([]string{}, values...)
		}
		alter(bad)
		require.Equal(t, 400, request("apple-console-admin", "POST", location, bad, "console-test-token").Code)
	}
	require.Equal(t, 400, request("apple-console-admin", "GET", location+"?confirmed=yes", nil, "console-test-token").Code)
	require.Equal(t, 403, request("apple-console-admin", "POST", location, confirm, "").Code)
	response = request("apple-console-admin", "POST", location, confirm, "console-test-token")
	require.Equal(t, 204, response.Code, response.Body.String())
	require.Equal(t, location, response.Header().Get("HX-Redirect"))
	require.Equal(t, 1, releases)
	require.Equal(t, 204, request("apple-console-admin", "POST", location, confirm, "console-test-token").Code)
	require.Equal(t, 1, releases)
	response = request("apple-console-admin", "GET", location, nil, "console-test-token")
	require.Equal(t, 200, response.Code, response.Body.String())
	require.Contains(t, response.Body.String(), "Resolution is not yet confirmed")
	require.Contains(t, response.Body.String(), `/resolution/reconcile`)
	retained, err := store.Read(ctx, "apple-console-admin", scope, device, op.ID)
	require.NoError(t, err)
	require.Nil(t, retained.ReleasedAt)
	v, err = resolution.Review(ctx, "apple-console-admin", scope, device, op.ID)
	require.NoError(t, err)
	require.True(t, v.CanRetry)
	retry := url.Values{"csrf": {"console-test-token"}, "confirmed": {"yes"}, "resolution_id": {confirm.Get("resolution_id")}, "retry_id": {uuid.NewString()}, "revision": {v.Revision}}
	exerciseNetbirdRetryFormRejections(t, request, location+"/retry", retry)
	response = request("apple-console-admin", "POST", location+"/retry", retry, "console-test-token")
	require.Equal(t, 204, response.Code, response.Body.String())
	require.Equal(t, location, response.Header().Get("HX-Redirect"))
	before := controls
	require.Equal(t, 204, request("apple-console-admin", "POST", location+"/retry", retry, "console-test-token").Code)
	require.Equal(t, before, controls)
	require.Equal(t, 2, releases)
	check := url.Values{"csrf": {"console-test-token"}, "confirmed": {"yes"}, "resolution_id": {releaseID}}
	require.Equal(t, 403, request("scoped-viewer", "POST", location+"/reconcile", check, "console-test-token").Code)
	require.Equal(t, 204, request("apple-console-admin", "POST", location+"/reconcile", check, "console-test-token").Code)
	response = request("apple-console-admin", "GET", location, nil, "console-test-token")
	require.Equal(t, 200, response.Code, response.Body.String())
	require.Contains(t, response.Body.String(), "Resolution confirmed")
	require.NotContains(t, response.Body.String(), `name="confirmed"`)
	retained, err = store.Read(ctx, "apple-console-admin", scope, device, op.ID)
	require.NoError(t, err)
	require.NotNil(t, retained.ReleasedAt)
	require.Equal(t, "unconfirmed", retained.Status)
	require.Nil(t, retained.Result)
	require.Equal(t, 2, releases)
	exerciseNetbirdConnectionWithdrawalRoutes(t, h, e, ctx, scope, device, path)
}

func exerciseNetbirdRetryFormRejections(t *testing.T, request func(string, string, string, url.Values, string) *httptest.ResponseRecorder, path string, form url.Values) {
	t.Helper()
	for _, actor := range []string{"scoped-viewer", "scoped-operator"} {
		require.Equal(t, 403, request(actor, "POST", path, form, "console-test-token").Code)
	}
	require.Equal(t, 403, request("apple-console-admin", "POST", path, form, "").Code)
	for _, alter := range []func(url.Values){func(v url.Values) { v.Del("confirmed") }, func(v url.Values) { v.Del("retry_id") }, func(v url.Values) { v.Add("retry_id", uuid.NewString()) }, func(v url.Values) { v.Set("retry_id", "invalid") }, func(v url.Values) { v.Set("setup_key", "injected") }} {
		bad := url.Values{}
		for k, list := range form {
			bad[k] = append([]string{}, list...)
		}
		alter(bad)
		require.Equal(t, 400, request("apple-console-admin", "POST", path, bad, "console-test-token").Code)
	}
}

func exerciseNetbirdConnectionWithdrawalRoutes(t *testing.T, h *Handler, e *echo.Echo, ctx context.Context, scope access.Scope, device, path string) {
	t.Helper()
	oldStore, oldResolver := h.NetbirdOperations, h.NetbirdResolutions
	defer func() { h.NetbirdOperations = oldStore; h.NetbirdResolutions = oldResolver }()
	var command inventory.NetbirdOperationCommand
	s, err := inventory.NewNetbirdOperationStore(h.Model.DB, h.Access, false, func(context.Context, netbirdcommand.Identity) (netbirdcommand.State, error) {
		return netbirdcommand.State{Status: "ready", Revision: strings.Repeat("b", 64), Remaining: 4096}, nil
	}, func(_ context.Context, c inventory.NetbirdOperationCommand) (*inventory.NetbirdOperationResult, error) {
		command = c
		return nil, errors.New("owned command was not delivered")
	})
	require.NoError(t, err)
	v, err := s.Review(ctx, "apple-console-admin", scope, device, "down", "")
	require.NoError(t, err)
	r, err := s.Request(ctx, "apple-console-admin", scope, device, uuid.NewString(), "down", "", v.Revision)
	require.NoError(t, err)
	_, err = s.DispatchOne(ctx)
	require.NoError(t, err)
	withdrawals, queries := 0, 0
	resolutionID := ""
	resolver, err := inventory.NewNetbirdResolutionStore(s, func(_ context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
		queries++
		if c.Kind == "withdraw" {
			withdrawals++
			require.Equal(t, r.Revision, c.Revision)
			require.Equal(t, "down", c.Operation)
			if withdrawals > 1 {
				resolutionID = c.RequestID
			}
			return nil, errors.New("owned withdrawal request or response lost")
		}
		if resolutionID == "" {
			p, e := netbirdcommand.ControlResponseFor(c, "missing")
			return &p, e
		}
		p, e := netbirdcommand.ControlResponseFor(c, "ok")
		require.NoError(t, e)
		p.Receipt, e = netbirdcommand.ReceiptFor(command, "withdrawn")
		require.NoError(t, e)
		p.ReleaseID = resolutionID
		return &p, nil
	})
	require.NoError(t, err)
	h.NetbirdOperations, h.NetbirdResolutions = s, resolver
	request := ownedTagHTTPRequest(t, h, e, ctx)
	location := path + "/" + r.ID + "/resolution"
	page := request("apple-console-admin", "GET", location, nil, "console-test-token")
	require.Equal(t, 200, page.Code, page.Body.String())
	require.Contains(t, page.Body.String(), "Confirm withdrawal")
	require.Contains(t, page.Body.String(), "rejects any later delivery")
	review, err := resolver.Review(ctx, "apple-console-admin", scope, device, r.ID)
	require.NoError(t, err)
	form := url.Values{"csrf": {"console-test-token"}, "confirmed": {"yes"}, "resolution_id": {uuid.NewString()}, "revision": {review.Revision}}
	for _, actor := range []string{"scoped-viewer", "scoped-operator"} {
		require.Equal(t, 403, request(actor, "POST", location, form, "console-test-token").Code)
	}
	require.Equal(t, 403, request("apple-console-admin", "POST", location, form, "").Code)
	response := request("apple-console-admin", "POST", location, form, "console-test-token")
	require.Equal(t, 204, response.Code, response.Body.String())
	require.Equal(t, 1, withdrawals)
	before := queries
	require.Equal(t, 204, request("apple-console-admin", "POST", location, form, "console-test-token").Code)
	require.Equal(t, before, queries)
	page = request("apple-console-admin", "GET", location, nil, "console-test-token")
	require.Equal(t, 200, page.Code, page.Body.String())
	require.Contains(t, page.Body.String(), "Confirm recovery attempt")
	review, err = resolver.Review(ctx, "apple-console-admin", scope, device, r.ID)
	require.NoError(t, err)
	require.Equal(t, "withdraw", review.RetryKind)
	retry := url.Values{"csrf": {"console-test-token"}, "confirmed": {"yes"}, "resolution_id": {form.Get("resolution_id")}, "retry_id": {uuid.NewString()}, "revision": {review.Revision}}
	exerciseNetbirdRetryFormRejections(t, request, location+"/retry", retry)
	response = request("apple-console-admin", "POST", location+"/retry", retry, "console-test-token")
	require.Equal(t, 204, response.Code, response.Body.String())
	require.Equal(t, 2, withdrawals)
	check := url.Values{"csrf": {"console-test-token"}, "confirmed": {"yes"}, "resolution_id": {form.Get("resolution_id")}}
	require.Equal(t, 204, request("apple-console-admin", "POST", location+"/reconcile", check, "console-test-token").Code)
	retained, err := s.Read(ctx, "apple-console-admin", scope, device, r.ID)
	require.NoError(t, err)
	require.NotNil(t, retained.ReleasedAt)
	require.Equal(t, "unconfirmed", retained.Status)
	page = request("apple-console-admin", "GET", location, nil, "console-test-token")
	require.Contains(t, page.Body.String(), "Resolution confirmed")
	require.NotContains(t, page.Body.String(), `name="confirmed"`)
}

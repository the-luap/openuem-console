package handlers

import (
	"context"
	"errors"
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
			releaseID = c.RequestID
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
	require.Equal(t, 1, releases)
}

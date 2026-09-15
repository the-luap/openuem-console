package handlers

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/open-uem/nats/netbirdcommand"
	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/stretchr/testify/require"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func exerciseNetbirdRemovalRecoveryRoutes(t *testing.T, h *Handler, e *echo.Echo, ctx context.Context, tenant, site, foreign int, original netbirdcommand.Command, originalRelease string) {
	t.Helper()
	old := h.NetbirdRemovalRecoveries
	defer func() { h.NetbirdRemovalRecoveries = old }()
	originalHash, err := original.Digest()
	require.NoError(t, err)
	reference := netbirdcommand.RemovalRecoveryReference{RequestID: original.RequestID, CommandHash: originalHash, Revision: original.Revision, ReleaseID: originalRelease, Removal: original.Removal}
	absent := false
	var command netbirdcommand.Command
	native, inspections, queries, mutations := 0, 0, 0, 0
	receiptState, releaseID := "completed", ""
	loseReply := false
	control := func(_ context.Context, c netbirdcommand.ControlRequest) (*netbirdcommand.ControlResponse, error) {
		if c.Kind == "removal-recovery-state" {
			inspections++
			require.Equal(t, reference, c.RemovalRecoveryOriginal)
			if absent {
				p, err := netbirdcommand.ControlResponseFor(c, "missing")
				return &p, err
			}
			p, err := netbirdcommand.ControlResponseFor(c, "ok")
			p.State = netbirdcommand.State{Status: "ready", Revision: strings.Repeat("e", 64), Remaining: 100}
			p.RemovalRecovery = netbirdcommand.RemovalRecovery{Original: reference, Mode: "manifest", JournalRevision: p.State.Revision, StateDigest: strings.Repeat("a", 64)}
			return &p, err
		}
		if c.Kind == "state" {
			p, err := netbirdcommand.ControlResponseFor(c, "ok")
			p.State = netbirdcommand.State{Status: "ready", Revision: strings.Repeat("e", 64), Remaining: 100}
			if receiptState == "unconfirmed" {
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
				return nil, errors.New("owned lost resolution reply")
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
	store, err := inventory.NewNetbirdRemovalRecoveryDeliveryStore(h.Model.DB, h.Access, true, control, func(_ context.Context, c netbirdcommand.Command) (*netbirdcommand.Receipt, error) {
		native++
		require.Equal(t, netbirdcommand.RemovalRecoveryVersion, c.Version)
		require.Equal(t, "recover-removal", c.Operation)
		require.Equal(t, reference, c.RemovalRecovery.Original)
		command = c
		if receiptState != "completed" {
			return nil, errors.New("owned lost continuation reply")
		}
		out, err := netbirdcommand.ReceiptFor(c, "completed")
		return &out, err
	})
	require.NoError(t, err)
	h.NetbirdRemovalRecoveries = store
	request := ownedTagHTTPRequest(t, h, e, ctx)
	path := fmt.Sprintf("/tenant/%d/site/%d/computers/%s/netbird/removal-recoveries", tenant, site, original.DeviceID)
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
	require.Equal(t, 403, request("scoped-viewer", "GET", path+"/review?original_id="+original.RequestID, nil, "").Code)
	absent = true
	absentReview := request("scoped-operator", "GET", path+"/review?original_id="+original.RequestID, nil, "")
	require.NotEqual(t, 200, absentReview.Code)
	require.NotContains(t, absentReview.Body.String(), "Queue continuation")
	require.NotContains(t, absentReview.Body.String(), "Queue continuation")
	absent = false
	reviewPath := path + "/review?original_id=" + original.RequestID
	review := request("scoped-operator", "GET", reviewPath, nil, "")
	require.Equal(t, 200, review.Code)
	require.Contains(t, review.Body.String(), "Owned removal &lt;endpoint&gt;")
	form := fields(review.Body.String())
	form.Set("confirmed", "yes")
	require.Equal(t, original.RequestID, form.Get("original_id"))
	require.NotEmpty(t, form.Get("request_id"))
	require.NotEmpty(t, form.Get("revision"))
	for _, change := range []string{"confirmation", "duplicate", "unknown", "revision", "query", "original"} {
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
		case "original":
			bad.Set("original_id", uuid.NewString())
		case "query":
			target += "?recovery_digest=" + strings.Repeat("a", 64)
		}
		code := request("scoped-operator", "POST", target, bad, "console-test-token").Code
		if change == "original" {
			require.NotEqual(t, 204, code)
		} else {
			require.Equal(t, 400, code, change)
		}
	}
	require.Equal(t, 403, request("scoped-viewer", "POST", path, form, "console-test-token").Code)
	require.Equal(t, 403, request("scoped-operator", "POST", path, form, "wrong").Code)
	require.Equal(t, 204, request("scoped-operator", "POST", path, form, "console-test-token").Code)
	admittedInspections := inspections
	require.Equal(t, 204, request("scoped-operator", "POST", path, form, "console-test-token").Code)
	require.Equal(t, admittedInspections, inspections)
	receiptPath := path + "/" + form.Get("request_id")
	response := request("scoped-viewer", "GET", receiptPath, nil, "")
	require.Equal(t, 200, response.Code, response.Body.String())
	require.NotContains(t, response.Body.String(), "Cancel continuation request")
	require.Contains(t, response.Body.String(), "Queued for removal continuation")
	require.Zero(t, native)
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
		absent = false
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
		beforeQueries, beforeNative, beforeInspections := queries, native, inspections
		response = request("scoped-viewer", "GET", receiptPath, nil, "")
		require.Equal(t, 200, response.Code, response.Body.String())
		require.Equal(t, beforeQueries, queries)
		require.Equal(t, beforeNative, native)
		require.Equal(t, beforeInspections, inspections)
		require.NotContains(t, response.Body.String(), "Check retained receipt")
		require.NotContains(t, response.Body.String(), "owned-native-ui-source")
		post := url.Values{"revision": {form.Get("revision")}, "confirmed": {"yes"}, "csrf": {strings.Repeat("t", 32)}}
		if scenario == "observe" {
			absent = true
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
			require.Contains(t, response.Body.String(), "Package removal verified")
		} else {
			require.Contains(t, response.Body.String(), "Reviewed resolution confirmed")
			require.Contains(t, response.Body.String(), "unconfirmed")
		}
		require.Equal(t, beforeNative, native)
		require.Equal(t, beforeInspections, inspections)
		require.Equal(t, 404, request("apple-console-admin", "GET", strings.Replace(receiptPath, fmt.Sprintf("/tenant/%d/", tenant), fmt.Sprintf("/tenant/%d/", foreign), 1), nil, "").Code)
	}
	originalPath := fmt.Sprintf("/tenant/%d/site/%d/computers/%s/netbird/removals/%s", tenant, site, original.DeviceID, original.RequestID)
	link := path + "/review?original_id=" + original.RequestID
	require.Contains(t, request("scoped-operator", "GET", originalPath, nil, "").Body.String(), link)
	require.NotContains(t, request("scoped-viewer", "GET", originalPath, nil, "").Body.String(), "Review continuation of interrupted removal")
	var outcome string
	require.NoError(t, h.Model.DB.QueryRowContext(ctx, `SELECT outcome FROM uem_netbird_removal_results WHERE request_id=$1`, original.RequestID).Scan(&outcome))
	require.Equal(t, "unconfirmed", outcome)
	require.Equal(t, 4, native)
	require.Equal(t, 2, mutations)
}

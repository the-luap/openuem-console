package handlers

import (
	"crypto/x509"
	"encoding/pem"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/registry"
)

func exerciseWindowsSoftwareReconciliation(t *testing.T, h *Handler, identity *enrollment.Response, keys *enrollment.Keys, path string, request func(string, string, string, url.Values) *httptest.ResponseRecorder, key *enrollment.SoftwareRecipientKey, recipient *enrollment.SoftwareRecipient, cert *x509.Certificate, call func(enrollment.SoftwareRequest) *enrollment.SoftwareReply) {
	t.Helper()
	prepare := url.Values{"request_id": {uuid.NewString()}, "device": {identity.DeviceID}, "operation": {"install"}, "confirmed": {"yes"}}
	if rec := request("scoped-operator", "POST", path, prepare); rec.Code != 303 {
		t.Fatal("check fixture preparation", rec.Code, rec.Body.String())
	}
	var id string
	if err := h.Model.DB.QueryRow(`SELECT id FROM uem_windows_software_requests WHERE request_id=$1`, prepare.Get("request_id")).Scan(&id); err != nil {
		t.Fatal(err)
	}
	dispatch := path + "/" + id + "/dispatch"
	fields := func(rec *httptest.ResponseRecorder, names ...string) url.Values {
		t.Helper()
		if rec.Code != 200 {
			t.Fatal("check review failed", rec.Code, rec.Body.String())
		}
		values := url.Values{"confirmed": {"yes"}}
		for _, name := range names {
			match := regexp.MustCompile(`name="` + name + `" value="([^"]+)"`).FindStringSubmatch(rec.Body.String())
			if len(match) != 2 {
				t.Fatal("missing review field", name)
			}
			values.Set(name, match[1])
		}
		return values
	}
	form := fields(request("scoped-operator", "GET", dispatch, nil), "dispatch_id", "review_hash")
	if rec := request("scoped-operator", "POST", dispatch, form); rec.Code != 303 {
		t.Fatal("check fixture dispatch", rec.Code, rec.Body.String())
	}
	original := call(enrollment.SoftwareRequest{Action: "poll", RecipientID: recipient.ID}).Task
	if original == nil {
		t.Fatal("check fixture task missing")
	}
	block, _ := pem.Decode([]byte(identity.Authority))
	if block == nil {
		t.Fatal("fixture authority missing")
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := key.Open(*original, root, recipient.Identity, recipient.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Close()
	nonce := secret.Nonce()
	defer clear(nonce)
	outcome := enrollment.SoftwareOutcome{State: "uncertain", Execution: "unknown", Before: enrollment.SoftwareObservation{State: "unknown"}, After: enrollment.SoftwareObservation{State: "unknown"}, Error: "interrupted"}
	result, err := enrollment.SignSoftwareResult(original.Context, recipient.Identity, secret.TaskHash(), nonce, outcome, cert, keys.Certificate, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(result.Nonce)
	proof, err := enrollment.SignSoftwareSubmission(*result, recipient.Identity, cert, keys.Certificate, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	call(enrollment.SoftwareRequest{Action: "result", Result: result, Submission: proof})
	reviewPath, history := dispatch+"/reconcile", dispatch+"/reconciliations"
	if rec := request("scoped-viewer", "GET", reviewPath, nil); rec.Code != 403 {
		t.Fatal("reader reviewed a software check", rec.Code)
	}
	if rec := request("scoped-viewer", "GET", history, nil); rec.Code != 200 || strings.Contains(rec.Body.String(), "Review a read-only check") || !strings.Contains(rec.Body.String(), "Original execution evidence") {
		t.Fatal("reader check history boundary", rec.Code, rec.Body.String())
	}
	review := request("scoped-operator", "GET", reviewPath, nil)
	form = fields(review, "reconciliation_id", "review_hash", "expires_at")
	if review.Header().Get("Cache-Control") != "no-store" || !strings.Contains(review.Body.String(), "Owned &lt;Windows&gt; target") || !strings.Contains(review.Body.String(), "read-only check") {
		t.Fatal("unsafe check review")
	}
	for _, private := range []string{"route-secret", "route-license", "packages.example.test", "BEGIN CERTIFICATE", "system_process_created", "original_nonce"} {
		if strings.Contains(review.Body.String(), private) {
			t.Fatal("check review exposed private evidence")
		}
	}
	clone := func() url.Values {
		copy := url.Values{}
		for key, value := range form {
			copy[key] = append([]string(nil), value...)
		}
		return copy
	}
	for _, change := range []func(url.Values){func(f url.Values) { f.Del("confirmed") }, func(f url.Values) { f.Add("reconciliation_id", uuid.NewString()) }, func(f url.Values) { f.Set("review_hash", "invalid") }, func(f url.Values) { f.Set("expires_at", "tomorrow") }, func(f url.Values) { f.Set("expires_at", strings.ReplaceAll(f.Get("expires_at"), "Z", "+00:00")) }, func(f url.Values) { f.Set("arguments", "unapproved") }} {
		f := clone()
		change(f)
		if rec := request("scoped-operator", "POST", reviewPath, f); rec.Code != 400 {
			t.Fatal("ambiguous software check accepted", rec.Code, rec.Body.String())
		}
	}
	for _, test := range []struct {
		user, suffix string
		code         int
	}{{"scoped-viewer", "", 403}, {"scoped-operator", "?expires_at=tomorrow", 400}} {
		if rec := request(test.user, "POST", reviewPath+test.suffix, clone()); rec.Code != test.code {
			t.Fatal("check route authorization/query boundary", rec.Code)
		}
	}
	f := clone()
	f.Set("csrf", "wrong")
	if rec := request("scoped-operator", "POST", reviewPath, f); rec.Code != 403 {
		t.Fatal("check CSRF bypass", rec.Code)
	}
	f = clone()
	f.Set("review_hash", strings.Repeat("a", 9000))
	if rec := request("scoped-operator", "POST", reviewPath, f); rec.Code != 403 {
		t.Fatal("unbounded check body", rec.Code)
	}
	f = clone()
	f.Set("review_hash", strings.Repeat("a", 64))
	if rec := request("scoped-operator", "POST", reviewPath, f); rec.Code != 409 {
		t.Fatal("stale check review", rec.Code)
	}
	for range 2 {
		if rec := request("scoped-operator", "POST", reviewPath, clone()); rec.Code != 303 || rec.Header().Get("Location") != history {
			t.Fatal("exact check confirmation retry", rec.Code, rec.Body.String())
		}
	}
	if rec := request("scoped-viewer", "GET", history, nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Queued; waiting for a compatible agent") || strings.Contains(rec.Body.String(), "Cancel queued check") {
		t.Fatal("queued reader check history", rec.Code, rec.Body.String())
	}
	if rec := request("scoped-operator", "GET", history, nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Cancel queued check") || strings.Contains(rec.Body.String(), "Review a read-only check") {
		t.Fatal("active check did not suppress competing review", rec.Code)
	}
	cancel := history + "/" + form.Get("reconciliation_id") + "/cancel"
	if rec := request("scoped-viewer", "POST", cancel, url.Values{"confirmed": {"yes"}}); rec.Code != 403 {
		t.Fatal("reader cancelled a check", rec.Code)
	}
	if rec := request("scoped-operator", "POST", cancel, nil); rec.Code != 400 {
		t.Fatal("check cancellation lacked confirmation", rec.Code)
	}
	for range 2 {
		if rec := request("scoped-operator", "POST", cancel, url.Values{"confirmed": {"yes"}}); rec.Code != 303 {
			t.Fatal("check cancel retry", rec.Code, rec.Body.String())
		}
	}
	form = fields(request("scoped-operator", "GET", reviewPath, nil), "reconciliation_id", "review_hash", "expires_at")
	if rec := request("scoped-operator", "POST", reviewPath, form); rec.Code != 303 {
		t.Fatal("second explicit check", rec.Code, rec.Body.String())
	}
	channel, err := registry.NewAccessStore(h.Model.DB)
	if err != nil {
		t.Fatal(err)
	}
	check := func(message enrollment.SoftwareReconciliationRequest) *enrollment.SoftwareReconciliationReply {
		t.Helper()
		active, err := channel.ActiveIdentity(t.Context(), identity.DeviceID)
		if err != nil {
			t.Fatal(err)
		}
		tx, err := h.Model.DB.BeginTx(t.Context(), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if _, _, _, err = channel.SoftwareIdentity(t.Context(), tx, active.Scope, active.ID); err != nil {
			t.Fatal(err)
		}
		var locked string
		if err = tx.QueryRow(`SELECT oid FROM agents WHERE oid=$1 FOR UPDATE`, active.ID).Scan(&locked); err != nil {
			t.Fatal(err)
		}
		message.Version, message.Protocol, message.AgentID = enrollment.SoftwareReconciliationVersion, enrollment.SoftwareReconciliationProtocol, active.ID
		reply, err := channel.HandleSoftwareReconciliationInTransaction(t.Context(), tx, *active, message)
		if err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
		return reply
	}
	delivery := check(enrollment.SoftwareReconciliationRequest{Action: "poll"})
	if delivery.Task == nil {
		t.Fatal("confirmed check was not delivered")
	}
	hash, _ := delivery.Task.Digest()
	observation := enrollment.SoftwareReconciliationOutcome{State: "observed", Admission: enrollment.SoftwareBootSession{Sequence: 21, SystemProcessCreated: 133000000000000000}, Current: enrollment.SoftwareBootSession{Sequence: 22, SystemProcessCreated: 133000000000000001}, Observation: enrollment.SoftwareObservation{State: "present", Version: original.Context.Expectation.Detection.Version}}
	observed, err := enrollment.SignSoftwareReconciliationResult(delivery.Task.Context, hash, nonce, observation, cert, keys.Certificate, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(observed.OriginalNonce)
	submission, err := enrollment.SignSoftwareReconciliationSubmission(*observed, recipient.Identity, cert, keys.Certificate, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	check(enrollment.SoftwareReconciliationRequest{Action: "result", Result: observed, Submission: submission})
	if rec := request("scoped-viewer", "GET", history, nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Original execution remains uncertain") || !strings.Contains(rec.Body.String(), "This verified observation released the original reservation") || strings.Contains(rec.Body.String(), "Review a read-only check") {
		t.Fatal("signed observation replaced original history or admitted repeated check", rec.Code, rec.Body.String())
	}
	if rec := request("scoped-operator", "POST", history+"/"+form.Get("reconciliation_id")+"/cancel", url.Values{"confirmed": {"yes"}}); rec.Code != 409 {
		t.Fatal("reported check was cancelled", rec.Code)
	}
}

package handlers

import (
	"context"
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

// Exercise actual routes and registry cryptography using an owned synthetic
// identity. No installer or external endpoint is invoked by these route tests.
func exerciseWindowsSoftwareDispatch(t *testing.T, h *Handler, ctx context.Context, identity *enrollment.Response, keys *enrollment.Keys, path string, prepare url.Values, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	if rec := request("scoped-operator", "POST", path, prepare); rec.Code != 303 {
		t.Fatal("dispatch preparation", rec.Code, rec.Body.String())
	}
	var id string
	if err := h.Model.DB.QueryRowContext(ctx, `SELECT id FROM uem_windows_software_requests WHERE request_id=$1`, prepare.Get("request_id")).Scan(&id); err != nil {
		t.Fatal(err)
	}
	dispatch := path + "/" + id + "/dispatch"
	if rec := request("scoped-operator", "GET", dispatch, nil); rec.Code != 409 {
		t.Fatal("review accepted missing recipient", rec.Code)
	}
	channel, err := registry.NewAccessStore(h.Model.DB)
	if err != nil {
		t.Fatal(err)
	}
	key, err := enrollment.NewSoftwareRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Close)
	call := func(message enrollment.SoftwareRequest) *enrollment.SoftwareReply {
		active, err := channel.ActiveIdentity(ctx, identity.DeviceID)
		if err != nil {
			t.Fatal(err)
		}
		tx, err := h.Model.DB.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if _, _, _, err = channel.SoftwareIdentity(ctx, tx, active.Scope, active.ID); err != nil {
			t.Fatal(err)
		}
		var locked string
		if err = tx.QueryRowContext(ctx, `SELECT oid FROM agents WHERE oid=$1 FOR UPDATE`, active.ID).Scan(&locked); err != nil {
			t.Fatal(err)
		}
		message.Version, message.Protocol, message.AgentID = enrollment.SoftwareVersion, enrollment.SoftwareProtocol, active.ID
		reply, err := channel.HandleSoftwareInTransaction(ctx, tx, *active, message)
		if err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
		return reply
	}
	reply := call(enrollment.SoftwareRequest{Action: "challenge", PublicKey: key.PublicKey()})
	block, _ := pem.Decode([]byte(identity.Certificate))
	if block == nil {
		t.Fatal("fixture certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := enrollment.SignSoftwareRegistration(*reply.Registration, cert, keys.Certificate, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	registered := call(enrollment.SoftwareRequest{Action: "register", Registration: reply.Registration, Signature: signature})
	if rec := request("scoped-viewer", "GET", dispatch, nil); rec.Code != 403 {
		t.Fatal("reader reviewed execution", rec.Code)
	}
	rec := request("scoped-operator", "GET", dispatch, nil)
	if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" || !strings.Contains(rec.Body.String(), "Owned &lt;Windows&gt; target") {
		t.Fatal("unsafe dispatch review", rec.Code, rec.Body.String())
	}
	for _, secret := range []string{"route-secret", "route-license", "packages.example.test", "BEGIN CERTIFICATE"} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Fatal("review leaked private intent")
		}
	}
	fields := url.Values{"confirmed": {"yes"}}
	for _, name := range []string{"dispatch_id", "review_hash"} {
		match := regexp.MustCompile(`name="` + name + `" value="([a-f0-9-]+)"`).FindStringSubmatch(rec.Body.String())
		if len(match) != 2 {
			t.Fatal("missing bound review field", name)
		}
		fields.Set(name, match[1])
	}
	clone := func() url.Values {
		f := url.Values{}
		for key, values := range fields {
			f[key] = append([]string(nil), values...)
		}
		return f
	}
	for _, change := range []func(url.Values){func(f url.Values) { f.Del("confirmed") }, func(f url.Values) { f.Add("dispatch_id", uuid.NewString()) }, func(f url.Values) { f.Set("review_hash", "invalid") }, func(f url.Values) { f.Set("source_url", "https://unapproved.example.test/a.msi") }} {
		f := clone()
		change(f)
		if rec := request("scoped-operator", "POST", dispatch, f); rec.Code != 400 {
			t.Fatal("ambiguous dispatch", rec.Code, rec.Body.String())
		}
	}
	for _, item := range []struct {
		user, suffix string
		code         int
	}{{"scoped-viewer", "", 403}, {"scoped-operator", "?operation=remove", 400}} {
		if rec := request(item.user, "POST", dispatch+item.suffix, clone()); rec.Code != item.code {
			t.Fatal("dispatch route boundary", rec.Code)
		}
	}
	f := clone()
	f.Set("csrf", "wrong")
	if rec := request("scoped-operator", "POST", dispatch, f); rec.Code != 403 {
		t.Fatal("dispatch CSRF bypass", rec.Code)
	}
	f = clone()
	f.Set("review_hash", strings.Repeat("a", 9000))
	if rec := request("scoped-operator", "POST", dispatch, f); rec.Code != 403 {
		t.Fatal("unbounded dispatch body", rec.Code)
	}
	f = clone()
	f.Set("review_hash", strings.Repeat("a", 64))
	if rec := request("scoped-operator", "POST", dispatch, f); rec.Code != 409 {
		t.Fatal("stale review accepted", rec.Code)
	}
	var count int
	if err := h.Model.DB.QueryRowContext(ctx, `SELECT count(*) FROM uem_windows_software_dispatches WHERE preparation_id=$1`, id).Scan(&count); err != nil || count != 0 {
		t.Fatal("invalid route created task", count, err)
	}
	for range 2 {
		if rec := request("scoped-operator", "POST", dispatch, clone()); rec.Code != 303 || rec.Header().Get("Location") != path {
			t.Fatal("dispatch retry", rec.Code, rec.Body.String())
		}
	}
	if rec := request("scoped-viewer", "GET", path, nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Queued; waiting for the agent") || strings.Contains(rec.Body.String(), "Cancel queued operation") {
		t.Fatal("queued reader history", rec.Code, rec.Body.String())
	}
	cancel := dispatch + "/cancel"
	for _, item := range []struct {
		user, suffix string
		form         url.Values
		code         int
	}{{"scoped-viewer", "", url.Values{"confirmed": {"yes"}}, 403}, {"scoped-operator", "", nil, 400}, {"scoped-operator", "?confirmed=yes", url.Values{"confirmed": {"yes"}}, 400}, {"scoped-operator", "", url.Values{"confirmed": {"yes"}, "csrf": {"wrong"}}, 403}} {
		if rec := request(item.user, "POST", cancel+item.suffix, item.form); rec.Code != item.code {
			t.Fatal("cancel route boundary", rec.Code)
		}
	}
	for range 2 {
		if rec := request("scoped-operator", "POST", cancel, url.Values{"confirmed": {"yes"}}); rec.Code != 303 {
			t.Fatal("queued cancellation retry", rec.Code, rec.Body.String())
		}
	}
	if rec := request("scoped-viewer", "GET", path, nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Cancelled before delivery") {
		t.Fatal("cancelled dispatch history", rec.Code)
	}
	if reply := call(enrollment.SoftwareRequest{Action: "poll", RecipientID: registered.Recipient.ID}); reply.Task != nil {
		t.Fatal("cancelled route task delivered")
	}
	exerciseWindowsSoftwareReconciliation(t, h, identity, keys, path, request, key, registered.Recipient, cert, call)
}

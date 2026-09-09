package handlers

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
)

func exerciseAppleProfileRevisions(t *testing.T, h *Handler, ctx context.Context, tenant, site int, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	base := fmt.Sprintf("/tenant/%d/site/%d/ios/configurations", tenant, site)
	data, err := apple.BuildProfile("Historical <WiFi>", "com.example.route-revisions", "wifi", map[string]any{"SSID_STR": "Synthetic", "EncryptionType": "WPA", "Password": "synthetic-history-secret"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := h.Apple.SaveProfile(ctx, tenant, "", 0, data, "synthetic-history-actor")
	if err != nil {
		t.Fatal(err)
	}
	items, _, err := h.Apple.ProfileRevisions(ctx, tenant, p.ID, "")
	if err != nil || len(items) != 1 {
		t.Fatal("new profile missing its revision", err)
	}
	first := items[0]
	if _, err = h.Apple.SaveProfile(ctx, tenant, p.ID, 1, data, "synthetic-history-actor"); err != nil {
		t.Fatal(err)
	}
	page := base + "/" + p.ID + "/history"
	download := base + "/" + p.ID + "/revisions/" + first.ID + "/download"
	action := base + "/" + p.ID + "/revisions/" + first.ID + "/restore"
	form := func() url.Values {
		return url.Values{"expected_revision": {"2"}, "reason": {"Restore <approved> configuration"}, "confirmed": {"yes"}}
	}
	for _, user := range []string{"scoped-viewer", "scoped-operator", "organization-admin"} {
		rec := request(user, "GET", page, nil)
		if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" || !strings.Contains(rec.Body.String(), "Historical &lt;WiFi&gt;") || strings.Contains(rec.Body.String(), "synthetic-history-secret") {
			t.Fatal("revision history privacy failure", user, rec.Code)
		}
		if user != "organization-admin" {
			if strings.Contains(rec.Body.String(), "Download stored revision") || strings.Contains(rec.Body.String(), "Restore and deploy revision") {
				t.Fatal("scoped reader sees protected revision action")
			}
			if rec = request(user, "GET", download, nil); rec.Code != 403 {
				t.Fatal("scoped role downloaded credentials", rec.Code)
			}
			if rec = request(user, "POST", action, form()); rec.Code != 403 {
				t.Fatal("scoped role restored organization profile", rec.Code)
			}
		}
	}
	rec := request("organization-admin", "GET", download, nil)
	if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" || !strings.Contains(rec.Header().Get("Content-Disposition"), "attachment") || !strings.Contains(rec.Body.String(), "synthetic-history-secret") {
		t.Fatal("authorized historical download failed", rec.Code)
	}
	if rec = request("organization-admin", "GET", base+"/"+uuid.NewString()+"/revisions/"+first.ID+"/download", nil); rec.Code != 404 {
		t.Fatal("revision download was rebound to another profile", rec.Code)
	}
	for _, change := range []func(url.Values){func(f url.Values) { f.Del("confirmed") }, func(f url.Values) { f.Add("reason", "duplicate") }, func(f url.Values) { f.Set("reason", "") }, func(f url.Values) { f.Set("reason", strings.Repeat("x", 1001)) }, func(f url.Values) { f.Set("expected_revision", "02") }, func(f url.Values) { f.Set("payload", "unapproved") }} {
		f := form()
		change(f)
		if rec = request("organization-admin", "POST", action, f); rec.Code != 400 {
			t.Fatal("ambiguous restoration accepted", rec.Code)
		}
	}
	f := form()
	f.Set("csrf", "wrong")
	if rec = request("organization-admin", "POST", action, f); rec.Code != 403 {
		t.Fatal("restore CSRF bypass", rec.Code)
	}
	if rec = request("organization-admin", "POST", action+"?reason=query", form()); rec.Code != 400 {
		t.Fatal("query changed restoration", rec.Code)
	}
	f = form()
	f.Set("expected_revision", "1")
	if rec = request("organization-admin", "POST", action, f); rec.Code != 409 {
		t.Fatal("stale restoration accepted", rec.Code)
	}
	if rec = request("organization-admin", "POST", action, form()); rec.Code != 303 {
		t.Fatal("authorized restoration failed", rec.Code, rec.Body.String())
	}
	rec = request("organization-admin", "GET", page, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Restored as a new revision") || !strings.Contains(rec.Body.String(), "Restore &lt;approved&gt; configuration") || strings.Contains(rec.Body.String(), "synthetic-history-secret") {
		t.Fatal("restoration provenance missing or unsafe", rec.Code)
	}
	if rec = request("organization-admin", "POST", action, form()); rec.Code != 409 {
		t.Fatal("old browser page overwrote restored revision", rec.Code)
	}
	if rec = request("organization-admin", "POST", base+"/"+p.ID+"/delete", url.Values{}); rec.Code != 303 {
		t.Fatal("unassigned catalog deletion failed", rec.Code)
	}
	rec = request("organization-admin", "GET", page, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "catalog entry was deleted") || strings.Contains(rec.Body.String(), "Restore and deploy revision") {
		t.Fatal("deleted catalog lost immutable history or offers restoration", rec.Code)
	}
	if rec = request("organization-admin", "GET", download, nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "synthetic-history-secret") {
		t.Fatal("catalog deletion lost protected historical download", rec.Code)
	}
	if rec = request("scoped-viewer", "GET", base+"/history", nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Historical &lt;WiFi&gt;") {
		t.Fatal("deleted history is not discoverable", rec.Code)
	}
}

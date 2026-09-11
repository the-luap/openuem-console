package handlers

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/ent/agent"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/registry"
)

func exerciseWindowsSoftwareRequests(t *testing.T, h *Handler, ctx context.Context, tenant, site int, version string, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	r, err := registry.NewStore(h.Model.DB, strings.Repeat("k", 32))
	if err != nil {
		t.Fatal(err)
	}
	invitation, err := r.Invite(ctx, registry.InvitationOptions{Scope: registry.Scope{TenantID: tenant, SiteID: site}, Platform: "windows", Architecture: "amd64", ExpiresAt: time.Now().Add(time.Hour), MaxUses: 1}, "organization-admin")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := enrollment.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keys.Broker.Wipe)
	claim, err := keys.Request(invitation.URL[strings.LastIndex(invitation.URL, "/")+1:], "windows", "amd64", "Owned route Windows")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := r.Claim(ctx, *claim)
	if err != nil {
		t.Fatal(err)
	}
	if err = h.Model.Client.Agent.Create().SetID(identity.DeviceID).SetHostname("Owned <Windows> target").SetOs("windows").SetAgentStatus(agent.AgentStatusEnabled).AddSiteIDs(site).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/tenant/%d/site/%d/software/catalog/%s/windows-requests", tenant, site, version)
	form := func() url.Values {
		return url.Values{"request_id": {uuid.NewString()}, "device": {identity.DeviceID}, "operation": {"install"}, "confirmed": {"yes"}}
	}
	for _, user := range []string{"scoped-viewer", "scoped-operator", "organization-admin"} {
		rec := request(user, "GET", path, nil)
		body := rec.Body.String()
		if rec.Code != 200 || !strings.Contains(body, "preparations never execute automatically") || strings.Contains(body, "route-secret") || strings.Contains(body, "route-license") || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("unsafe preparation page", user, rec.Code, body)
		}
		if strings.Contains(body, "Prepare request") != (user != "scoped-viewer") {
			t.Fatal("preparation control rights", user)
		}
	}
	if rec := request("scoped-viewer", "POST", path, form()); rec.Code != 403 {
		t.Fatal("reader prepared a request", rec.Code)
	}
	for _, change := range []func(url.Values){
		func(f url.Values) { f.Del("confirmed") }, func(f url.Values) { f.Add("device", uuid.NewString()) }, func(f url.Values) { f.Set("operation", "execute") },
		func(f url.Values) { f.Set("argument", "unapproved") }, func(f url.Values) { f.Set("request_id", "invalid") },
	} {
		f := form()
		change(f)
		if rec := request("scoped-operator", "POST", path, f); rec.Code != 400 {
			t.Fatal("ambiguous preparation accepted", rec.Code, rec.Body.String())
		}
	}
	f := form()
	f.Set("csrf", "wrong")
	if rec := request("scoped-operator", "POST", path, f); rec.Code != 403 {
		t.Fatal("request CSRF bypass", rec.Code)
	}
	if rec := request("scoped-operator", "POST", path+"?operation=remove", form()); rec.Code != 400 {
		t.Fatal("query altered preparation", rec.Code)
	}
	f = form()
	f.Set("device", strings.Repeat("x", 9000))
	// The CSRF middleware reads the bounded body first and rejects the
	// incomplete form before the preparation handler can receive it.
	if rec := request("scoped-operator", "POST", path, f); rec.Code != 403 {
		t.Fatal("unbounded request body", rec.Code)
	}
	f = form()
	for range 2 {
		if rec := request("scoped-operator", "POST", path, f); rec.Code != 303 || rec.Header().Get("Location") != path {
			t.Fatal("request preparation/retry failed", rec.Code, rec.Body.String())
		}
	}
	var id string
	if err = h.Model.DB.QueryRowContext(ctx, `SELECT id FROM uem_windows_software_requests WHERE tenant_id=$1 AND request_id=$2`, tenant, f.Get("request_id")).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if rec := request("scoped-operator", "POST", path, form()); rec.Code != 409 {
		t.Fatal("second device preparation accepted", rec.Code)
	}
	cancel := path + "/" + id + "/cancel"
	if rec := request("scoped-viewer", "POST", cancel, url.Values{"confirmed": {"yes"}}); rec.Code != 403 {
		t.Fatal("reader cancelled preparation", rec.Code)
	}
	if rec := request("scoped-operator", "POST", cancel, nil); rec.Code != 400 {
		t.Fatal("cancellation omitted review", rec.Code)
	}
	for range 2 {
		if rec := request("scoped-operator", "POST", cancel, url.Values{"confirmed": {"yes"}}); rec.Code != 303 {
			t.Fatal("cancel/retry failed", rec.Code)
		}
	}
	if rec := request("scoped-viewer", "GET", path, nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Cancelled before delivery") || strings.Contains(rec.Body.String(), "Cancel preparation") {
		t.Fatal("history missing or reader mutation", rec.Code)
	}
	exerciseWindowsSoftwareDispatch(t, h, ctx, identity, keys, path, form(), request)
}

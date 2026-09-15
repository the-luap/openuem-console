package handlers

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"howett.net/plist"
)

func exerciseAppleFirewall(t *testing.T, h *Handler, ctx context.Context, tenant, site int, request func(string, string, string, url.Values) *httptest.ResponseRecorder, artifact func(string, *httptest.ResponseRecorder)) {
	t.Helper()
	path := fmt.Sprintf("/tenant/%d/site/%d/ios/configurations", tenant, site)
	form := func() url.Values {
		return url.Values{"editor": {"macos-firewall"}, "name": {"Mac firewall <example>"}, "identifier": {"com.example.console-firewall"}, "EnableFirewall": {"true"}, "EnableStealthMode": {"true"}, "AllowSignedApp": {"false"}, "AllowedApplications": {"com.example.service"}, "BlockedApplications": {"com.example.blocked"}}
	}
	for _, user := range []string{"scoped-viewer", "scoped-operator"} {
		if rec := request(user, "POST", path, form()); rec.Code != 403 {
			t.Fatal("role created organization firewall profile", user, rec.Code)
		}
		rec := request(user, "GET", path, nil)
		if rec.Code != 200 || strings.Contains(rec.Body.String(), "Create a Mac firewall profile") {
			t.Fatal("firewall editor visible without permission", user, rec.Code)
		}
		artifact("firewall-"+user, rec)
	}
	for _, bad := range []struct {
		key    string
		values []string
		status int
	}{{"csrf", []string{"wrong"}, 403}, {"EnableFirewall", []string{"true", "false"}, 400}, {"EnableFirewall", []string{"on"}, 400}, {"BlockAllIncoming", []string{"yes"}, 400}, {"payload_scope", []string{"User"}, 400}, {"BlockedApplications", []string{"COM.EXAMPLE.SERVICE"}, 400}} {
		v := form()
		v[bad.key] = bad.values
		if rec := request("organization-admin", "POST", path, v); rec.Code != bad.status {
			t.Fatal("invalid firewall request accepted", bad.key, rec.Code, rec.Body.String())
		}
	}
	if rec := request("organization-admin", "POST", path, form()); rec.Code != 303 {
		t.Fatal("firewall editor save failed", rec.Code, rec.Body.String())
	}
	profiles, err := h.Apple.Profiles(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range profiles {
		if p.Identifier != "com.example.console-firewall" {
			continue
		}
		found = true
		var root map[string]any
		if _, err = plist.Unmarshal(p.Payload, &root); err != nil {
			t.Fatal(err)
		}
		payload := root["PayloadContent"].([]any)[0].(map[string]any)
		if p.Scope != "System" || payload["EnableFirewall"] != true || payload["BlockAllIncoming"] != false || payload["AllowSignedApp"] != false || len(payload["Applications"].([]any)) != 2 {
			t.Fatal("form altered firewall choices", payload)
		}
	}
	if !found {
		t.Fatal("saved firewall profile missing")
	}
	rec := request("organization-admin", "GET", path, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Create a Mac firewall profile") || !strings.Contains(rec.Body.String(), "Mac firewall &lt;example&gt;") {
		t.Fatal("firewall editor or escaped saved name missing", rec.Code)
	}
	artifact("firewall-admin", rec)
}

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

func exerciseAppleGatekeeper(t *testing.T, h *Handler, ctx context.Context, tenant, site int, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	path := fmt.Sprintf("/tenant/%d/site/%d/ios/configurations", tenant, site)
	form := func() url.Values {
		return url.Values{"editor": {"macos-gatekeeper"}, "payload_scope": {"System"}, "name": {"Gatekeeper <policy>"}, "identifier": {"com.example.console-gatekeeper"}, "app_sources": {"identified"}, "finder_override": {"true"}, "malware_upload": {"false"}, "confirmed": {"yes"}}
	}
	for _, user := range []string{"scoped-viewer", "scoped-operator"} {
		if rec := request(user, "POST", path, form()); rec.Code != 403 {
			t.Fatal("unprivileged Gatekeeper creation", user, rec.Code)
		}
		if rec := request(user, "GET", path, nil); rec.Code != 200 || strings.Contains(rec.Body.String(), "Create a Mac Gatekeeper profile") {
			t.Fatal("unprivileged Gatekeeper editor exposed", user, rec.Code)
		}
	}
	for _, bad := range []struct {
		key    string
		values []string
		status int
	}{{"csrf", []string{"wrong"}, 403}, {"confirmed", []string{""}, 400}, {"payload_scope", []string{"User"}, 400}, {"app_sources", []string{"identified", "disabled"}, 400}, {"app_sources", []string{"unknown"}, 400}, {"finder_override", []string{"yes"}, 400}, {"malware_upload", []string{"false", "true"}, 400}, {"extra", []string{"unapproved"}, 400}} {
		f := form()
		f[bad.key] = bad.values
		if rec := request("organization-admin", "POST", path, f); rec.Code != bad.status {
			t.Fatal("invalid Gatekeeper form accepted", bad.key, rec.Code)
		}
	}
	if rec := request("organization-admin", "POST", path+"?app_sources=disabled", form()); rec.Code != 400 {
		t.Fatal("query changed Gatekeeper configuration", rec.Code)
	}
	for _, choice := range []string{"identified", "store", "disabled"} {
		f := form()
		f.Set("app_sources", choice)
		f.Set("identifier", "com.example.console-gatekeeper."+choice)
		if choice == "disabled" {
			f.Set("finder_override", "")
			f.Set("malware_upload", "")
		}
		if rec := request("organization-admin", "POST", path, f); rec.Code != 303 {
			t.Fatal("Gatekeeper creation failed", choice, rec.Code)
		}
	}
	profiles, err := h.Apple.Profiles(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, p := range profiles {
		if !strings.HasPrefix(p.Identifier, "com.example.console-gatekeeper.") {
			continue
		}
		found++
		choice := strings.TrimPrefix(p.Identifier, "com.example.console-gatekeeper.")
		var root map[string]any
		if _, err = plist.Unmarshal(p.Payload, &root); err != nil {
			t.Fatal(err)
		}
		items := root["PayloadContent"].([]any)
		control := items[0].(map[string]any)
		if root["PayloadScope"] != "System" || control["PayloadType"] != "com.apple.systempolicy.control" || control["EnableAssessment"] != (choice != "disabled") {
			t.Fatal("Gatekeeper choice changed")
		}
		if choice == "disabled" {
			if len(items) != 1 || control["AllowIdentifiedDevelopers"] != nil || control["EnableXProtectMalwareUpload"] != nil {
				t.Fatal("default settings were submitted as explicit policies")
			}
		} else if len(items) != 2 || control["AllowIdentifiedDevelopers"] != (choice == "identified") || control["EnableXProtectMalwareUpload"] != false || items[1].(map[string]any)["DisableOverride"] != true {
			t.Fatal("Gatekeeper policy fields or payload separation changed")
		}
	}
	if found != 3 {
		t.Fatal("Gatekeeper policy choices were not persisted")
	}
	if rec := request("organization-admin", "GET", path, nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Gatekeeper &lt;policy&gt;") || strings.Contains(rec.Body.String(), "Gatekeeper <policy>") {
		t.Fatal("Gatekeeper display text was not escaped", rec.Code)
	}
}

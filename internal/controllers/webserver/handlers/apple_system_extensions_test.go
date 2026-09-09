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

func exerciseAppleSystemExtensions(t *testing.T, h *Handler, ctx context.Context, tenant, site int, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	path := fmt.Sprintf("/tenant/%d/site/%d/ios/configurations", tenant, site)
	form := func() url.Values {
		return url.Values{"editor": {"macos-system-extensions"}, "payload_scope": {"System"}, "name": {"Extensions <policy>"}, "identifier": {"com.example.console-extensions"}, "approval_mode": {"listed"}, "team_identifier": {"ABCDE12345"}, "bundle_identifiers": {"com.example.agent.extension"}, "user_overrides": {"false"}, "driver_extensions": {"yes"}, "network_extensions": {"yes"}, "security_extensions": {"yes"}, "confirmed": {"yes"}}
	}
	for _, user := range []string{"scoped-viewer", "scoped-operator"} {
		if rec := request(user, "POST", path, form()); rec.Code != 403 {
			t.Fatal("unprivileged extension policy creation", user, rec.Code)
		}
		if rec := request(user, "GET", path, nil); rec.Code != 200 || strings.Contains(rec.Body.String(), "Create a Mac System Extensions profile") {
			t.Fatal("unprivileged extension editor exposed", user, rec.Code)
		}
	}
	for _, bad := range []struct {
		key    string
		values []string
		status int
	}{
		{"csrf", []string{"wrong"}, 403}, {"confirmed", []string{""}, 400}, {"payload_scope", []string{"User"}, 400},
		{"approval_mode", []string{"listed", "team"}, 400}, {"approval_mode", []string{"unknown"}, 400},
		{"approval_mode", []string{"team"}, 400}, {"approval_mode", []string{"block"}, 400},
		{"user_overrides", []string{"yes"}, 400}, {"driver_extensions", []string{"yes", "yes"}, 400},
		{"network_extensions", []string{"false"}, 400}, {"extra", []string{"unapproved"}, 400},
	} {
		f := form()
		f[bad.key] = bad.values
		if rec := request("organization-admin", "POST", path, f); rec.Code != bad.status {
			t.Fatal("invalid extension form accepted", bad.key, rec.Code)
		}
	}
	if rec := request("organization-admin", "POST", path+"?approval_mode=block", form()); rec.Code != 400 {
		t.Fatal("query changed policy", rec.Code)
	}
	for _, mode := range []string{"listed", "team", "block", "no-types"} {
		f := form()
		f.Set("identifier", "com.example.console-extensions."+mode)
		if mode == "team" {
			f.Set("approval_mode", "team")
			f.Del("bundle_identifiers")
			f.Set("user_overrides", "true")
		}
		if mode == "block" {
			f.Set("approval_mode", "block")
			for _, k := range []string{"team_identifier", "bundle_identifiers", "user_overrides", "driver_extensions", "network_extensions", "security_extensions"} {
				f.Del(k)
			}
		}
		if mode == "no-types" {
			for _, k := range []string{"driver_extensions", "network_extensions", "security_extensions"} {
				f.Del(k)
			}
		}
		if mode == "listed" {
			f.Set("removable_identifiers", "com.example.agent.extension")
			f.Set("protected_ui_identifiers", "com.example.agent.extension")
		}
		if rec := request("organization-admin", "POST", path, f); rec.Code != 303 {
			t.Fatal("extension policy save failed", mode, rec.Code)
		}
	}
	profiles, err := h.Apple.Profiles(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, p := range profiles {
		if !strings.HasPrefix(p.Identifier, "com.example.console-extensions.") {
			continue
		}
		found++
		mode := strings.TrimPrefix(p.Identifier, "com.example.console-extensions.")
		var root map[string]any
		if _, err = plist.Unmarshal(p.Payload, &root); err != nil {
			t.Fatal(err)
		}
		items := root["PayloadContent"].([]any)
		payload := items[0].(map[string]any)
		if len(items) != 1 || root["PayloadScope"] != "System" || payload["PayloadType"] != "com.apple.system-extension-policy" || payload["AllowUserOverrides"] != (mode == "team") {
			t.Fatal("extension policy changed")
		}
		if mode == "block" {
			if payload["AllowedTeamIdentifiers"] != nil || payload["AllowedSystemExtensions"] != nil || payload["AllowedSystemExtensionTypes"] != nil {
				t.Fatal("block policy invented approvals")
			}
			continue
		}
		types := payload["AllowedSystemExtensionTypes"].(map[string]any)["ABCDE12345"].([]any)
		want := 3
		if mode == "no-types" {
			want = 0
		}
		if len(types) != want {
			t.Fatal("allowed types changed")
		}
		if mode == "team" {
			if payload["AllowedSystemExtensions"] != nil || payload["AllowedTeamIdentifiers"].([]any)[0] != "ABCDE12345" {
				t.Fatal("team policy contains bundle approvals")
			}
		} else if payload["AllowedSystemExtensions"].(map[string]any)["ABCDE12345"].([]any)[0] != "com.example.agent.extension" {
			t.Fatal("bundle approval changed")
		}
		if mode == "listed" && (payload["RemovableSystemExtensions"] == nil || payload["NonRemovableFromUISystemExtensions"] == nil || payload["NonRemovableSystemExtensions"] != nil) {
			t.Fatal("UI removal distinction lost")
		}
	}
	if found != 4 {
		t.Fatal("extension policies missing")
	}
	if rec := request("organization-admin", "GET", path, nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Extensions &lt;policy&gt;") || strings.Contains(rec.Body.String(), "Extensions <policy>") {
		t.Fatal("policy label not escaped", rec.Code)
	}
}

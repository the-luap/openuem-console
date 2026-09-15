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

func exerciseApplePrivacy(t *testing.T, h *Handler, ctx context.Context, tenant, site int, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	path := fmt.Sprintf("/tenant/%d/site/%d/ios/configurations", tenant, site)
	form := func() url.Values {
		return url.Values{"editor": {"macos-privacy"}, "payload_scope": {"System"}, "name": {"Privacy <policy>"}, "identifier": {"com.example.console-privacy"}, "service": {"SystemPolicyAllFiles"}, "application_identifier": {"com.example.App"}, "application_type": {"bundleID"}, "code_requirement": {`identifier "com.example.App" and anchor apple generic`}, "policy": {"allow"}, "confirmed": {"yes"}}
	}
	for _, user := range []string{"scoped-viewer", "scoped-operator"} {
		if rec := request(user, "POST", path, form()); rec.Code != 403 {
			t.Fatal("unprivileged privacy creation", user, rec.Code)
		}
		if rec := request(user, "GET", path, nil); rec.Code != 200 || strings.Contains(rec.Body.String(), "Create a Mac privacy profile (PPPC/TCC)") {
			t.Fatal("unprivileged privacy editor exposed", user, rec.Code)
		}
	}
	for _, bad := range []struct {
		key    string
		values []string
		status int
	}{
		{"csrf", []string{"wrong"}, 403}, {"confirmed", []string{""}, 400}, {"payload_scope", []string{"User"}, 400},
		{"service", []string{"Camera", "Microphone"}, 400}, {"policy", []string{"deny", "allow"}, 400},
		{"static_code", []string{"false"}, 400}, {"receiver_identifier", []string{""}, 400}, {"extra", []string{"unapproved"}, 400},
	} {
		f := form()
		f[bad.key] = bad.values
		if rec := request("organization-admin", "POST", path, f); rec.Code != bad.status {
			t.Fatal("invalid privacy form accepted", bad.key, rec.Code)
		}
	}
	if rec := request("organization-admin", "POST", path+"?policy=deny", form()); rec.Code != 400 {
		t.Fatal("query changed privacy policy", rec.Code)
	}
	for _, test := range []struct{ service, policy string }{{"Camera", "allow"}, {"Microphone", "allow"}, {"ScreenCapture", "allow"}, {"ListenEvent", "allow"}, {"SystemPolicyAllFiles", "user"}, {"Unknown", "deny"}, {"AppleEvents", "allow"}} {
		f := form()
		f.Set("service", test.service)
		f.Set("policy", test.policy)
		if rec := request("organization-admin", "POST", path, f); rec.Code < 400 || rec.Code >= 500 {
			t.Fatal("invalid privacy service policy accepted", test, rec.Code)
		}
	}
	for _, test := range []struct{ service, policy string }{{"Camera", "deny"}, {"ScreenCapture", "user"}, {"AppleEvents", "allow"}, {"SystemPolicyAppData", "allow"}, {"Accessibility", "deny"}} {
		f := form()
		f.Set("identifier", "com.example.console-privacy."+test.service)
		f.Set("service", test.service)
		f.Set("policy", test.policy)
		if test.service == "AppleEvents" {
			f.Set("receiver_identifier", "com.example.Receiver")
			f.Set("receiver_type", "bundleID")
			f.Set("receiver_requirement", `identifier "com.example.Receiver" and anchor apple generic`)
			f.Set("static_code", "yes")
		}
		if test.service == "SystemPolicyAppData" {
			f.Set("application_type", "path")
			f.Set("application_identifier", "/Library/Application Support/Example/agent")
			f.Set("comment", "Reviewed <binary>")
		}
		if rec := request("organization-admin", "POST", path, f); rec.Code != 303 {
			t.Fatal("privacy policy save failed", test, rec.Code)
		}
	}
	profiles, err := h.Apple.Profiles(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, p := range profiles {
		if !strings.HasPrefix(p.Identifier, "com.example.console-privacy.") {
			continue
		}
		found++
		service := strings.TrimPrefix(p.Identifier, "com.example.console-privacy.")
		var root map[string]any
		if _, err = plist.Unmarshal(p.Payload, &root); err != nil {
			t.Fatal(err)
		}
		payload := root["PayloadContent"].([]any)[0].(map[string]any)
		services := payload["Services"].(map[string]any)
		identity := services[service].([]any)[0].(map[string]any)
		if root["PayloadScope"] != "System" || payload["PayloadType"] != "com.apple.TCC.configuration-profile-policy" || len(services) != 1 {
			t.Fatal("privacy payload structure changed")
		}
		if service == "ScreenCapture" {
			if identity["Allowed"] != nil || identity["Authorization"] != "AllowStandardUserToSetSystemService" {
				t.Fatal("user choice became a grant")
			}
		} else if identity["Allowed"] != (service == "AppleEvents" || service == "SystemPolicyAppData") || identity["Authorization"] != nil {
			t.Fatal("privacy boolean changed")
		}
		if service == "AppleEvents" {
			if identity["AEReceiverIdentifier"] != "com.example.Receiver" || identity["StaticCode"] != true {
				t.Fatal("receiver or static code option missing")
			}
		} else if identity["AEReceiverIdentifier"] != nil || identity["StaticCode"] != nil {
			t.Fatal("inactive receiver or optional static code written")
		}
		if service == "SystemPolicyAppData" && (identity["IdentifierType"] != "path" || identity["Identifier"] != "/Library/Application Support/Example/agent" || identity["Comment"] != "Reviewed <binary>") {
			t.Fatal("binary path identity changed")
		}
	}
	if found != 5 {
		t.Fatal("saved privacy policies missing")
	}
	if rec := request("organization-admin", "GET", path, nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Privacy &lt;policy&gt;") || strings.Contains(rec.Body.String(), "Privacy <policy>") {
		t.Fatal("privacy label not escaped", rec.Code)
	}
}

package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"howett.net/plist"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func exerciseApplePlatformSSO(t *testing.T, h *Handler, ctx context.Context, tenant, site int, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	path := fmt.Sprintf("/tenant/%d/site/%d/ios/configurations", tenant, site)
	form := func() url.Values {
		return url.Values{"editor": {"macos-platform-sso"}, "payload_scope": {"System"}, "name": {"Identity <provider>"}, "identifier": {"com.example.console-identity"}, "extension_identifier": {"com.example.Identity.ssoextension"}, "team_identifier": {"ABCDEFGHIJ"}, "sso_urls": {"https://login.example.test/"}, "authentication_method": {"Password"}, "shared_device_keys": {"yes"}, "create_user_at_login": {"yes"}, "registration_token": {"synthetic-route-sso-token"}, "provider_data": {`{"ProviderFlag":true}`}, "confirmed": {"yes"}}
	}
	for _, user := range []string{"scoped-viewer", "scoped-operator"} {
		if rec := request(user, "POST", path, form()); rec.Code != 403 {
			t.Fatal("scoped role created identity profile", user, rec.Code)
		}
		if rec := request(user, "GET", path, nil); rec.Code != 200 || strings.Contains(rec.Body.String(), "Create a Mac Platform SSO profile") {
			t.Fatal("unprivileged profile page exposed SSO editor", user, rec.Code)
		}
	}
	for _, bad := range []struct {
		key    string
		values []string
		status int
	}{{"csrf", []string{"wrong"}, 403}, {"confirmed", []string{""}, 400}, {"authentication_method", []string{"Password", "UserSecureEnclaveKey"}, 400}, {"provider_data", []string{`{"duplicate":1,"duplicate":2}`}, 400}, {"shared_device_keys", []string{"true"}, 400}, {"payload_scope", []string{"User"}, 400}, {"extra", []string{"unapproved"}, 400}} {
		f := form()
		f[bad.key] = bad.values
		if rec := request("organization-admin", "POST", path, f); rec.Code != bad.status {
			t.Fatal("ambiguous SSO form accepted", bad.key, rec.Code)
		}
	}
	if rec := request("organization-admin", "POST", path+"?authentication_method=SmartCard", form()); rec.Code != 400 {
		t.Fatal("query changed identity configuration", rec.Code)
	}
	if rec := request("organization-admin", "POST", path, form()); rec.Code != 303 {
		t.Fatal("authorized SSO profile creation failed", rec.Code)
	}
	profiles, err := h.Apple.Profiles(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range profiles {
		if p.Identifier != "com.example.console-identity" {
			continue
		}
		found = true
		var root map[string]any
		if _, err = plist.Unmarshal(p.Payload, &root); err != nil {
			t.Fatal(err)
		}
		payload := root["PayloadContent"].([]any)[0].(map[string]any)
		settings := payload["PlatformSSO"].(map[string]any)
		if settings["AuthenticationMethod"] != "Password" || settings["UseSharedDeviceKeys"] != true || settings["EnableCreateUserAtLogin"] != true || payload["RegistrationToken"] != "synthetic-route-sso-token" || payload["ExtensionData"].(map[string]any)["ProviderFlag"] != true {
			t.Fatal("SSO form choices changed")
		}
	}
	if !found {
		t.Fatal("saved identity profile missing")
	}
	for _, key := range []string{"shared_device_keys", "create_user_at_login"} {
		f := form()
		f.Set("unattended_setup", "yes")
		f.Del(key)
		if rec := request("organization-admin", "POST", path, f); rec.Code != 400 {
			t.Fatal("unattended editor accepted incomplete account setup", key, rec.Code)
		}
	}
	f := form()
	f.Set("identifier", "com.example.console-unattended")
	f.Set("unattended_setup", "yes")
	if rec := request("organization-admin", "POST", path, f); rec.Code != 303 {
		t.Fatal("unattended profile editor failed", rec.Code)
	}
	profiles, err = h.Apple.Profiles(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	unattended := false
	for _, p := range profiles {
		if p.Identifier != "com.example.console-unattended" {
			continue
		}
		var root map[string]any
		if _, err = plist.Unmarshal(p.Payload, &root); err != nil {
			t.Fatal(err)
		}
		settings := root["PayloadContent"].([]any)[0].(map[string]any)["PlatformSSO"].(map[string]any)
		unattended = settings["EnableRegistrationDuringSetup"] == true && settings["EnableCreateFirstUserDuringSetup"] == false
	}
	if !unattended {
		t.Fatal("unattended editor lost setup flags")
	}
	search := fmt.Sprintf("/tenant/%d/ios/ade/platform-sso/profiles", tenant)
	for _, user := range []string{"scoped-viewer", "scoped-operator"} {
		if rec := request(user, "GET", search, nil); rec.Code != 403 {
			t.Fatal("scoped role accessed ADE profile search", user, rec.Code)
		}
	}
	for _, query := range []string{"?q=a&q=b", "?unknown=value"} {
		if rec := request("organization-admin", "GET", search+query, nil); rec.Code != 400 {
			t.Fatal("ambiguous profile search accepted", rec.Code)
		}
	}
	for _, tc := range []struct {
		identifier string
		eligible   bool
	}{{"com.example.console-identity", false}, {"com.example.console-unattended", true}} {
		rec := request("organization-admin", "GET", search+"?q="+tc.identifier, nil)
		var choices struct {
			Items []struct {
				ID, Profile, Label string
				Eligible           bool
			}
			Next string
		}
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &choices) != nil || len(choices.Items) != 1 || choices.Items[0].Eligible != tc.eligible || choices.Items[0].ID == choices.Items[0].Profile || choices.Next != "" {
			t.Fatal("profile picker lost current snapshot eligibility", tc.identifier, rec.Code)
		}
		if rec.Header().Get("Cache-Control") != "no-store" || strings.Contains(rec.Body.String(), "synthetic-route-sso-token") || strings.Contains(rec.Body.String(), "ProviderFlag") {
			t.Fatal("profile picker exposed provider secrets")
		}
	}
	for _, user := range []string{"organization-admin", "scoped-viewer"} {
		rec := request(user, "GET", path, nil)
		if rec.Code != 200 || strings.Contains(rec.Body.String(), "synthetic-route-sso-token") || !strings.Contains(rec.Body.String(), "Identity &lt;provider&gt;") {
			t.Fatal("identity profile list leaked token or display markup", user, rec.Code)
		}
	}
}

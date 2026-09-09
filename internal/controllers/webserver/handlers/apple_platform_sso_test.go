package handlers

import (
	"context"
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
	for _, user := range []string{"organization-admin", "scoped-viewer"} {
		rec := request(user, "GET", path, nil)
		if rec.Code != 200 || strings.Contains(rec.Body.String(), "synthetic-route-sso-token") || !strings.Contains(rec.Body.String(), "Identity &lt;provider&gt;") {
			t.Fatal("identity profile list leaked token or display markup", user, rec.Code)
		}
	}
}

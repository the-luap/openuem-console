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

func exerciseAppleADCertificates(t *testing.T, h *Handler, ctx context.Context, tenant, site int, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	path := fmt.Sprintf("/tenant/%d/site/%d/ios/configurations", tenant, site)
	form := func() url.Values {
		return url.Values{"editor": {"apple-ad-certificate"}, "payload_scope": {"System"}, "name": {"Directory <identity>"}, "identifier": {"com.example.console-ad"}, "certificate_server": {"CA.example.test."}, "certificate_template": {"Machine"}, "confirmed": {"yes"}}
	}
	for _, user := range []string{"scoped-viewer", "scoped-operator"} {
		if rec := request(user, "POST", path, form()); rec.Code != 403 {
			t.Fatal("unprivileged AD certificate creation", rec.Code)
		}
		if rec := request(user, "GET", path, nil); rec.Code != 200 || strings.Contains(rec.Body.String(), "Create an Active Directory certificate profile") {
			t.Fatal("unprivileged AD editor exposed", rec.Code)
		}
	}
	for _, bad := range []struct {
		key    string
		values []string
		status int
	}{
		{"csrf", []string{"wrong"}, 403}, {"confirmed", []string{""}, 400}, {"payload_scope", []string{"invalid"}, 400}, {"certificate_server", []string{"ca"}, 400}, {"certificate_server", []string{"ca.example.test", "other.example.test"}, 400}, {"certificate_template", []string{""}, 400}, {"certificate_template", []string{"synthetic-directory-private\nvalue"}, 400},
		{"key_size", []string{"2048.0"}, 400}, {"key_size", []string{"02048"}, 400}, {"key_size", []string{"8193"}, 400}, {"renewal_notice", []string{"-1"}, 400}, {"renewal_notice", []string{"3651"}, 400}, {"acquisition", []string{"LDAP"}, 400}, {"key_extractable", []string{"no"}, 400}, {"auto_renewal", []string{"true", "false"}, 400}, {"prompt_for_credentials", []string{"true"}, 400}, {"extra", []string{"value"}, 400},
	} {
		f := form()
		f[bad.key] = bad.values
		if rec := request("organization-admin", "POST", path, f); rec.Code != bad.status || strings.Contains(rec.Body.String(), "synthetic-directory-private") {
			t.Fatal("invalid AD form accepted or payload echoed", bad.key, rec.Code)
		}
	}
	if rec := request("organization-admin", "POST", path+"?auto_renewal=true", form()); rec.Code != 400 {
		t.Fatal("query changed AD renewal policy", rec.Code)
	}
	f := form()
	f.Set("payload_scope", "User")
	f.Set("auto_renewal", "true")
	if rec := request("organization-admin", "POST", path, f); rec.Code != 400 {
		t.Fatal("User AD automatic renewal accepted", rec.Code)
	}
	for _, mode := range []string{"minimal", "advanced", "user"} {
		f := form()
		f.Set("identifier", "com.example.console-ad."+mode)
		if mode != "minimal" {
			f.Set("description", "synthetic-directory-private-description")
			f.Set("certificate_authority", "CN=Example CA,CN=Configuration,DC=example,DC=test")
			f.Set("acquisition", "HTTP")
			f.Set("renewal_notice", "0")
			f.Set("key_size", "3072")
			f.Set("key_extractable", "false")
			f.Set("all_apps_access", "false")
			f.Set("auto_renewal", "true")
		}
		if mode == "user" {
			f.Set("payload_scope", "User")
			f.Set("certificate_template", "User")
			f.Set("auto_renewal", "false")
		}
		if rec := request("organization-admin", "POST", path, f); rec.Code != 303 {
			t.Fatal("AD certificate creation failed", mode, rec.Code)
		}
	}
	profiles, err := h.Apple.Profiles(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, p := range profiles {
		if !strings.HasPrefix(p.Identifier, "com.example.console-ad.") {
			continue
		}
		found++
		mode := strings.TrimPrefix(p.Identifier, "com.example.console-ad.")
		var root map[string]any
		if _, err = plist.Unmarshal(p.Payload, &root); err != nil {
			t.Fatal(err)
		}
		payload := root["PayloadContent"].([]any)[0].(map[string]any)
		if payload["PayloadType"] != "com.apple.ADCertificate.managed" || payload["CertServer"] != "CA.example.test." || (p.Scope == "User") != (mode == "user") {
			t.Fatal("AD server spelling, payload type or scope changed")
		}
		if _, exists := payload["PromptForCredentials"]; exists {
			t.Fatal("interactive AD credentials emitted")
		}
		if mode == "minimal" {
			for _, key := range []string{"CertificateAuthority", "CertificateAcquisitionMechanism", "CertificateRenewalTimeInterval", "Keysize", "AllowAllAppsAccess", "KeyIsExtractable", "EnableAutoRenewal"} {
				if _, exists := payload[key]; exists {
					t.Fatal("AD optional defaults emitted", key)
				}
			}
		} else if payload["CertificateRenewalTimeInterval"] != uint64(0) || payload["Keysize"] != uint64(3072) || payload["AllowAllAppsAccess"] != false || payload["KeyIsExtractable"] != false || payload["EnableAutoRenewal"] != (mode == "advanced") {
			t.Fatal("AD optional values lost zero/false or integer types")
		}
	}
	if found != 3 {
		t.Fatal("AD variants missing or invalid form changed catalog", found)
	}
	if rec := request("organization-admin", "GET", path, nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Directory &lt;identity&gt;") || strings.Contains(rec.Body.String(), "synthetic-directory-private-description") {
		t.Fatal("AD catalog escaped incorrectly or exposed payload details", rec.Code)
	}
}

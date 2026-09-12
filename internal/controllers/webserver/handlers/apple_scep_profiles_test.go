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

func exerciseAppleSCEPProfiles(t *testing.T, h *Handler, ctx context.Context, tenant, site int, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	path := fmt.Sprintf("/tenant/%d/site/%d/ios/configurations", tenant, site)
	form := func() url.Values {
		return url.Values{"editor": {"apple-scep"}, "payload_scope": {"System"}, "name": {"SCEP <identity>"}, "identifier": {"com.example.console-scep"}, "scep_url": {"https://ca.example.test/scep"}, "key_size": {"2048"}, "confirmed": {"yes"}}
	}
	for _, user := range []string{"scoped-viewer", "scoped-operator"} {
		if rec := request(user, "POST", path, form()); rec.Code != 403 {
			t.Fatal("unprivileged SCEP creation", user, rec.Code)
		}
		if rec := request(user, "GET", path, nil); rec.Code != 200 || strings.Contains(rec.Body.String(), "Create a SCEP certificate profile") {
			t.Fatal("unprivileged SCEP editor exposed", user, rec.Code)
		}
	}
	for _, bad := range []struct {
		key    string
		values []string
		status int
	}{{"csrf", []string{"wrong"}, 403}, {"confirmed", []string{""}, 400}, {"payload_scope", []string{"invalid"}, 400}, {"key_size", []string{"2048", "4096"}, 400}, {"key_size", []string{"2048.0"}, 400}, {"key_extractable", []string{"no"}, 400}, {"all_apps_access", []string{"true", "false"}, 400}, {"retry_delay", []string{"-1"}, 400}, {"extra", []string{"unapproved"}, 400}} {
		f := form()
		f[bad.key] = bad.values
		if rec := request("organization-admin", "POST", path, f); rec.Code != bad.status {
			t.Fatal("invalid SCEP form accepted", bad.key, rec.Code)
		}
	}
	if rec := request("organization-admin", "POST", path+"?key_size=1024", form()); rec.Code != 400 {
		t.Fatal("query changed SCEP settings", rec.Code)
	}
	f := form()
	f.Set("scep_url", "http://ca.example.test/scep")
	f.Set("challenge", "synthetic-scep-console-secret")
	if rec := request("organization-admin", "POST", path, f); rec.Code != 400 || strings.Contains(rec.Body.String(), "synthetic-scep-console-secret") {
		t.Fatal("unpinned HTTP accepted or challenge echoed", rec.Code)
	}
	for _, mode := range []string{"minimal", "user", "http"} {
		f := form()
		f.Set("identifier", "com.example.console-scep."+mode)
		if mode != "minimal" {
			f.Set("subject", "O=Example\nCN=Client=42")
			f.Set("san_dns", "One.example.test\nTwo.example.test")
			f.Set("san_email", "User@example.test")
			f.Set("challenge", "synthetic-scep-console-secret")
			f.Set("key_usage", "5")
			f.Set("retries", "0")
			f.Set("retry_delay", "0")
			f.Set("key_extractable", "false")
			f.Set("all_apps_access", "false")
		}
		if mode == "user" {
			f.Set("payload_scope", "User")
		}
		if mode == "http" {
			f.Set("scep_url", "http://ca.example.test/scep")
			f.Set("fingerprint", strings.Repeat("AB", 20))
		}
		if rec := request("organization-admin", "POST", path, f); rec.Code != 303 {
			t.Fatal("SCEP profile creation failed", mode, rec.Code)
		}
	}
	profiles, err := h.Apple.Profiles(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, p := range profiles {
		if !strings.HasPrefix(p.Identifier, "com.example.console-scep.") {
			continue
		}
		found++
		mode := strings.TrimPrefix(p.Identifier, "com.example.console-scep.")
		var root map[string]any
		if _, err = plist.Unmarshal(p.Payload, &root); err != nil {
			t.Fatal(err)
		}
		payload := root["PayloadContent"].([]any)[0].(map[string]any)
		content := payload["PayloadContent"].(map[string]any)
		if payload["PayloadType"] != "com.apple.security.scep" || content["Key Type"] != "RSA" || content["Keysize"] != uint64(2048) || (root["PayloadScope"] == "User") != (mode == "user") {
			t.Fatal("SCEP key or scope changed")
		}
		if mode == "minimal" {
			if len(content) != 3 {
				t.Fatal("optional SCEP defaults persisted")
			}
			continue
		}
		if content["Challenge"] != "synthetic-scep-console-secret" || content["Key Usage"] != uint64(5) || content["Retries"] != uint64(0) || content["RetryDelay"] != uint64(0) || content["KeyIsExtractable"] != false || content["AllowAllAppsAccess"] != false {
			t.Fatal("SCEP values lost zero or false")
		}
		if content["Subject"].([]any)[1].([]any)[0].([]any)[1] != "Client=42" || len(content["SubjectAltName"].(map[string]any)["dNSName"].([]any)) != 2 {
			t.Fatal("subject or alternative-name structure changed")
		}
		if mode == "http" && len(content["CAFingerprint"].([]byte)) != 20 {
			t.Fatal("HTTP fingerprint missing")
		}
	}
	if found != 3 {
		t.Fatal("SCEP policy variants missing")
	}
	if rec := request("organization-admin", "GET", path, nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "SCEP &lt;identity&gt;") || strings.Contains(rec.Body.String(), "synthetic-scep-console-secret") {
		t.Fatal("SCEP display escaped incorrectly or exposed challenge", rec.Code)
	}
}

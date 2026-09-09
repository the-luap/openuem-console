package handlers

import (
	"bytes"
	"context"
	"fmt"
	"mime/multipart"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"howett.net/plist"
)

func exerciseAppleACMEProfiles(t *testing.T, h *Handler, ctx context.Context, tenant, site int, request func(string, string, string, url.Values) *httptest.ResponseRecorder) {
	t.Helper()
	path := fmt.Sprintf("/tenant/%d/site/%d/ios/configurations", tenant, site)
	form := func() url.Values {
		return url.Values{"editor": {"apple-acme"}, "payload_scope": {"System"}, "name": {"ACME <identity>"}, "identifier": {"com.example.console-acme"}, "directory_url": {"https://ca.example.test/acme/directory"}, "client_identifier": {"synthetic-acme-console-secret"}, "key_type": {"ECSECPrimeRandom"}, "key_size": {"256"}, "hardware_bound": {"false"}, "subject": {""}, "confirmed": {"yes"}}
	}
	for _, user := range []string{"scoped-viewer", "scoped-operator"} {
		if rec := request(user, "POST", path, form()); rec.Code != 403 {
			t.Fatal("unprivileged ACME creation", user, rec.Code)
		}
		if rec := request(user, "GET", path, nil); rec.Code != 200 || strings.Contains(rec.Body.String(), "Create an ACME certificate profile") {
			t.Fatal("unprivileged ACME editor exposed", user, rec.Code)
		}
	}
	for _, bad := range []struct {
		key    string
		values []string
		status int
	}{
		{"csrf", []string{"wrong"}, 403}, {"confirmed", []string{""}, 400}, {"payload_scope", []string{"invalid"}, 400},
		{"key_size", []string{"256", "384"}, 400}, {"key_size", []string{"256.0"}, 400}, {"key_size", []string{"0256"}, 400},
		{"key_type", []string{"RSA"}, 400}, {"hardware_bound", []string{""}, 400}, {"hardware_bound", []string{"no"}, 400},
		{"attest", []string{"true"}, 400}, {"key_extractable", []string{"no"}, 400}, {"all_apps_access", []string{"true", "false"}, 400},
		{"directory_url", []string{"http://ca.example.test"}, 400}, {"directory_url", []string{"https://secret@ca.example.test"}, 400},
		{"san_dns", []string{"first.example.test\nsecond.example.test"}, 400}, {"extended_key_usage", []string{"client-auth"}, 400},
		{"usage_flags", []string{"2"}, 400}, {"extra", []string{"unapproved"}, 400},
	} {
		f := form()
		f[bad.key] = bad.values
		if rec := request("organization-admin", "POST", path, f); rec.Code != bad.status || strings.Contains(rec.Body.String(), "synthetic-acme-console-secret") {
			t.Fatal("invalid ACME form accepted or client echoed", bad.key, rec.Code)
		}
	}
	if rec := request("organization-admin", "POST", path+"?hardware_bound=true", form()); rec.Code != 400 {
		t.Fatal("query changed ACME settings", rec.Code)
	}
	for _, mode := range []string{"minimal", "user", "hardware", "rsa"} {
		f := form()
		f.Set("identifier", "com.example.console-acme."+mode)
		if mode == "user" {
			f.Set("payload_scope", "User")
			f.Set("subject", "O=Example\nCN=Client=42")
			f.Set("san_dns", "One.example.test")
			f.Set("extended_key_usage", "1.3.6.1.5.5.7.3.2")
			f.Set("usage_flags", "0")
			f.Set("attest", "false")
			f.Set("key_extractable", "false")
			f.Set("all_apps_access", "false")
		}
		if mode == "hardware" {
			f.Set("hardware_bound", "true")
			f.Set("attest", "true")
			f.Set("key_size", "384")
		}
		if mode == "rsa" {
			f.Set("key_type", "RSA")
			f.Set("key_size", "2048")
		}
		if rec := request("organization-admin", "POST", path, f); rec.Code != 303 {
			t.Fatal("ACME creation failed", mode, rec.Code)
		}
	}
	profiles, err := h.Apple.Profiles(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, p := range profiles {
		if !strings.HasPrefix(p.Identifier, "com.example.console-acme.") {
			continue
		}
		found++
		mode := strings.TrimPrefix(p.Identifier, "com.example.console-acme.")
		var root map[string]any
		if _, err = plist.Unmarshal(p.Payload, &root); err != nil {
			t.Fatal(err)
		}
		payload := root["PayloadContent"].([]any)[0].(map[string]any)
		if payload["PayloadType"] != "com.apple.security.acme" || payload["ClientIdentifier"] != "synthetic-acme-console-secret" || (root["PayloadScope"] == "User") != (mode == "user") {
			t.Fatal("ACME identity or scope changed")
		}
		if mode == "minimal" {
			if len(payload["Subject"].([]any)) != 0 || payload["HardwareBound"] != false {
				t.Fatal("required empty/false ACME values lost")
			}
			for _, key := range []string{"Attest", "UsageFlags", "KeyIsExtractable", "AllowAllAppsAccess", "SubjectAltName", "ExtendedKeyUsage"} {
				if _, exists := payload[key]; exists {
					t.Fatal("optional default persisted", key)
				}
			}
		}
		if mode == "user" && (payload["UsageFlags"] != uint64(0) || payload["Attest"] != false || payload["KeyIsExtractable"] != false || payload["AllowAllAppsAccess"] != false || payload["SubjectAltName"].(map[string]any)["dNSName"] != "One.example.test") {
			t.Fatal("ACME explicit false/zero or scalar SAN lost")
		}
		if mode == "hardware" && (payload["HardwareBound"] != true || payload["Attest"] != true || payload["KeySize"] != uint64(384)) {
			t.Fatal("hardware ACME values changed")
		}
		if mode == "rsa" && (payload["KeyType"] != "RSA" || payload["KeySize"] != uint64(2048)) {
			t.Fatal("RSA ACME values changed")
		}
	}
	if found != 4 {
		t.Fatal("ACME policy variants missing")
	}
	if rec := request("organization-admin", "GET", path, nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "ACME &lt;identity&gt;") || strings.Contains(rec.Body.String(), "synthetic-acme-console-secret") {
		t.Fatal("ACME display privacy failure", rec.Code)
	}
}

func exerciseAppleACMEHistory(t *testing.T, h *Handler, ctx context.Context, tenant, site int, request func(string, string, string, url.Values) *httptest.ResponseRecorder, requestBody func(string, string, string, string, []byte) *httptest.ResponseRecorder) {
	t.Helper()
	base := fmt.Sprintf("/tenant/%d/site/%d/ios/configurations/acme-history", tenant, site)
	id := uuid.NewString()
	if _, err := h.Model.DB.ExecContext(ctx, `INSERT INTO mdm_apple_acme_legacy_profiles(id,tenant_id,device_id,profile_id,revision,identifier,payload_scope,state) VALUES($1,$2,$3,$4,7,'com.example.console-acme-history','System','unresolved')`, id, tenant, uuid.NewString(), uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	data, err := apple.BuildProfile("Historical archive", "com.example.console-acme-history", "wifi", map[string]any{"SSID_STR": "Example", "EncryptionType": "WPA", "Password": "synthetic-history-archive-secret"})
	if err != nil {
		t.Fatal(err)
	}
	form := func() url.Values {
		return url.Values{"csrf": {"console-test-token"}, "confirmed": {"yes"}, "expected_revision": {"7"}, "reason": {"Original <reviewed> archive from the configuration repository"}}
	}
	submit := func(user, target string, f url.Values, files map[string][][]byte) *httptest.ResponseRecorder {
		var body bytes.Buffer
		w := multipart.NewWriter(&body)
		for k, values := range f {
			for _, v := range values {
				if err := w.WriteField(k, v); err != nil {
					t.Fatal(err)
				}
			}
		}
		for k, values := range files {
			for _, v := range values {
				p, err := w.CreateFormFile(k, "original.mobileconfig")
				if err != nil {
					t.Fatal(err)
				}
				if _, err = p.Write(v); err != nil {
					t.Fatal(err)
				}
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return requestBody(user, "POST", target, w.FormDataContentType(), body.Bytes())
	}
	action := base + "/" + id + "/review"
	files := map[string][][]byte{"profile": {data}}
	for _, user := range []string{"scoped-viewer", "scoped-operator"} {
		if rec := request(user, "GET", base, nil); rec.Code != 403 {
			t.Fatal("unprivileged ACME history read", user, rec.Code)
		}
		if rec := submit(user, action, form(), files); rec.Code != 403 {
			t.Fatal("unprivileged ACME archive review", user, rec.Code)
		}
	}
	if rec := request("organization-admin", "GET", base, nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Record historical archive review") || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("historical review unavailable or cacheable", rec.Code)
	}
	for _, bad := range []struct {
		key    string
		values []string
		status int
	}{{"csrf", []string{"wrong"}, 403}, {"confirmed", []string{""}, 400}, {"reason", []string{""}, 400}, {"reason", []string{"one", "two"}, 400}, {"reason", []string{strings.Repeat("x", 1001)}, 400}, {"expected_revision", []string{"07"}, 400}, {"expected_revision", []string{"6"}, 409}, {"extra", []string{"unapproved"}, 400}} {
		f := form()
		f[bad.key] = bad.values
		if rec := submit("organization-admin", action, f, files); rec.Code != bad.status {
			t.Fatal("invalid archive review accepted", bad.key, rec.Code)
		}
	}
	for _, bad := range []map[string][][]byte{{}, {"profile": {data, data}}, {"profile": {data}, "extra": {data}}, {"profile": {[]byte("synthetic-history-archive-secret")}}} {
		if rec := submit("organization-admin", action, form(), bad); rec.Code != 400 || strings.Contains(rec.Body.String(), "synthetic-history-archive-secret") {
			t.Fatal("invalid archive accepted or echoed", rec.Code)
		}
	}
	if rec := submit("organization-admin", action+"?expected_revision=7", form(), files); rec.Code != 400 {
		t.Fatal("query changed archive review", rec.Code)
	}
	if rec := submit("organization-admin", base+"/"+uuid.NewString()+"/review", form(), files); rec.Code != 404 {
		t.Fatal("missing archive not scoped", rec.Code)
	}
	if rec := submit("organization-admin", action, form(), files); rec.Code != 303 {
		t.Fatal("authorized archive review failed", rec.Code, rec.Body.String())
	}
	if rec := submit("organization-admin", action, form(), files); rec.Code != 409 {
		t.Fatal("repeated review overwrote evidence", rec.Code)
	}
	rec := request("organization-admin", "GET", base+"?state=reviewed", nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Original &lt;reviewed&gt; archive") || strings.Contains(rec.Body.String(), "synthetic-history-archive-secret") || strings.Contains(rec.Body.String(), `name="profile"`) {
		t.Fatal("review receipt unsafe or missing", rec.Code)
	}
	var encrypted []byte
	if err := h.Model.DB.QueryRowContext(ctx, `SELECT reviewed_payload FROM mdm_apple_acme_legacy_profiles WHERE id=$1`, id).Scan(&encrypted); err != nil || len(encrypted) == 0 || bytes.Contains(encrypted, []byte("synthetic-history-archive-secret")) {
		t.Fatal("reviewed archive is not protected", err)
	}
}

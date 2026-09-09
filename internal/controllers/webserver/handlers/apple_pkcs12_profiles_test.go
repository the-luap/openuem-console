package handlers

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"mime/multipart"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"howett.net/plist"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func exerciseApplePKCS12(t *testing.T, h *Handler, ctx context.Context, tenant, site int, request func(string, string, string, string, []byte) *httptest.ResponseRecorder) {
	t.Helper()
	path := fmt.Sprintf("/tenant/%d/site/%d/ios/configurations", tenant, site)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic public certificate"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := pkcs12.Modern2023.Encode(key, parsed, nil, " synthetic-pkcs12-console-secret ")
	if err != nil {
		t.Fatal(err)
	}
	form := func() url.Values {
		return url.Values{"csrf": {"console-test-token"}, "confirmed": {"yes"}, "editor": {"apple-pkcs12"}, "payload_scope": {"System"}, "name": {"Identity <private>"}, "identifier": {"com.example.console-pkcs12"}, "password": {" synthetic-pkcs12-console-secret "}, "key_extractable": {""}, "all_apps_access": {""}}
	}
	submit := func(user, target string, fields url.Values, files map[string][][]byte) *httptest.ResponseRecorder {
		var body bytes.Buffer
		w := multipart.NewWriter(&body)
		for field, values := range fields {
			for _, value := range values {
				if err := w.WriteField(field, value); err != nil {
					t.Fatal(err)
				}
			}
		}
		for name, items := range files {
			for _, data := range items {
				part, err := w.CreateFormFile(name, "identity.p12")
				if err != nil {
					t.Fatal(err)
				}
				if _, err = part.Write(data); err != nil {
					t.Fatal(err)
				}
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return request(user, "POST", target, w.FormDataContentType(), body.Bytes())
	}
	files := map[string][][]byte{"identity": {encoded}}
	for _, user := range []string{"scoped-viewer", "scoped-operator"} {
		if rec := submit(user, path, form(), files); rec.Code != 403 {
			t.Fatal("unprivileged certificate import", user, rec.Code)
		}
	}
	for _, bad := range []struct {
		key    string
		values []string
		status int
	}{{"csrf", []string{"wrong"}, 403}, {"confirmed", []string{""}, 400}, {"payload_scope", []string{"System", "User"}, 400}, {"payload_scope", []string{"invalid"}, 400}, {"extra", []string{"unapproved"}, 400}, {"password", []string{"one", "two"}, 400}, {"key_extractable", []string{"no"}, 400}, {"all_apps_access", []string{"0"}, 400}} {
		f := form()
		f[bad.key] = bad.values
		if rec := submit("organization-admin", path, f, files); rec.Code != bad.status {
			t.Fatal("invalid certificate form accepted", bad.key, rec.Code)
		}
	}
	for _, bad := range []map[string][][]byte{{}, {"identity": {encoded, encoded}}, {"identity": {encoded}, "private_key": {[]byte("private-key-sentinel")}}, {"identity": {[]byte("private-key-sentinel")}}} {
		if rec := submit("organization-admin", path, form(), bad); rec.Code != 400 || strings.Contains(rec.Body.String(), "private-key-sentinel") {
			t.Fatal("invalid certificate import accepted or echoed content", rec.Code)
		}
	}
	if rec := submit("organization-admin", path+"?payload_scope=User", form(), files); rec.Code != 400 {
		t.Fatal("query changed certificate scope", rec.Code)
	}
	for _, scope := range []string{"System", "User"} {
		f := form()
		f.Set("payload_scope", scope)
		f.Set("identifier", "com.example.console-pkcs12."+scope)
		if scope == "User" {
			f.Set("key_extractable", "false")
			f.Set("all_apps_access", "false")
		}
		if rec := submit("organization-admin", path, f, files); rec.Code != 303 {
			t.Fatal("certificate import failed", scope, rec.Code)
		}
	}
	profiles, err := h.Apple.Profiles(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, p := range profiles {
		if !strings.HasPrefix(p.Identifier, "com.example.console-pkcs12.") {
			continue
		}
		found++
		var root map[string]any
		if _, err = plist.Unmarshal(p.Payload, &root); err != nil {
			t.Fatal(err)
		}
		items := root["PayloadContent"].([]any)
		payload := items[0].(map[string]any)
		if len(items) != 1 || root["PayloadScope"] != strings.TrimPrefix(p.Identifier, "com.example.console-pkcs12.") || payload["PayloadType"] != "com.apple.security.pkcs12" || !bytes.Equal(payload["PayloadContent"].([]byte), encoded) || payload["Password"] != " synthetic-pkcs12-console-secret " {
			t.Fatal("certificate or scope changed during import")
		}
		if p.Scope == "User" {
			if payload["KeyIsExtractable"] != false || payload["AllowAllAppsAccess"] != false {
				t.Fatal("explicit identity options lost")
			}
		} else {
			for _, key := range []string{"KeyIsExtractable", "AllowAllAppsAccess"} {
				if _, exists := payload[key]; exists {
					t.Fatal("omitted identity option changed")
				}
			}
		}
	}
	if found != 2 {
		t.Fatal("certificate scopes missing from catalog")
	}
	for _, user := range []string{"organization-admin", "scoped-viewer", "scoped-operator"} {
		rec := request(user, "GET", path, "", nil)
		if rec.Code != 200 || strings.Contains(rec.Body.String(), "synthetic-pkcs12-console-secret") {
			t.Fatal("identity page or secret privacy", user, rec.Code)
		}
		if user != "organization-admin" && strings.Contains(rec.Body.String(), "Create a PKCS12 identity profile") {
			t.Fatal("identity editor shown without management role")
		}
		if user == "organization-admin" && !strings.Contains(rec.Body.String(), "Identity &lt;private&gt;") {
			t.Fatal("identity name not escaped")
		}
	}
}

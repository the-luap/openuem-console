package handlers

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"mime/multipart"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"howett.net/plist"
)

func exerciseApplePublicCertificates(t *testing.T, h *Handler, ctx context.Context, tenant, site int, request func(string, string, string, string, []byte) *httptest.ResponseRecorder) {
	t.Helper()
	path := fmt.Sprintf("/tenant/%d/site/%d/ios/configurations", tenant, site)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic public certificate"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	form := func() url.Values {
		return url.Values{"csrf": {"console-test-token"}, "confirmed": {"yes"}, "editor": {"apple-certificates"}, "payload_scope": {"System"}, "name": {"Certificates <trusted>"}, "identifier": {"com.example.console-certificates"}}
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
				part, err := w.CreateFormFile(name, "certificate.pem")
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
	files := map[string][][]byte{"certificate": {encoded}}
	for _, user := range []string{"scoped-viewer", "scoped-operator"} {
		if rec := submit(user, path, form(), files); rec.Code != 403 {
			t.Fatal("unprivileged certificate import", user, rec.Code)
		}
	}
	for _, bad := range []struct {
		key    string
		values []string
		status int
	}{{"csrf", []string{"wrong"}, 403}, {"confirmed", []string{""}, 400}, {"payload_scope", []string{"System", "User"}, 400}, {"payload_scope", []string{"invalid"}, 400}, {"extra", []string{"unapproved"}, 400}} {
		f := form()
		f[bad.key] = bad.values
		if rec := submit("organization-admin", path, f, files); rec.Code != bad.status {
			t.Fatal("invalid certificate form accepted", bad.key, rec.Code)
		}
	}
	for _, bad := range []map[string][][]byte{{}, {"certificate": {encoded, encoded}}, {"certificate": {encoded}, "private_key": {[]byte("private-key-sentinel")}}, {"certificate": {[]byte("private-key-sentinel")}}} {
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
		f.Set("identifier", "com.example.console-certificates."+scope)
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
		if !strings.HasPrefix(p.Identifier, "com.example.console-certificates.") {
			continue
		}
		found++
		var root map[string]any
		if _, err = plist.Unmarshal(p.Payload, &root); err != nil {
			t.Fatal(err)
		}
		items := root["PayloadContent"].([]any)
		payload := items[0].(map[string]any)
		if len(items) != 1 || root["PayloadScope"] != strings.TrimPrefix(p.Identifier, "com.example.console-certificates.") || payload["PayloadType"] != "com.apple.security.pkcs1" || !bytes.Equal(payload["PayloadContent"].([]byte), der) {
			t.Fatal("certificate or scope changed during import")
		}
	}
	if found != 2 {
		t.Fatal("certificate scopes missing from catalog")
	}
}

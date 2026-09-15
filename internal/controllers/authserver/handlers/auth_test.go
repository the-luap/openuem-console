package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/ocsp"
)

func TestCertificateLoginRejectsHeaderOnlyCredentials(t *testing.T) {
	h := &Handler{}
	for _, scheme := range []string{"http", "https"} {
		req := httptest.NewRequest("GET", scheme+"://console.test/auth", nil)
		req.Header.Set("Client-Cert", ":cHVibGljLWNlcnRpZmljYXRl:")
		req.Header.Set("X-Forwarded-For", "127.0.0.1")
		c := echo.New().NewContext(req, httptest.NewRecorder())
		err := h.Auth(c)
		httpErr, ok := err.(*echo.HTTPError)
		if !ok || httpErr.Code != http.StatusUnauthorized {
			t.Fatalf("untrusted certificate reached login: %v", err)
		}
	}
}

func TestIssuerRejectsMissingCredentialsAndRootCertificates(t *testing.T) {
	if _, err := getIssuerFromCert(nil, nil); err == nil {
		t.Fatal("missing certificate accepted")
	}
}

func TestRevocationBindsCertificateAndFreshness(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := getIssuerFromCert(issuer, issuer); err == nil {
		t.Fatal("root certificate accepted as administrator")
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(2)}
	for _, tt := range []struct {
		name       string
		status     int
		serial     int64
		this, next time.Time
		valid      bool
	}{
		{"good", ocsp.Good, 2, now.Add(-time.Minute), now.Add(time.Hour), true},
		{"different certificate", ocsp.Good, 3, now.Add(-time.Minute), now.Add(time.Hour), false},
		{"revoked", ocsp.Revoked, 2, now.Add(-time.Minute), now.Add(time.Hour), false},
		{"unknown", ocsp.Unknown, 2, now.Add(-time.Minute), now.Add(time.Hour), false},
		{"expired", ocsp.Good, 2, now.Add(-time.Hour), now.Add(-time.Second), false},
		{"future", ocsp.Good, 2, now.Add(time.Hour), now.Add(2 * time.Hour), false},
		{"old without expiry", ocsp.Good, 2, now.Add(-48 * time.Hour), time.Time{}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			data, err := ocsp.CreateResponse(issuer, issuer, ocsp.Response{SerialNumber: big.NewInt(tt.serial), Status: tt.status, ThisUpdate: tt.this, NextUpdate: tt.next}, key)
			if err != nil {
				t.Fatal(err)
			}
			err = verifyRevocationResponse(data, cert, issuer, now)
			if (err == nil) != tt.valid {
				t.Fatalf("unexpected revocation verification: %v", err)
			}
		})
	}
}

func TestConsoleRedirectUsesConfiguredOrigin(t *testing.T) {
	h := &Handler{ServerName: "backend.test", ConsolePort: "1323", PublicOrigin: "https://uem.example.test"}
	if h.consoleOrigin() != "https://uem.example.test" {
		t.Fatal("public origin ignored")
	}
	h.PublicOrigin = ""
	if h.consoleOrigin() != "https://backend.test:1323" {
		t.Fatal("direct origin changed")
	}
}

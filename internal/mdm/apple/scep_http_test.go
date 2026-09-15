package apple

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"github.com/open-uem/openuem-console/internal/security/clientidentity"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestSCEPHTTPBoundariesAndGETRetry(t *testing.T) {
	s, server, invite, token := portalFixture(t)
	profile, err := s.EnrollmentProfile(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	content := testSCEPProfile(t, profile)
	a, err := s.scepEnrollmentAuthority(context.Background(), invite.DeviceID, false)
	if err != nil {
		t.Fatal(err)
	}
	f, csr := testSCEPDeviceRequest(t, invite.DeviceID, content["Challenge"].(string), a.ca, a.ra)
	base := "/mdm/apple/" + invite.DeviceID + "/scep"
	wire := testSCEPWire(t, f, csr, scepWireOptions{})
	client := server.Client()
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		address := server.URL + base + "?operation=PKIOperation"
		var body io.Reader = bytes.NewReader(wire)
		if method == http.MethodGet {
			address += "&message=" + url.QueryEscape(base64.StdEncoding.EncodeToString(wire))
			body = nil
		}
		r, _ := http.NewRequest(method, address, body)
		r.Header.Set("Content-Type", "application/x-pki-message")
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != 200 || response.Header.Get("Content-Type") != "application/x-pki-message" || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal(method, response.StatusCode, err)
		}
		testSCEPResult(t, f, data, true)
	}
	for _, tc := range []struct {
		name, method, path, media string
		body                      []byte
		secure                    bool
		status                    int
	}{
		{"HTTPS required", "GET", base + "?operation=GetCACaps", "", nil, false, 400},
		{"unsupported method", "PUT", base + "?operation=PKIOperation", "", nil, true, 405},
		{"duplicate operation", "GET", base + "?operation=GetCACaps&operation=GetCACert", "", nil, true, 400},
		{"unknown query", "GET", base + "?operation=GetCACaps&extra=1", "", nil, true, 400},
		{"malformed query", "GET", base + "?operation=GetCACaps&message=%xx", "", nil, true, 400},
		{"unsupported operation", "GET", base + "?operation=GetCRL", "", nil, true, 400},
		{"discovery POST", "POST", base + "?operation=GetCACert", "", nil, true, 400},
		{"POST query message", "POST", base + "?operation=PKIOperation&message=wrong", "application/x-pki-message", wire, true, 400},
		{"GET invalid base64", "GET", base + "?operation=PKIOperation&message=bad", "", nil, true, 400},
		{"POST missing media", "POST", base + "?operation=PKIOperation", "", wire, true, 415},
		{"POST wrong media", "POST", base + "?operation=PKIOperation", "text/plain", wire, true, 415},
		{"POST too large", "POST", base + "?operation=PKIOperation", "application/x-pki-message", make([]byte, maxSCEPMessage+1), true, 413},
		{"invalid CMS", "POST", base + "?operation=PKIOperation", "application/x-pki-message", []byte("invalid"), true, 400},
		{"encoded route", "GET", strings.Replace(base, "scep", "%73cep", 1) + "?operation=GetCACaps", "", nil, true, 400},
		{"noncanonical ID", "GET", strings.Replace(base, invite.DeviceID, strings.ToUpper(invite.DeviceID), 1) + "?operation=GetCACaps", "", nil, true, 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "https://mdm.example.test"+tc.path, bytes.NewReader(tc.body))
			if tc.secure {
				r.TLS = &tls.ConnectionState{HandshakeComplete: true}
			} else {
				r.TLS = nil
			}
			r.Header.Set("Content-Type", tc.media)
			w := httptest.NewRecorder()
			s.ProtocolHandler(nil).ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
}

func TestSCEPHTTPAdmissionLimits(t *testing.T) {
	s, _, invite, token := portalFixture(t)
	if _, err := s.EnrollmentProfile(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	path := "https://mdm.example.test/mdm/apple/" + invite.DeviceID + "/scep?operation=GetCACaps"
	request := func() *http.Request {
		r := httptest.NewRequest("GET", path, nil)
		r.TLS = &tls.ConnectionState{HandshakeComplete: true}
		return r
	}
	handler := s.ProtocolHandler(nil)
	blocked := false
	for range 35 {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, request())
		if w.Code == 429 {
			blocked = true
			if w.Header().Get("Retry-After") == "" {
				t.Fatal("missing retry guidance")
			}
			break
		}
		if w.Code != 200 {
			t.Fatal(w.Code)
		}
	}
	if !blocked {
		t.Fatal("per-source limit missing")
	}
	limits := newEnrollmentLimiter()
	for range cap(limits.claims) {
		limits.claims <- struct{}{}
	}
	w := httptest.NewRecorder()
	s.scepHTTP(w, request(), invite.DeviceID, limits, clientidentity.Policy{})
	if w.Code != 429 {
		t.Fatal("concurrent crypto limit missing", w.Code)
	}
}

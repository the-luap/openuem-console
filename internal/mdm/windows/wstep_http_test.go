package windows

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/xml"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func wstepTLSServer(t *testing.T, s *Store) (*httptest.Server, string) {
	t.Helper()
	server := httptest.NewUnstartedServer(nil)
	endpoint := "https://" + server.Listener.Addr().String() + "/EnrollmentServer/Enrollment.svc"
	h, err := NewWSTEPHandler(s, endpoint, enrollmentTestOptions())
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	server.Config.Handler = h
	server.Config.ReadHeaderTimeout = 2 * time.Second
	server.Config.ReadTimeout = 5 * time.Second
	server.Config.WriteTimeout = 5 * time.Second
	server.Config.MaxHeaderBytes = 16 << 10
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	server.Client().Timeout = 5 * time.Second
	return server, endpoint
}

func assertWSTEPFault(t *testing.T, data []byte, code, subcode string) {
	t.Helper()
	var root policyWireNode
	if err := xml.Unmarshal(data, &root); err != nil {
		t.Fatal("invalid enrollment fault XML")
	}
	fault := wireChild(t, wireChild(t, &root, soapNS, "Body"), soapNS, "Fault")
	wireCode := wireChild(t, fault, soapNS, "Code")
	if wireChild(t, wireCode, soapNS, "Value").Text != "s:"+code {
		t.Fatal("incorrect enrollment SOAP fault code")
	}
	if subcode != "" && wireChild(t, wireChild(t, wireCode, soapNS, "Subcode"), soapNS, "Value").Text != "s:"+subcode {
		t.Fatal("incorrect enrollment fault subcode")
	}
}

func TestWSTEPHTTPSProtocolBoundaries(t *testing.T) {
	server, endpoint := wstepTLSServer(t, policyClosedStore(t))
	wire := strings.ReplaceAll(wstepTestMessage([]byte{1, 2, 3, 4}), wstepTestURL, endpoint)
	for name, test := range map[string]struct {
		status int
		edit   func(*http.Request)
	}{
		"wrong host": {404, func(r *http.Request) {
			r.Host = "attacker.example.test"
			r.Header.Set("X-Forwarded-Host", server.Listener.Addr().String())
		}},
		"wrong path":             {404, func(r *http.Request) { r.URL.Path = "/enrollmentserver/Enrollment.svc" }},
		"encoded path":           {404, func(r *http.Request) { r.URL.RawPath = "/EnrollmentServer/%45nrollment.svc" }},
		"query":                  {404, func(r *http.Request) { r.URL.RawQuery = "tenant=2" }},
		"empty query":            {404, func(r *http.Request) { r.URL.ForceQuery = true }},
		"get":                    {405, func(r *http.Request) { r.Method = http.MethodGet }},
		"head":                   {405, func(r *http.Request) { r.Method = http.MethodHead }},
		"delete":                 {405, func(r *http.Request) { r.Method = http.MethodDelete }},
		"SOAPAction":             {415, func(r *http.Request) { r.Header.Set("SOAPAction", WSTEPAction) }},
		"wrong content type":     {415, func(r *http.Request) { r.Header.Set("Content-Type", "text/xml") }},
		"duplicate content type": {415, func(r *http.Request) { r.Header.Add("Content-Type", "application/soap+xml") }},
		"wrong media action": {415, func(r *http.Request) {
			r.Header.Set("Content-Type", mime.FormatMediaType("application/soap+xml", map[string]string{"action": PolicyAction}))
		}},
		"compressed input": {415, func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }},
		"known oversized body": {413, func(r *http.Request) {
			data := strings.Repeat("x", MaxWSTEPBytes+1)
			r.Body = io.NopCloser(strings.NewReader(data))
			r.ContentLength = int64(len(data))
		}},
		"chunked oversized body": {413, func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", MaxWSTEPBytes+1)))
			r.ContentLength = -1
		}},
		"wrong SOAP destination": {400, func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(wstepTestMessage([]byte{1, 2, 3, 4})))
			r.ContentLength = -1
		}},
		"malformed XML": {400, func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader("<broken>synthetic-secret-marker"))
			r.ContentLength = -1
		}},
		"required header": {400, func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(strings.Replace(wire, "</s:Header>", `<x:Required xmlns:x="urn:test" s:mustUnderstand="true"/></s:Header>`, 1)))
			r.ContentLength = -1
		}},
		"closed database": {500, func(r *http.Request) {}},
	} {
		t.Run(name, func(t *testing.T) {
			r, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(wire))
			if err != nil {
				t.Fatal(err)
			}
			r.Header.Set("Content-Type", "application/soap+xml")
			test.edit(r)
			response, body := policyHTTPResult(t, server, r)
			if response.StatusCode != test.status {
				t.Fatalf("status %d, expected %d", response.StatusCode, test.status)
			}
			if test.status == 405 && response.Header.Get("Allow") != "POST" {
				t.Fatal("incorrect allowed methods")
			}
			if test.status == 400 {
				if name == "required header" {
					assertWSTEPFault(t, body, "MustUnderstand", "")
				} else {
					assertWSTEPFault(t, body, "Sender", "MessageFormat")
				}
			}
			if test.status == 500 {
				assertWSTEPFault(t, body, "Receiver", "EnrollmentServer")
			}
		})
	}
}

func TestWSTEPHTTPConfigurationBodyAndTLS(t *testing.T) {
	s := policyClosedStore(t)
	for _, bad := range []string{"", "http://enroll.example.test/enrollment", wstepTestURL + "?tenant=1"} {
		if h, err := NewWSTEPHandler(s, bad, enrollmentTestOptions()); err == nil || h != nil {
			t.Fatal("invalid enrollment URL admitted")
		}
	}
	for _, bad := range []*Store{nil, {}} {
		if h, err := NewWSTEPHandler(bad, wstepTestURL, enrollmentTestOptions()); !errors.Is(err, ErrStore) || h != nil {
			t.Fatal("invalid store admitted")
		}
	}
	withoutKey, _ := NewStore(s.db)
	if _, err := NewWSTEPHandler(withoutKey, wstepTestURL, enrollmentTestOptions()); !errors.Is(err, ErrMasterKey) {
		t.Fatal("enrollment handler started without master key")
	}
	if _, err := NewWSTEPHandler(s, wstepTestURL, EnrollmentOptions{}); !errors.Is(err, ErrProvisioning) {
		t.Fatal("invalid provisioning configuration admitted")
	}
	h, err := NewWSTEPHandler(s, wstepTestURL, enrollmentTestOptions())
	if err != nil {
		t.Fatal(err)
	}
	for _, tlsPresent := range []bool{false, true} {
		body := &discoveryCountingBody{Reader: strings.NewReader(strings.Repeat("x", MaxWSTEPBytes*4))}
		r := httptest.NewRequest(http.MethodPost, wstepTestURL, body)
		r.Header.Set("Content-Type", "application/soap+xml")
		r.Header.Set("X-Forwarded-Proto", "https")
		if !tlsPresent {
			r.TLS = nil
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if !tlsPresent {
			if w.Code != 400 || body.read != 0 {
				t.Fatal("TLS requirement bypassed")
			}
		} else if w.Code != 413 || body.read != MaxWSTEPBytes+1 || !body.closed {
			t.Fatal("unbounded enrollment body read")
		}
	}
	for _, body := range []io.ReadCloser{nil, io.NopCloser(discoveryFailedReader{})} {
		r := httptest.NewRequest(http.MethodPost, wstepTestURL, nil)
		r.Body = body
		r.Header.Set("Content-Type", "application/soap+xml")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatal("failed body read reached issuance")
		}
		assertWSTEPFault(t, w.Body.Bytes(), "Sender", "MessageFormat")
	}
}

func TestWSTEPHTTPSIssuesAndReplaysScopedCertificate(t *testing.T) {
	s := authorityTestStore(t)
	initializeTestAuthority(t, s, 1)
	i, request, _ := enrollmentTestRequest(t, s)
	server, endpoint := wstepTLSServer(t, s)
	wire := strings.NewReplacer(wstepTestURL, endpoint, "synthetic-secret-marker", request.Credential.Password).Replace(wstepTestMessage(request.CSRDER))
	post := func(data string) (*http.Response, []byte) {
		t.Helper()
		r, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", mime.FormatMediaType("application/soap+xml", map[string]string{"action": WSTEPAction, "charset": "utf-8"}))
		r.Header.Set("X-Forwarded-Host", "attacker.example.test")
		return policyHTTPResult(t, server, r)
	}
	badCSR := strings.NewReplacer(wstepTestURL, endpoint, "synthetic-secret-marker", request.Credential.Password).Replace(wstepTestMessage([]byte("not DER")))
	response, body := post(badCSR)
	if response.StatusCode != 500 {
		t.Fatal("invalid CSR proof was admitted")
	}
	assertWSTEPFault(t, body, "Receiver", "CertificateRequest")
	response, body = post(strings.Replace(wire, ">CIMClient_Windows<", ">WindowsPhone<", 1))
	if response.StatusCode != 500 {
		t.Fatal("legacy client was admitted")
	}
	assertWSTEPFault(t, body, "Receiver", "Authorization")
	assertEnrollmentCounts(t, s, 0)
	padded := wire + strings.Repeat(" ", MaxWSTEPBytes-len(wire))
	response, body = post(padded)
	media, parameters, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || response.StatusCode != 200 || media != "application/soap+xml" || parameters["action"] != WSTEPResponseAction {
		t.Fatal("TLS issuance did not return a complete WSTEP response")
	}
	provisioning, id := provisioningFromResponse(t, body, discoveryTestID)
	newID := "urn:uuid:00112233-4455-4677-8899-aabbccddeeff"
	response, body = post(strings.Replace(wire, discoveryTestID, newID, 1))
	if response.StatusCode != 200 {
		t.Fatal("TLS issuance retry failed")
	}
	replayed, replayID := provisioningFromResponse(t, body, newID)
	if !bytes.Equal(provisioning, replayed) || id != replayID {
		t.Fatal("TLS retry changed certificate or secrets")
	}
	assertEnrollmentCounts(t, s, 1)
	if invitationEventCount(t, s, i.ID, "invitation.consumed") != 1 || invitationEventCount(t, s, i.ID, "enrollment.replayed") != 1 {
		t.Fatal("TLS retry was not committed exactly once")
	}
	response, wrong := post(strings.Replace(wire, request.Credential.Password, "incorrect-password", 1))
	if response.StatusCode != 500 {
		t.Fatal("wrong credential admitted")
	}
	assertWSTEPFault(t, wrong, "Receiver", "Authentication")
	if err := s.RevokeEnrollmentInvitation(context.Background(), "operator", credentialTestScope, i.ID); err != nil {
		t.Fatal(err)
	}
	response, revoked := post(wire)
	if response.StatusCode != 500 || !bytes.Equal(wrong, revoked) {
		t.Fatal("authentication fault exposes invitation lifecycle")
	}
	for _, sensitive := range []string{request.Credential.Password, request.Credential.Username, string(provisioning), "SYNTHETIC-WINDOWS"} {
		if bytes.Contains(revoked, []byte(sensitive)) {
			t.Fatal("fault exposes protected enrollment data")
		}
	}
}

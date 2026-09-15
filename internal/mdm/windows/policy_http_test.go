package windows

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func policyClosedStore(t *testing.T) *Store {
	t.Helper()
	// No database connection is attempted: close the handle before constructing
	// the handler. Protocol-boundary tests also run in native Windows CI.
	db, err := sql.Open("pgx", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := NewStoreWithMasterKey(db, authorityTestMasterKey)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func policyTLSServer(t *testing.T, s *Store) (*httptest.Server, string) {
	t.Helper()
	server := httptest.NewUnstartedServer(nil)
	endpoint := "https://" + server.Listener.Addr().String() + "/EnrollmentServer/Policy.svc"
	h, err := NewPolicyHandler(s, endpoint)
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

func policyHTTPResult(t *testing.T, server *httptest.Server, request *http.Request) (*http.Response, []byte) {
	t.Helper()
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.ProtoMajor != 1 || len(response.TransferEncoding) != 0 || response.ContentLength != int64(len(body)) || response.Header.Get("Content-Length") != strconv.Itoa(len(body)) {
		t.Fatal("response is not a complete HTTP/1.1 message")
	}
	if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Pragma") != "no-cache" || response.Header.Get("X-Content-Type-Options") != "nosniff" || response.Header.Get("Set-Cookie") != "" {
		t.Fatal("unexpected policy cache or cookie behavior")
	}
	for _, secret := range []string{"synthetic-secret-marker", "synthetic@example.test", "attacker.example.test"} {
		if bytes.Contains(body, []byte(secret)) {
			t.Fatal("response reflected request data")
		}
	}
	return response, body
}

func TestPolicyHTTPProtocolBoundaries(t *testing.T) {
	server, endpoint := policyTLSServer(t, policyClosedStore(t))
	wire := strings.ReplaceAll(policyTestMessage(), policyTestURL, endpoint)
	for name, test := range map[string]struct {
		status int
		edit   func(*http.Request)
	}{
		"wrong host": {404, func(r *http.Request) {
			r.Host = "attacker.example.test"
			r.Header.Set("X-Forwarded-Host", server.Listener.Addr().String())
		}},
		"wrong path":             {404, func(r *http.Request) { r.URL.Path = "/enrollmentserver/Policy.svc" }},
		"encoded path":           {404, func(r *http.Request) { r.URL.RawPath = "/EnrollmentServer/%50olicy.svc" }},
		"dot path":               {404, func(r *http.Request) { r.URL.Path = "/EnrollmentServer/../EnrollmentServer/Policy.svc" }},
		"query":                  {404, func(r *http.Request) { r.URL.RawQuery = "tenant=2" }},
		"empty query":            {404, func(r *http.Request) { r.URL.ForceQuery = true }},
		"get":                    {405, func(r *http.Request) { r.Method = http.MethodGet }},
		"head":                   {405, func(r *http.Request) { r.Method = http.MethodHead }},
		"put":                    {405, func(r *http.Request) { r.Method = http.MethodPut }},
		"missing content type":   {415, func(r *http.Request) { r.Header.Del("Content-Type") }},
		"duplicate content type": {415, func(r *http.Request) { r.Header.Add("Content-Type", "application/soap+xml") }},
		"SOAP 1.1":               {415, func(r *http.Request) { r.Header.Set("Content-Type", "text/xml") }},
		"SOAPAction":             {415, func(r *http.Request) { r.Header.Set("SOAPAction", PolicyAction) }},
		"wrong action": {415, func(r *http.Request) {
			r.Header.Set("Content-Type", mime.FormatMediaType("application/soap+xml", map[string]string{"action": DiscoveryAction}))
		}},
		"wrong charset": {415, func(r *http.Request) { r.Header.Set("Content-Type", "application/soap+xml; charset=utf-16") }},
		"gzip":          {415, func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }},
		"duplicate encoding": {415, func(r *http.Request) {
			r.Header.Add("Content-Encoding", "identity")
			r.Header.Add("Content-Encoding", "identity")
		}},
		"large body": {413, func(r *http.Request) {
			data := strings.Repeat("x", MaxPolicyBytes+1)
			r.Body = io.NopCloser(strings.NewReader(data))
			r.ContentLength = int64(len(data))
		}},
		"large chunked body": {413, func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", MaxPolicyBytes+1)))
			r.ContentLength = -1
		}},
		"malformed SOAP": {400, func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader("<broken>synthetic-secret-marker"))
			r.ContentLength = -1
		}},
		"wrong SOAP destination": {400, func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(policyTestMessage()))
			r.ContentLength = -1
		}},
		"required header": {400, func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(strings.Replace(wire, "</s:Header>", `<x:Required xmlns:x="urn:test" s:mustUnderstand="1"/></s:Header>`, 1)))
			r.ContentLength = -1
		}},
		"unavailable database": {500, func(r *http.Request) {}},
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
			if test.status == 400 || test.status == 500 {
				var root policyWireNode
				if err := xml.Unmarshal(body, &root); err != nil {
					t.Fatal(err)
				}
				fault := wireChild(t, wireChild(t, &root, soapNS, "Body"), soapNS, "Fault")
				code := wireChild(t, fault, soapNS, "Code")
				want := "s:Sender"
				if name == "required header" {
					want = "s:MustUnderstand"
				} else if test.status == 500 {
					want = "s:Receiver"
				}
				if wireChild(t, code, soapNS, "Value").Text != want {
					t.Fatal("incorrect SOAP fault code")
				}
				if name != "required header" {
					want = "s:MessageFormat"
					if test.status == 500 {
						want = "s:EnrollmentServer"
					}
					if wireChild(t, wireChild(t, code, soapNS, "Subcode"), soapNS, "Value").Text != want {
						t.Fatal("incorrect MDE2 fault subcode")
					}
				}
			}
		})
	}
}

func TestPolicyHTTPBodyAndConfiguration(t *testing.T) {
	s := policyClosedStore(t)
	for _, bad := range []string{"", "http://enroll.example.test/Policy.svc", policyTestURL + "?tenant=1"} {
		if h, err := NewPolicyHandler(s, bad); err == nil || h != nil {
			t.Fatal("invalid policy URL admitted")
		}
	}
	for _, bad := range []*Store{nil, {}} {
		if h, err := NewPolicyHandler(bad, policyTestURL); !errors.Is(err, ErrStore) || h != nil {
			t.Fatal("invalid store admitted")
		}
	}
	withoutKey, _ := NewStore(s.db)
	if _, err := NewPolicyHandler(withoutKey, policyTestURL); !errors.Is(err, ErrMasterKey) {
		t.Fatal("handler started without a master key")
	}
	h, err := NewPolicyHandler(s, policyTestURL)
	if err != nil {
		t.Fatal(err)
	}
	for _, present := range []bool{false, true} {
		body := &discoveryCountingBody{Reader: strings.NewReader(strings.Repeat("x", 4*MaxPolicyBytes))}
		r := httptest.NewRequest(http.MethodPost, policyTestURL, body)
		r.Header.Set("Content-Type", "application/soap+xml")
		r.Header.Set("X-Forwarded-Proto", "https")
		if !present {
			r.TLS = nil
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if !present {
			if w.Code != 400 || body.read != 0 {
				t.Fatal("TLS requirement bypassed")
			}
		} else if w.Code != 413 || body.read != MaxPolicyBytes+1 || !body.closed {
			t.Fatal("policy read is unbounded")
		}
	}
	for _, body := range []io.ReadCloser{nil, io.NopCloser(discoveryFailedReader{})} {
		r := httptest.NewRequest(http.MethodPost, policyTestURL, nil)
		r.Body = body
		r.Header.Set("Content-Type", "application/soap+xml")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 400 || bytes.Contains(w.Body.Bytes(), []byte("synthetic-secret-marker")) {
			t.Fatal("failed body read did not return a private fault")
		}
	}
}

func TestPolicyHTTPSWithScopedPostgreSQLAuthority(t *testing.T) {
	s := authorityTestStore(t)
	a := initializeTestAuthority(t, s, 1)
	i, credential := createTestInvitation(t, s, "operator")
	server, endpoint := policyTLSServer(t, s)
	wire := strings.NewReplacer(policyTestURL, endpoint, "synthetic-secret-marker", credential.Password).Replace(policyTestMessage())
	// Exact byte limit and a non-default charset spelling still produce a full
	// authenticated policy. Forwarded host/account hints cannot change its scope.
	padded := wire + strings.Repeat(" ", MaxPolicyBytes-len(wire))
	r, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(padded))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", mime.FormatMediaType("application/soap+xml", map[string]string{"charset": "UTF-8", "action": PolicyAction}))
	r.Header.Set("Content-Encoding", "identity")
	r.Header.Set("X-Forwarded-Host", "attacker.example.test")
	response, body := policyHTTPResult(t, server, r)
	media, parameters, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || response.StatusCode != 200 || media != "application/soap+xml" || parameters["action"] != PolicyResponseAction || !bytes.Contains(body, []byte(a.ID)) || bytes.Contains(body, []byte(credential.Password)) {
		t.Fatal("authenticated TLS policy did not bind issuer or response action")
	}
	var wg sync.WaitGroup
	for n := 1; n <= 8; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			id := fmt.Sprintf("urn:uuid:d62c6720-0989-4a51-a1b6-%012d", n)
			request, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(strings.ReplaceAll(wire, discoveryTestID, id)))
			if err != nil {
				t.Error(err)
				return
			}
			request.Header.Set("Content-Type", "application/soap+xml")
			response, err := server.Client().Do(request)
			if err != nil {
				t.Error(err)
				return
			}
			defer response.Body.Close()
			data, err := io.ReadAll(response.Body)
			if err != nil || response.StatusCode != 200 || strings.Count(string(data), id) != 1 || !bytes.Contains(data, []byte(a.ID)) {
				t.Error("concurrent authenticated policy lost correlation or scope")
			}
		}(n)
	}
	wg.Wait()
	if invitationEventCount(t, s, i.ID, "policy.read") != 9 || invitationEventCount(t, s, i.ID, "invitation.consumed") != 0 {
		t.Fatal("HTTPS policy audits or invitation consumption changed")
	}
	// The same fixed authentication fault covers a wrong password, account
	// mismatch, revoked invitation, consumed invitation and expired invitation.
	ctx := context.Background()
	if err := s.RevokeEnrollmentInvitation(ctx, "operator", credentialTestScope, i.ID); err != nil {
		t.Fatal(err)
	}
	_, consumed := createTestInvitation(t, s, "operator")
	if err := s.withEnrollmentCredential(ctx, *consumed, simulatedIssuance); err != nil {
		t.Fatal(err)
	}
	var now time.Time
	if err := s.db.QueryRow(`SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	_, expired := insertTimedInvitation(t, s, now.Add(-2*time.Hour), now.Add(-time.Hour))
	var previous []byte
	for _, c := range []UsernameCredential{{Username: credential.Username, Password: "wrong"}, {Username: "wrong@example.test", Password: credential.Password}, *credential, *consumed, *expired} {
		data := strings.NewReplacer(policyTestURL, endpoint, "synthetic@example.test", c.Username, "synthetic-secret-marker", c.Password).Replace(policyTestMessage())
		r, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/soap+xml")
		response, body := policyHTTPResult(t, server, r)
		if response.StatusCode != 500 || !bytes.Contains(body, []byte("s:Authentication")) || bytes.Contains(body, []byte(a.ID)) || bytes.Contains(body, []byte(c.Username)) || bytes.Contains(body, []byte(c.Password)) {
			t.Fatal("invalid credential exposed policy or request data")
		}
		if previous != nil && !bytes.Equal(previous, body) {
			t.Fatal("authentication fault reveals credential lifecycle")
		}
		previous = body
	}
}

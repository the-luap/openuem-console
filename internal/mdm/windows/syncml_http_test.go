package windows

import (
	"bytes"
	"crypto/tls"
	"database/sql"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

type syncMLFailingReader struct{}

func (syncMLFailingReader) Read([]byte) (int, error) {
	return 0, errors.New("synthetic private body read detail")
}
func (syncMLFailingReader) Close() error { return nil }

func TestSyncMLHTTPTransportAndContentBoundaries(t *testing.T) {
	_, leaf, _ := managementTestCertificates(t)
	box, _ := newAuthoritySecretBox(authorityTestMasterKey)
	store := &Store{db: &sql.DB{}, secrets: box}
	options := enrollmentTestOptions()
	handler, err := NewSyncMLHandler(store, options)
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		mutate func(*http.Request)
		status int
	}{
		"plaintext":    {func(r *http.Request) { r.TLS = nil }, http.StatusBadRequest},
		"wrong host":   {func(r *http.Request) { r.Host = "other.example.test" }, http.StatusNotFound},
		"wrong path":   {func(r *http.Request) { r.URL.Path += "/" }, http.StatusNotFound},
		"escaped path": {func(r *http.Request) { r.URL.RawPath = "/windows/%73yncml" }, http.StatusNotFound},
		"query":        {func(r *http.Request) { r.URL.RawQuery = "token=synthetic-private-value" }, http.StatusNotFound},
		"GET":          {func(r *http.Request) { r.Method = http.MethodGet }, http.StatusMethodNotAllowed},
		"HEAD":         {func(r *http.Request) { r.Method = http.MethodHead }, http.StatusMethodNotAllowed},
		"no TLS peer": {func(r *http.Request) {
			r.TLS.PeerCertificates = nil
			r.Header.Set("X-Forwarded-Client-Cert", "synthetic-certificate")
		}, http.StatusForbidden},
		"incomplete TLS":         {func(r *http.Request) { r.TLS.HandshakeComplete = false }, http.StatusForbidden},
		"old TLS":                {func(r *http.Request) { r.TLS.Version = tls.VersionTLS11 }, http.StatusForbidden},
		"missing content type":   {func(r *http.Request) { r.Header.Del("Content-Type") }, http.StatusUnsupportedMediaType},
		"duplicate content type": {func(r *http.Request) { r.Header.Add("Content-Type", syncMLContentType) }, http.StatusUnsupportedMediaType},
		"WBXML":                  {func(r *http.Request) { r.Header.Set("Content-Type", "application/vnd.syncml.dm+wbxml") }, http.StatusUnsupportedMediaType},
		"other charset":          {func(r *http.Request) { r.Header.Set("Content-Type", syncMLContentType+"; charset=utf-16") }, http.StatusUnsupportedMediaType},
		"unknown parameter":      {func(r *http.Request) { r.Header.Set("Content-Type", syncMLContentType+"; action=other") }, http.StatusUnsupportedMediaType},
		"gzip":                   {func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }, http.StatusUnsupportedMediaType},
		"identity encoding":      {func(r *http.Request) { r.Header.Set("Content-Encoding", "identity") }, http.StatusUnsupportedMediaType},
		"declared oversized":     {func(r *http.Request) { r.ContentLength = MaxSyncMLBytes + 1 }, http.StatusRequestEntityTooLarge},
		"stream oversized": {func(r *http.Request) {
			r.ContentLength = -1
			r.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", MaxSyncMLBytes+1)))
		}, http.StatusRequestEntityTooLarge},
		"missing body":      {func(r *http.Request) { r.Body = nil }, http.StatusBadRequest},
		"body read failure": {func(r *http.Request) { r.Body = syncMLFailingReader{} }, http.StatusBadRequest},
		"invalid XML":       {func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("<invalid/>")) }, http.StatusBadRequest},
	} {
		t.Run(name, func(t *testing.T) {
			r := managementTestRequest(t, leaf.Raw, options)
			r.Header.Set("Content-Type", syncMLContentType)
			r.Body = io.NopCloser(strings.NewReader("unread"))
			test.mutate(r)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != test.status || w.Body.Len() != 0 || w.Header().Get("Content-Length") != "0" || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Location") != "" {
				t.Fatal("HTTP boundary returned unexpected status, data or headers", w.Code)
			}
			if test.status == http.StatusMethodNotAllowed && w.Header().Get("Allow") != "POST" {
				t.Fatal("missing method declaration")
			}
		})
	}
	for _, invalid := range []*Store{nil, {}, {db: &sql.DB{}}} {
		if handler, err := NewSyncMLHandler(invalid, options); err == nil || handler != nil {
			t.Fatal("handler accepted missing database or master key")
		}
	}
	options.ManagementURL = "http://manage.example.test/windows/syncml"
	if handler, err := NewSyncMLHandler(store, options); err == nil || handler != nil {
		t.Fatal("handler accepted insecure configuration")
	}
}

func TestSyncMLHTTPRealTLSCSPExchangeReplayAndRevocation(t *testing.T) {
	s := authorityTestStore(t)
	initializeTestAuthority(t, s, 1)
	var handler *SyncMLHandler
	resumed := make(chan bool, 8)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { resumed <- r.TLS.DidResume; handler.ServeHTTP(w, r) }))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.Config.ReadHeaderTimeout = 2 * time.Second
	server.Config.ReadTimeout = 5 * time.Second
	server.Config.WriteTimeout = 5 * time.Second
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, ClientAuth: tls.RequireAnyClientCert}
	options := enrollmentTestOptions()
	options.ManagementURL = "https://" + server.Listener.Addr().String() + "/windows/syncml"
	_, result, key := managementTestEnrollment(t, s, options)
	f := syncMLTestEnrolled(t, s, result, options)
	queued := cspTestQueue(t, f, cspTestPolicy())
	updatePolicy := UpdatePolicy{QualityDeadlineDays: updateTestInt(7)}
	updateRun := updateTestQueue(t, f, updatePolicy, false)
	var err error
	handler, err = NewSyncMLHandler(s, options)
	if err != nil {
		t.Fatal(err)
	}
	server.StartTLS()
	defer server.Close()
	client := server.Client()
	client.Timeout = 5 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	transport := client.Transport.(*http.Transport).Clone()
	defer transport.CloseIdleConnections()
	transport.Proxy = nil
	transport.DisableKeepAlives = true
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: [][]byte{result.Certificate}, PrivateKey: key}}
	transport.TLSClientConfig.ClientSessionCache = tls.NewLRUClientSessionCache(2)
	client.Transport = transport
	post := func(data []byte, status int) []byte {
		t.Helper()
		response, err := client.Post(options.ManagementURL, syncMLContentType, bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		got, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != status || response.Header.Get("Content-Length") != strconv.Itoa(len(got)) || len(response.TransferEncoding) != 0 || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("real TLS management exchange returned unexpected HTTP framing", response.StatusCode)
		}
		if status == http.StatusOK && response.Header.Get("Content-Type") != syncMLContentType+"; charset=utf-8" {
			t.Fatal("unexpected SyncML response MIME")
		}
		if status != http.StatusOK && len(got) != 0 {
			t.Fatal("HTTP error exposed a protocol body")
		}
		return got
	}
	initial := f.initial(t)
	first := post(initial, http.StatusOK)
	if <-resumed {
		t.Fatal("first connection unexpectedly resumed")
	}
	if replay := post(initial, http.StatusOK); !bytes.Equal(replay, first) {
		t.Fatal("TLS replay changed protocol bytes")
	}
	if !<-resumed {
		t.Fatal("retry did not exercise TLS resumption")
	}
	deliveryRequest := syncMLTestWire(t, syncMLTestReply(syncMLTestParsed(t, first)))
	delivery := post(deliveryRequest, http.StatusOK)
	if !<-resumed || len(syncMLTestParsed(t, delivery).Commands) != 2 {
		t.Fatal("CSP delivery did not use the authenticated resumed TLS session")
	}
	final := post(syncMLTestWire(t, cspTestReply(syncMLTestParsed(t, delivery))), http.StatusOK)
	if !<-resumed {
		t.Fatal("completion did not use resumed TLS")
	}
	for step := 0; step < 3; step++ {
		final = post(syncMLTestWire(t, updateTestReply(syncMLTestParsed(t, final), updatePolicy, false, false)), http.StatusOK)
		if !<-resumed {
			t.Fatal("typed update step did not use resumed TLS")
		}
	}
	if updateTestRead(t, f, updateRun.ID).Phase != "verified" {
		t.Fatal("TLS update workflow did not verify effective policy")
	}
	if message := syncMLTestParsed(t, final); len(message.Commands) != 1 || message.Header.Credential != nil {
		t.Fatal("unexpected completed exchange")
	}
	if cspTestRead(t, f, queued.ID).Command.Phase != "acknowledged" {
		t.Fatal("TLS CSP evidence was not committed")
	}
	post(deliveryRequest, http.StatusConflict)
	if !<-resumed {
		t.Fatal("completed CSP replay did not exercise TLS resumption")
	}
	if _, err := s.db.Exec(`UPDATE mdm_windows_device_certificates SET revoked_at=clock_timestamp() WHERE id=$1`, f.identity.CertificateID); err != nil {
		t.Fatal(err)
	}
	post(initial, http.StatusForbidden)
	if !<-resumed {
		t.Fatal("revocation test did not use resumed TLS")
	}
	syncMLTestCounts(t, s, 1, 1, 6, 4)
}

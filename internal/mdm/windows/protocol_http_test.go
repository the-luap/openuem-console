package windows

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/gateway"
	"github.com/open-uem/openuem-console/internal/mdm/windows/protocol"
	"github.com/open-uem/openuem-console/internal/security/clientidentity"
)

func protocolTestOptions(origin string) ProtocolOptions {
	return ProtocolOptions{PublicOrigin: origin, ProviderID: "OpenUEM", DisplayName: "OpenUEM Windows Management"}
}

func protocolTestGatewayIdentity(t *testing.T) (tls.Certificate, clientidentity.Policy) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic Windows gateway"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := clientidentity.FromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, policy
}

func TestWindowsProtocolConfigurationAndAdmission(t *testing.T) {
	s := policyClosedStore(t)
	for _, origin := range []string{"", "http://uem.example.test", "https://uem.example.test/path", "https://uem.example.test/?", "https://uem.example.test/#", "https://uem.example.test/%2f", "https://user@uem.example.test", "https://uem.example.test:0", "https://uem.example.test:65536", "https://uem.example.test?token=private", "https://uem.example.test/.."} {
		if _, err := protocolTestOptions(origin).EnrollmentOptions(); err == nil {
			t.Fatal("invalid origin admitted")
		}
	}
	for _, bad := range []*Store{nil, {}, {db: s.db}} {
		if h, err := NewProtocolHandler(bad, protocolTestOptions("https://uem.example.test"), clientidentity.Policy{}); err == nil || h != nil {
			t.Fatal("missing protected store admitted")
		}
	}
	bad := protocolTestOptions("https://uem.example.test")
	bad.ProviderID = "invalid provider"
	if _, err := bad.EnrollmentOptions(); err == nil {
		t.Fatal("invalid provider admitted")
	}
	h, err := NewProtocolHandler(s, protocolTestOptions("https://uem.example.test/"), clientidentity.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	server := h.Server("127.0.0.1:0")
	if server.TLSConfig.MinVersion != tls.VersionTLS12 || server.TLSConfig.ClientAuth != tls.RequestClientCert || server.ReadTimeout <= 0 || server.WriteTimeout <= 0 || server.ReadHeaderTimeout <= 0 || server.MaxHeaderBytes != 32<<10 {
		t.Fatal("server transport bounds missing")
	}
	request := func() *http.Request {
		r := httptest.NewRequest("GET", "https://uem.example.test"+protocol.DiscoveryPath, nil)
		r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
		return r
	}
	for _, test := range []struct {
		change func(*http.Request)
		status int
	}{
		{func(r *http.Request) { r.TLS = nil }, 400},
		{func(r *http.Request) { r.TLS.HandshakeComplete = false }, 400},
		{func(r *http.Request) { r.TLS.Version = tls.VersionTLS11 }, 400},
		{func(r *http.Request) { r.Host = "attacker.example.test" }, 404},
		{func(r *http.Request) { r.URL.RawQuery = "tenant=2" }, 404},
		{func(r *http.Request) { r.Method = "DELETE" }, 405},
		{func(r *http.Request) { r.URL.Path = "/windows" }, 404},
	} {
		r, w := request(), httptest.NewRecorder()
		test.change(r)
		h.ServeHTTP(w, r)
		if w.Code != test.status || w.Body.Len() != 0 || w.Header().Get("Content-Length") != "0" {
			t.Fatal("protocol boundary failed", w.Code)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request().WithContext(ctx))
	if w.Code != 503 {
		t.Fatal("canceled request admitted")
	}
	entered, release := make(chan struct{}, protocolRequestLimit), make(chan struct{})
	h.routes[protocol.DiscoveryPath] = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if deadline, ok := r.Context().Deadline(); !ok || time.Until(deadline) > 30*time.Second {
			t.Error("request deadline missing")
		}
		entered <- struct{}{}
		<-release
		writeEnrollmentHTTP(w, r, 200, "", nil)
	})
	var group sync.WaitGroup
	for range protocolRequestLimit {
		group.Go(func() { h.ServeHTTP(httptest.NewRecorder(), request()) })
	}
	for range protocolRequestLimit {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("admission test stalled")
		}
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, request())
	if w.Code != 429 || w.Header().Get("Retry-After") != "5" || w.Body.Len() != 0 {
		t.Error("full admission did not reject immediately")
	}
	close(release)
	group.Wait()
	if len(h.slots) != 0 {
		t.Fatal("admission slots leaked")
	}
}

func TestWindowsProtocolGatewayEnrollmentAndScheduledUpdate(t *testing.T) {
	s := authorityTestStore(t)
	a := initializeTestAuthority(t, s, 1)
	front := httptest.NewUnstartedServer(nil)
	options := protocolTestOptions("https://" + front.Listener.Addr().String())
	enrollment, err := options.EnrollmentOptions()
	if err != nil {
		t.Fatal(err)
	}
	identity, policy := protocolTestGatewayIdentity(t)
	public, err := NewProtocolHandler(s, options, policy)
	if err != nil {
		t.Fatal(err)
	}
	backend := httptest.NewUnstartedServer(nil)
	backend.Config = public.Server(backend.Listener.Addr().String())
	backend.TLS = backend.Config.TLSConfig
	backend.StartTLS()
	defer backend.Close()
	backendRoots := x509.NewCertPool()
	backendRoots.AddCert(backend.Certificate())
	g, err := gateway.New(gateway.Config{PublicOrigin: options.PublicOrigin, AppleURL: backend.URL, ConsoleURL: backend.URL, AuthURL: backend.URL, WindowsURL: backend.URL, AdminNetworks: []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")}, BackendTLS: &tls.Config{Certificates: []tls.Certificate{identity}, RootCAs: backendRoots}})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	resumed := make(chan bool, 32)
	front.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == protocol.ManagementPath {
			resumed <- r.TLS.DidResume
		}
		g.ServeHTTP(w, r)
	})
	front.TLS = &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, ClientAuth: tls.RequestClientCert}
	front.StartTLS()
	defer front.Close()
	client := front.Client()
	client.Timeout = 5 * time.Second
	send := func(client *http.Client, method, path, contentType string, data []byte, status int) []byte {
		t.Helper()
		r, err := http.NewRequest(method, front.URL+path, bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		if contentType != "" {
			r.Header.Set("Content-Type", contentType)
		}
		r.Header.Set("Client-Cert", ":"+base64.StdEncoding.EncodeToString(identity.Certificate[0])+":")
		r.Header.Set("X-SSL-Client-Cert", "synthetic forged identity")
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("synthetic protocol request failed")
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil || response.StatusCode != status || response.Header.Get("Content-Length") != strconv.Itoa(len(body)) || len(response.TransferEncoding) != 0 || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("unexpected protocol status or framing", response.StatusCode)
		}
		return body
	}
	send(client, "GET", protocol.DiscoveryPath, "", nil, 200)
	send(client, "HEAD", protocol.DiscoveryPath, "", nil, 200)
	discovery := send(client, "POST", protocol.DiscoveryPath, "application/soap+xml", []byte(strings.ReplaceAll(discoveryTestMessage(), discoveryTestURL, front.URL+protocol.DiscoveryPath)), 200)
	for _, value := range []string{front.URL + protocol.PolicyPath, front.URL + protocol.EnrollmentPath, "OnPremise"} {
		if !bytes.Contains(discovery, []byte(value)) {
			t.Fatal("discovery did not advertise configured endpoints")
		}
	}
	i, request, key := enrollmentTestRequest(t, s)
	policyWire := strings.NewReplacer(policyTestURL, front.URL+protocol.PolicyPath, "synthetic@example.test", request.Credential.Username, "synthetic-secret-marker", request.Credential.Password).Replace(policyTestMessage())
	policyReply := send(client, "POST", protocol.PolicyPath, "application/soap+xml", []byte(policyWire), 200)
	if !bytes.Contains(policyReply, []byte(a.ID)) {
		t.Fatal("policy omitted scoped authority")
	}
	wstepWire := strings.NewReplacer(wstepTestURL, front.URL+protocol.EnrollmentPath, "synthetic@example.test", request.Credential.Username, "synthetic-secret-marker", request.Credential.Password).Replace(wstepTestMessage(request.CSRDER))
	wstepReply := send(client, "POST", protocol.EnrollmentPath, "application/soap+xml", []byte(wstepWire), 200)
	provisioning, _ := provisioningFromResponse(t, wstepReply, request.MessageID)
	if !bytes.Contains(provisioning, []byte(enrollment.ManagementURL)) {
		t.Fatal("provisioning did not bind public management URL")
	}
	if retry := send(client, "POST", protocol.EnrollmentPath, "application/soap+xml", []byte(wstepWire), 200); !bytes.Equal(retry, wstepReply) {
		t.Fatal("enrollment retry changed bytes")
	}
	result := readEnrollmentTestResult(t, s, i.ID)
	f := syncMLTestEnrolled(t, s, result, enrollment)
	updatePolicy := updateTestFullPolicy()
	ring := updateTestRing(t, f, updatePolicy)
	schedule := updateTestSchedule(t, f, ring, time.Now().UTC().Truncate(time.Microsecond))
	// The production runner resumes the persisted plan without a HTTP request.
	worker, stop := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); s.RunUpdateSchedules(worker, nil) }()
	t.Cleanup(func() { stop(); <-done })
	var rolloutID string
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for rolloutID == "" {
		// Observe committed fixture metadata without the console reader's FOR
		// SHARE lock. That reader can make the worker's SKIP LOCKED pass skip
		// this plan and wait its normal 15-second polling interval, especially
		// on a loaded CI runner. Validate the protected public read afterward.
		if err := s.db.QueryRowContext(t.Context(), `SELECT COALESCE(rollout_id::text,'') FROM mdm_windows_update_schedules WHERE id=$1`, schedule.ID).Scan(&rolloutID); err != nil {
			t.Fatal(err)
		}
		if rolloutID != "" {
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("runner did not activate due plan")
		case <-tick.C:
		}
	}
	stop()
	<-done
	if read := updateTestScheduleRead(t, f, schedule.ID); read.Phase != "activated" || read.RolloutID != rolloutID {
		t.Fatal("activated schedule failed protected console read")
	}
	rollout, err := s.UpdateRolloutDetails(t.Context(), "operator", f.identity.Scope, rolloutID)
	if err != nil {
		t.Fatal(err)
	}
	deviceTransport := client.Transport.(*http.Transport).Clone()
	deviceTransport.TLSClientConfig = deviceTransport.TLSClientConfig.Clone()
	deviceTransport.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: [][]byte{result.Certificate}, PrivateKey: key}}
	deviceTransport.TLSClientConfig.ClientSessionCache = tls.NewLRUClientSessionCache(2)
	deviceTransport.DisableKeepAlives = true
	defer deviceTransport.CloseIdleConnections()
	device := &http.Client{Transport: deviceTransport, Timeout: 5 * time.Second}
	initial := f.initial(t)
	send(client, "POST", protocol.ManagementPath, syncMLContentType, initial, 403)
	<-resumed
	first := send(device, "POST", protocol.ManagementPath, syncMLContentType, initial, 200)
	if <-resumed {
		t.Fatal("initial device handshake unexpectedly resumed")
	}
	if retry := send(device, "POST", protocol.ManagementPath, syncMLContentType, initial, 200); !bytes.Equal(first, retry) || !<-resumed {
		t.Fatal("resumed device retry failed")
	}
	response := send(device, "POST", protocol.ManagementPath, syncMLContentType, syncMLTestWire(t, syncMLTestReply(syncMLTestParsed(t, first))), 200)
	<-resumed
	for step := 0; step < 7; step++ {
		if len(response) > 5000 {
			t.Fatal("gateway changed advertised response budget")
		}
		response = send(device, "POST", protocol.ManagementPath, syncMLContentType, syncMLTestWire(t, updateTestReply(syncMLTestParsed(t, response), updatePolicy, false, false)), 200)
		if !<-resumed {
			t.Fatal("update did not use resumed device TLS")
		}
	}
	if updateTestRead(t, f, rollout.Runs[0].ID).Phase != "verified" {
		t.Fatal("gateway update effective values were not verified")
	}
	if _, err := s.db.Exec(`UPDATE mdm_windows_device_certificates SET revoked_at=clock_timestamp() WHERE id=$1`, f.identity.CertificateID); err != nil {
		t.Fatal(err)
	}
	send(device, "POST", protocol.ManagementPath, syncMLContentType, initial, 403)
	if !<-resumed {
		t.Fatal("revocation did not exercise resumed TLS")
	}
	// Possession of a device key does not grant direct access to the private
	// listener, including its otherwise anonymous discovery service.
	directTransport := backend.Client().Transport.(*http.Transport).Clone()
	directTransport.TLSClientConfig.Certificates = deviceTransport.TLSClientConfig.Certificates
	defer directTransport.CloseIdleConnections()
	direct := &http.Client{Transport: directTransport, Timeout: 5 * time.Second}
	if r, err := direct.Get(backend.URL + protocol.DiscoveryPath); err == nil {
		r.Body.Close()
		t.Fatal("device bypassed pinned gateway TLS")
	}
}

package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

func TestAgentChannelUsesPrivateMutualTLSAndSurvivesHTTPDeadlines(t *testing.T) {
	gatewayIdentity, _ := testIdentity(t, "gateway")
	gatewayRoots := x509.NewCertPool()
	gatewayRoots.AddCert(gatewayIdentity.Leaf)
	certificateServer := httptest.NewTLSServer(http.NotFoundHandler())
	certificate := certificateServer.TLS.Certificates[0]
	backendRoots := x509.NewCertPool()
	backendRoots.AddCert(certificateServer.Certificate())
	certificateServer.Close()
	deviceKey, _ := nkeys.CreateUser()
	devicePublic, _ := deviceKey.PublicKey()
	workerKey, _ := nkeys.CreateUser()
	workerPublic, _ := workerKey.PublicKey()
	broker, err := server.NewServer(&server.Options{
		Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true,
		Websocket: server.WebsocketOpts{Host: "127.0.0.1", Port: -1, TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12,
			ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: gatewayRoots,
		}},
		Nkeys: []*server.NkeyUser{
			{Nkey: devicePublic, Permissions: &server.Permissions{
				Publish:   &server.SubjectPermission{Allow: []string{"uem.v1.agent.own.request.report"}},
				Subscribe: &server.SubjectPermission{Allow: []string{"uem.v1.agent.own.reply.>"}},
			}},
			{Nkey: workerPublic},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	broker.Start()
	t.Cleanup(func() { broker.Shutdown(); broker.WaitForShutdown() })
	if !broker.ReadyForConnections(5 * time.Second) {
		t.Fatal("broker did not start")
	}
	backendURL := strings.Replace(broker.WebsocketURL(), "wss://", "https://", 1)
	frontend := httptest.NewUnstartedServer(nil)
	frontOrigin := "https://" + frontend.Listener.Addr().String()
	proxy, err := New(Config{
		PublicOrigin: frontOrigin, AppleURL: backendURL, AuthURL: backendURL, ConsoleURL: backendURL,
		AgentURL: backendURL, AgentConnectionLimit: 1,
		AdminNetworks: []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")},
		BackendTLS:    &tls.Config{Certificates: []tls.Certificate{gatewayIdentity}, RootCAs: backendRoots},
	})
	if err != nil {
		t.Fatal(err)
	}
	frontend.Config.Handler = proxy
	frontend.Config.ReadTimeout = time.Second
	frontend.Config.WriteTimeout = time.Second
	frontend.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequestClientCert}
	frontend.StartTLS()
	t.Cleanup(frontend.Close)
	t.Cleanup(func() { _ = proxy.Close() })
	frontRoots := x509.NewCertPool()
	frontRoots.AddCert(frontend.Certificate())
	endpoint := strings.Replace(frontend.URL, "https://", "wss://", 1) + "/agent-channel"
	options := []nats.Option{nats.Secure(&tls.Config{RootCAs: frontRoots}), nats.Nkey(devicePublic, deviceKey.Sign), nats.CustomInboxPrefix("uem.v1.agent.own.reply"), nats.NoReconnect(), nats.Timeout(time.Second)}
	// The agent key alone cannot open the private backend, even with valid TLS
	// server trust. The gateway presents a separate pinned TLS identity there.
	if c, err := nats.Connect(broker.WebsocketURL()+"/agent-channel", nats.Secure(&tls.Config{RootCAs: backendRoots}), nats.Nkey(devicePublic, deviceKey.Sign), nats.NoReconnect()); err == nil {
		c.Close()
		t.Fatal("direct backend bypassed gateway TLS identity")
	}
	worker, err := nats.Connect(broker.ClientURL(), nats.Nkey(workerPublic, workerKey.Sign), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	_, err = worker.Subscribe("uem.v1.agent.own.request.report", func(msg *nats.Msg) { _ = msg.Respond([]byte("accepted")) })
	if err != nil {
		t.Fatal(err)
	}
	if err = worker.FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{}, 1)
	options = append(options, nats.ClosedHandler(func(*nats.Conn) { closed <- struct{}{} }))
	client, err := nats.Connect(endpoint, options...)
	if err != nil {
		t.Fatal("individual key did not authenticate through gateway", err)
	}
	defer client.Close()
	request := func() {
		t.Helper()
		response, err := client.Request("uem.v1.agent.own.request.report", []byte("inventory"), time.Second)
		if err != nil || string(response.Data) != "accepted" {
			t.Fatal("proxied request failed", err)
		}
	}
	request()
	if other, err := nats.Connect(endpoint, options...); err == nil {
		other.Close()
		t.Fatal("agent connection limit was not enforced")
	}
	for _, path := range []string{"/agent-channel", "/agent-channel?token=secret", "/agent-channel/extra", "/login"} {
		response, err := frontend.Client().Get(frontend.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		want := 400
		if path == "/agent-channel/extra" || path == "/login" {
			want = 403
		}
		if response.StatusCode != want {
			t.Fatalf("%s: got %d want %d", path, response.StatusCode, want)
		}
	}
	// A long-lived stream must remain usable after the ordinary HTTP timeouts.
	<-time.After(1100 * time.Millisecond)
	request()
	if err = proxy.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("gateway shutdown left agent stream open")
	}
	if other, err := nats.Connect(endpoint, options...); err == nil {
		other.Close()
		t.Fatal("closing gateway accepted another stream")
	}
}

func TestAgentUpgradeRejectsBrowserCredentialsAndAmbiguousRequests(t *testing.T) {
	valid := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "https://uem.example/agent-channel", nil)
		r.Header.Set("Connection", "keep-alive, Upgrade")
		r.Header.Set("Upgrade", "websocket")
		r.Header.Set("Sec-WebSocket-Version", "13")
		r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
		return r
	}
	if !nativeWebSocket(valid()) {
		t.Fatal("valid native upgrade rejected")
	}
	for _, header := range []string{"Origin", "Cookie", "Authorization", "Proxy-Authorization", "Sec-WebSocket-Protocol"} {
		r := valid()
		r.Header.Set(header, "")
		if nativeWebSocket(r) {
			t.Fatal("forbidden native header accepted", header)
		}
	}
	for _, modify := range []func(*http.Request){
		func(r *http.Request) { r.Method = http.MethodPost },
		func(r *http.Request) { r.ProtoMajor = 2 },
		func(r *http.Request) { r.URL.RawQuery = "token=secret" },
		func(r *http.Request) { r.URL.ForceQuery = true },
		func(r *http.Request) { r.ContentLength = 1 },
		func(r *http.Request) { r.TransferEncoding = []string{"chunked"} },
		func(r *http.Request) { r.Header.Set("Connection", "keep-alive") },
		func(r *http.Request) { r.Header.Set("Upgrade", "h2c") },
		func(r *http.Request) { r.Header.Set("Sec-WebSocket-Key", "invalid") },
		func(r *http.Request) { r.Header.Add("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==") },
		func(r *http.Request) { r.Header.Add("Sec-WebSocket-Version", "13") },
		func(r *http.Request) { r.Header.Set("Sec-WebSocket-Version", "12") },
	} {
		r := valid()
		modify(r)
		if nativeWebSocket(r) {
			t.Fatal("ambiguous or invalid upgrade accepted")
		}
	}
}

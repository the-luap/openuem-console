package apple

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/gateway"
	"github.com/open-uem/openuem-console/internal/security/clientidentity"
	"howett.net/plist"
	"software.sslmate.com/src/go-pkcs12"
)

func TestCatalogTrustsAppleRootWithoutDisablingTLSVerification(t *testing.T) {
	client, err := catalogClient()
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	root, err := x509.ParseCertificate(appleCatalogRootDER)
	if err != nil {
		t.Fatal(err)
	}
	if digest(root.Raw) != "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024" {
		t.Fatal("unexpected catalog trust anchor; review the official Apple PKI source")
	}
	transport := client.Transport.(*http.Transport)
	if _, err = root.Verify(x509.VerifyOptions{Roots: transport.TLSClientConfig.RootCAs, CurrentTime: time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)}); err != nil {
		t.Fatal("Apple catalog root is not trusted", err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("catalog client accepted an unrelated self-signed server")
	}))
	server.Config.ErrorLog = slog.NewLogLogger(slog.NewTextHandler(io.Discard, nil), slog.LevelError)
	server.StartTLS()
	defer server.Close()
	response, err := client.Get(server.URL)
	if response != nil {
		response.Body.Close()
	}
	var verificationError *tls.CertificateVerificationError
	if !errors.As(err, &verificationError) {
		t.Fatal("catalog client did not reject untrusted TLS", err)
	}
}

func TestPublicProtocolRequiresIssuedIdentityOverTLS(t *testing.T) {
	t.Run("direct", func(t *testing.T) { testPublicProtocolIdentity(t, false) })
	t.Run("gateway", func(t *testing.T) { testPublicProtocolIdentity(t, true) })
}

func testPublicProtocolIdentity(t *testing.T, proxied bool) {
	s := testStore(t)
	settings := testSettings(t, s, 1)
	ctx := context.Background()
	invite, err := s.Invite(ctx, Scope{TenantID: 1, SiteID: 1}, "HTTP test", "admin")
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewUnstartedServer(s.ProtocolHandler(logger))
	server.TLS = &tls.Config{ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	if proxied {
		// A separately pinned TLS identity authenticates the gateway hop. It is not
		// an enrolled device and cannot substitute for a device identity.
		profileData, _, err := identityProfile(settings, "test-gateway", time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		var gatewayProfile map[string]any
		if _, err = plist.Unmarshal(profileData, &gatewayProfile); err != nil {
			t.Fatal(err)
		}
		identity := gatewayProfile["PayloadContent"].([]any)[0].(map[string]any)
		key, cert, _, err := pkcs12.DecodeChain(identity["PayloadContent"].([]byte), identity["Password"].(string))
		if err != nil {
			t.Fatal(err)
		}
		policy, err := clientidentity.FromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
		if err != nil {
			t.Fatal(err)
		}
		backend := httptest.NewUnstartedServer(s.ProtocolHandlerWithIdentity(logger, policy))
		backend.TLS = &tls.Config{}
		policy.ConfigureTLS(backend.TLS)
		backend.StartTLS()
		defer backend.Close()
		frontend := httptest.NewUnstartedServer(nil)
		roots := x509.NewCertPool()
		roots.AddCert(backend.Certificate())
		handler, err := gateway.New(gateway.Config{PublicOrigin: "https://" + frontend.Listener.Addr().String(), AppleURL: backend.URL, ConsoleURL: backend.URL, AuthURL: backend.URL, AdminNetworks: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, BackendTLS: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{{Certificate: [][]byte{cert.Raw}, PrivateKey: key}}}})
		if err != nil {
			t.Fatal(err)
		}
		frontend.Config.Handler = handler
		frontend.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
		frontend.StartTLS()
		defer frontend.Close()
		server = frontend
		response, err := backend.Client().Get(backend.URL + "/mdm/apple/enroll/" + strings.Repeat("a", 43))
		if response != nil {
			response.Body.Close()
		}
		if err == nil {
			t.Fatal("direct backend enrollment bypassed gateway")
		}
	}
	client := server.Client()
	token := invite.URL[strings.LastIndex(invite.URL, "/")+1:]
	if _, err = s.db.Exec(`UPDATE mdm_apple_settings SET public_url=$1 WHERE tenant_id=1`, server.URL); err != nil {
		t.Fatal(err)
	}
	address := server.URL + "/mdm/apple/enroll/" + token
	form := portalStart(t, client, address)
	response := portalPost(t, client, address, server.URL, form)
	portalRead(t, response)
	if response.StatusCode != 303 {
		t.Fatal("enrollment claim failed", response.StatusCode)
	}
	form.Set("action", "download")
	response = portalPost(t, client, address, server.URL, form)
	body := portalRead(t, response)
	if response.StatusCode != 200 {
		t.Fatal("enrollment failed", response.StatusCode, string(body))
	}
	var profile map[string]any
	if _, err = plist.Unmarshal(body, &profile); err != nil {
		t.Fatal(err)
	}
	identity := profile["PayloadContent"].([]any)[0].(map[string]any)
	key, cert, _, err := pkcs12.DecodeChain(identity["PayloadContent"].([]byte), identity["Password"].(string))
	if err != nil {
		t.Fatal(err)
	}
	message := map[string]any{"MessageType": "Authenticate", "UDID": "http-test-udid", "Topic": "com.apple.mgmt.test", "ProductName": "iPhone16,1", "OSVersion": "18.6"}
	payload, err := plist.Marshal(message, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPut, server.URL+"/mdm/apple/"+invite.DeviceID+"/checkin", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-SSL-Client-Cert", "forged certificate")
	request.Header.Set("Client-Cert", ":"+base64.StdEncoding.EncodeToString(cert.Raw)+":")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatal("request without TLS identity accepted", response.StatusCode)
	}
	transport := client.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: [][]byte{cert.Raw}, PrivateKey: key}}
	authenticated := &http.Client{Transport: transport}
	defer authenticated.CloseIdleConnections()
	request, err = http.NewRequest(http.MethodPut, server.URL+"/mdm/apple/"+invite.DeviceID+"/checkin", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	response, err = authenticated.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("valid TLS identity rejected", response.StatusCode)
	}
	response = portalPost(t, client, address, server.URL, form)
	portalRead(t, response)
	if response.StatusCode != 409 {
		t.Fatal("profile could be downloaded after device check-in", response.StatusCode)
	}
	message = map[string]any{"MessageType": "TokenUpdate", "UDID": "http-test-udid", "Topic": "com.apple.mgmt.test", "Token": []byte("test-token"), "PushMagic": "test-magic"}
	payload, err = plist.Marshal(message, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	request, _ = http.NewRequest(http.MethodPut, server.URL+"/mdm/apple/"+invite.DeviceID+"/checkin", bytes.NewReader(payload))
	response, err = authenticated.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("device registration failed", response.StatusCode)
	}
	response, err = client.Get(address)
	if err != nil {
		t.Fatal(err)
	}
	body = portalRead(t, response)
	if response.StatusCode != 200 || !bytes.Contains(body, []byte("Enrollment complete")) || bytes.Contains(body, []byte("type=\"submit\"")) {
		t.Fatal("browser did not observe completed enrollment", response.StatusCode)
	}
	savePortalArtifact(t, "enrolled", body)
}

func TestAPNsRequestAndErrorSemantics(t *testing.T) {
	fail := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/3/device/0123" || r.Header.Get("apns-topic") != "com.apple.mgmt.test" || r.Header.Get("apns-push-type") != "mdm" {
			t.Error("invalid APNs request")
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body["mdm"] != "magic" {
			t.Error("missing push magic")
		}
		if fail {
			w.WriteHeader(410)
			_, _ = w.Write([]byte(`{"reason":"Unregistered"}`))
		}
	}))
	defer server.Close()
	if err := Push(context.Background(), server.Client(), server.URL, "com.apple.mgmt.test", []byte{1, 35}, "magic"); err != nil {
		t.Fatal(err)
	}
	fail = true
	err := Push(context.Background(), server.Client(), server.URL, "com.apple.mgmt.test", []byte{1, 35}, "magic")
	p, ok := err.(*PushError)
	if !ok || p.Status != 410 || p.Reason != "Unregistered" {
		t.Fatal("APNs rejection treated as success", err)
	}
}

package apple

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
	s := testStore(t)
	testSettings(t, s, 1)
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
	client := server.Client()
	token := invite.URL[strings.LastIndex(invite.URL, "/")+1:]
	response, err := client.Get(server.URL + "/mdm/apple/enroll/" + token)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
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
	response, err = client.Get(server.URL + "/mdm/apple/enroll/" + token)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 404 {
		t.Fatal("one-time profile could be downloaded again")
	}
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

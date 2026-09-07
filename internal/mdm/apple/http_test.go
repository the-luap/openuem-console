package apple

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"howett.net/plist"
	"software.sslmate.com/src/go-pkcs12"
)

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

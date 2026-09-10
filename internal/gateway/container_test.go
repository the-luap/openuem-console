//go:build linux

package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/security/clientidentity"
)

// This fixture runs in the separate smoke image as the runtime's unprivileged
// UID, with a read-only root, bounded temporary storage and only loopback access.
// All credentials, listeners and child processes belong to this test.
func TestGatewayContainerProcess(t *testing.T) {
	binary := os.Getenv("OPENUEM_GATEWAY_TEST_BINARY")
	if binary == "" {
		t.Skip("requires the isolated gateway smoke image")
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("gateway test binary must be an absolute path")
	}
	if os.Geteuid() == 0 {
		t.Fatal("container fixture must exercise the unprivileged runtime user")
	}
	f := newPublicTLSFixture(t)
	first, second := f.issue(t, nil), f.issue(t, nil)
	f.publish(t, first)
	gatewayIdentity, gatewayPEM := testIdentity(t, "isolated-gateway")
	device, _ := testIdentity(t, "isolated-device")
	policy, err := clientidentity.FromPEM(gatewayPEM)
	if err != nil {
		t.Fatal(err)
	}
	backend := httptest.NewUnstartedServer(policy.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !policy.IsGateway(r) {
			t.Error("backend did not authenticate the dedicated gateway identity")
		}
		if r.URL.Path == "/mdm/apple/00000000-0000-4000-8000-000000000001/checkin" {
			certificate, err := policy.Certificate(r)
			if err != nil || !certificate.Equal(device.Leaf) {
				t.Error("actual TLS end-device identity was not preserved", err)
			}
		}
		_, _ = io.WriteString(w, "ready")
	})))
	backend.TLS = &tls.Config{Certificates: []tls.Certificate{f.issue(t, nil)}}
	policy.ConfigureTLS(backend.TLS)
	backend.StartTLS()
	t.Cleanup(backend.Close)
	directory := filepath.Dir(f.keyPath)
	gatewayCertPath, gatewayKeyPath := filepath.Join(directory, "gateway.pem"), filepath.Join(directory, "gateway-key.pem")
	rootPath := filepath.Join(directory, "backend-root.pem")
	writePublicTLSFile(t, gatewayCertPath, gatewayPEM)
	privateKey, err := x509.MarshalPKCS8PrivateKey(gatewayIdentity.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	writePublicTLSFile(t, gatewayKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKey}))
	writePublicTLSFile(t, rootPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.root.Raw}))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	origin := "https://" + address
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary,
		"--listen", address, "--public-origin", origin,
		"--tls-cert", f.certificatePath, "--tls-key", f.keyPath, "--tls-reload-interval", "1s",
		"--gateway-cert", gatewayCertPath, "--gateway-key", gatewayKeyPath, "--backend-ca", rootPath,
		"--apple-url", backend.URL, "--console-url", backend.URL, "--auth-url", backend.URL,
		"--desktop-url", backend.URL, "--windows-url", backend.URL,
		"--admin-networks", "127.0.0.1/32")
	var output gatewayProcessLog
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var waitError error
	go func() { waitError = command.Wait(); close(done) }()
	defer func() {
		select {
		case <-done:
			return
		default:
		}
		_ = command.Process.Kill()
		<-done
	}()
	client := publicTLSClient(t, f.clientTLS(), true)
	waitFor := func(description string, check func() bool) {
		t.Helper()
		deadline := time.NewTimer(5 * time.Second)
		defer deadline.Stop()
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for {
			if check() {
				return
			}
			select {
			case <-done:
				t.Fatalf("gateway exited during %s: %v; %s", description, waitError, output.String())
			case <-deadline.C:
				t.Fatalf("gateway did not complete %s; %s", description, output.String())
			case <-tick.C:
			}
		}
	}
	waitFor("initial TLS admission", func() bool {
		response, err := client.Get(origin + "/login")
		if err != nil {
			return false
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		return err == nil && string(body) == "ready" && response.StatusCode == http.StatusOK && response.ProtoMajor == 2
	})
	// A second loopback source is outside the sole approved administrator prefix.
	// Its forged forwarding headers must not open private console routes.
	publicConfig := f.clientTLS()
	publicConfig.Certificates = []tls.Certificate{device}
	external := publicTLSClient(t, publicConfig, false)
	external.Transport.(*http.Transport).DialContext = (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}}).DialContext
	for _, path := range []string{"/login", "/tenant/1/computers", "/auth", "/deploy"} {
		request, err := http.NewRequest(http.MethodGet, origin+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("X-Forwarded-For", "127.0.0.1")
		response, err := external.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Fatal("external administration was not denied", path, response.StatusCode)
		}
	}
	request, err := http.NewRequest(http.MethodPut, origin+"/mdm/apple/00000000-0000-4000-8000-000000000001/checkin", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := external.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatal("public device route did not reach its pinned backend", response.StatusCode)
	}
	for _, path := range []string{"/EnrollmentServer/Discovery.svc", "/enroll/desktop/bootstrap-keys"} {
		getPublicTLS(t, external, origin+path)
	}
	// Exercise the actual command's scheduled watcher, without calling Reload.
	f.publish(t, second)
	waitFor("scheduled public certificate renewal", func() bool {
		response, err := external.Get(origin + "/EnrollmentServer/Discovery.svc")
		if err != nil {
			return false
		}
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		return response.TLS.PeerCertificates[0].Equal(second.Leaf)
	})
	response = getPublicTLS(t, client, origin+"/login")
	if !response.TLS.PeerCertificates[0].Equal(first.Leaf) {
		t.Fatal("scheduled renewal interrupted the original HTTP/2 connection")
	}
	writePublicTLSFile(t, f.keyPath, []byte("interrupted publication"))
	waitFor("rejected partial publication", func() bool { return bytes.Contains([]byte(output.String()), []byte("public TLS reload rejected")) })
	response = getPublicTLS(t, external, origin+"/EnrollmentServer/Discovery.svc")
	if !response.TLS.PeerCertificates[0].Equal(second.Leaf) {
		t.Fatal("partial publication replaced the current certificate")
	}
	f.publish(t, second)
	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
		if waitError != nil {
			t.Fatal("SIGTERM did not shut down and join the gateway workers", waitError, output.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SIGTERM did not finish gateway shutdown")
	}
}

// Capture only bounded synthetic process diagnostics; concurrent polling must
// not race with os/exec's stdout/stderr writers.
type gatewayProcessLog struct {
	mu   sync.Mutex
	data []byte
}

func (l *gatewayProcessLog) Write(data []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	length := len(data)
	if available := (16 << 10) - len(l.data); available > 0 {
		if len(data) > available {
			data = data[:available]
		}
		l.data = append(l.data, data...)
	}
	return length, nil
}

func (l *gatewayProcessLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return string(l.data)
}

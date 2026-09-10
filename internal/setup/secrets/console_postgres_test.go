//go:build linux

package secrets_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/open-uem/nats/enrollment/keyfile"
	"github.com/open-uem/openuem-console/internal/setup/secrets"
)

func TestInstallationSecretsDatabasePostgresConsole(t *testing.T) {
	binary := os.Getenv("OPENUEM_CONSOLE_TEST_BINARY")
	if binary == "" {
		t.Skip("requires the console distribution executable and its runtime mounts")
	}
	if os.Getenv("OPENUEM_DATABASE_TEST_PRIVATE_PKI") == "" || filepath.Dir(binary) != "/" || os.Geteuid() == 0 {
		t.Fatal("console process fixture requires private PKI, a root-level executable and a non-root runtime")
	}
	brokerBinary := os.Getenv("OPENUEM_DATABASE_TEST_BROKER")
	if brokerBinary == "" {
		t.Fatal("console process fixture requires the stock broker distribution executable")
	}
	installationDirectory := filepath.Join(t.TempDir(), "installation")
	installation, err := secrets.Initialize(t.Context(), installationDirectory)
	if err != nil {
		t.Fatal("cannot prepare protected console credentials", err)
	}
	f := startDatabaseFixtureForInstallation(t, true, installation.Installation)
	bootstrapFixture(t, f)
	pki := filepath.Join(f.root, "private-pki")
	allocatePort := func() string {
		t.Helper()
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal("cannot allocate a private console fixture port")
		}
		defer listener.Close()
		return strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	}
	brokerPort, websocketPort := allocatePort(), allocatePort()
	consolePort, authPort := allocatePort(), allocatePort()
	brokerDirectory := filepath.Join(f.root, "broker")
	initialize := exec.CommandContext(f.ctx, os.Getenv("OPENUEM_DATABASE_TEST_PRIVATE_PKI"), "individual-broker",
		"--directory", brokerDirectory, "--listen", "127.0.0.1:"+brokerPort, "--websocket-listen", "127.0.0.1:"+websocketPort,
		"--tls-cert", filepath.Join(pki, "broker/server.pem"), "--tls-key", filepath.Join(pki, "broker/server.key"),
		"--gateway-ca", filepath.Join(pki, "broker/gateway-leaves.pem"), "--store-directory", filepath.Join(f.root, "jetstream"))
	initialize.Stdout, initialize.Stderr = io.Discard, io.Discard
	if initialize.Run() != nil {
		t.Fatal("production individual broker initialization failed")
	}
	seed, err := keyfile.Read(filepath.Join(brokerDirectory, "provisioner-user.seed"), 512)
	if err != nil {
		t.Fatal("cannot read the private broker provisioning identity")
	}
	provisioner, err := nkeys.FromSeed(seed)
	clear(seed)
	if err != nil {
		t.Fatal("private broker provisioning identity is invalid")
	}
	defer provisioner.Wipe()
	provisionerPublic, _ := provisioner.PublicKey()
	startBroker := func() func() {
		return startConsoleFixtureProcess(t, f.ctx, "broker", brokerBinary,
			[]string{"--config", filepath.Join(brokerDirectory, "broker.json")}, []string{"GOMAXPROCS=2"}, f.root)
	}
	awaitBroker := func() *nats.Conn {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
			connection, err := nats.Connect("tls://nats.internal:"+brokerPort,
				nats.RootCAs(filepath.Join(pki, "trust/backend-ca.pem")),
				nats.Nkey(provisionerPublic, provisioner.Sign), nats.NoReconnect(), nats.Timeout(500*time.Millisecond))
			if err == nil {
				return connection
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal("stock broker did not accept the private TLS provisioning identity")
		return nil
	}
	stopBroker := startBroker()
	brokerConnection := awaitBroker()
	stream, err := brokerConnection.JetStream()
	if err != nil {
		brokerConnection.Close()
		t.Fatal("stock broker did not expose the private JetStream service")
	}
	_, err = stream.AddStream(&nats.StreamConfig{Name: "AGENTS_STREAM", Subjects: []string{"agent.>"}, Storage: nats.FileStorage})
	brokerConnection.Close()
	if err != nil {
		t.Fatal("stock broker rejected authorized command stream provisioning")
	}
	// Administrator certificate trust is deliberately a separate synthetic CA.
	// This fixture verifies password login; it does not claim administrator PKI
	// issuance, OCSP integration or physical device acceptance.
	adminDirectory := t.TempDir()
	administratorCA, _, _ := databaseTLS(t, adminDirectory)
	origin := "https://console.internal:" + consolePort
	startupRequests := make(chan struct{}, 4)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodConnect {
			http.Error(w, "unexpected fixture request", http.StatusBadRequest)
			return
		}
		select {
		case startupRequests <- struct{}{}:
		default:
		}
		// Hold the initial public catalog connection open without sending any
		// traffic outside this loopback fixture. Shutdown must cancel this wait.
		<-request.Context().Done()
	}))
	t.Cleanup(proxy.Close)
	awaitStartupCheck := func() {
		t.Helper()
		select {
		case <-startupRequests:
		case <-time.After(5 * time.Second):
			t.Fatal("console did not enter the controlled startup catalog request")
		}
	}
	environment := []string{
		"GOMAXPROCS=2", "HOME=" + f.root, "HTTPS_PROXY=" + proxy.URL,
		"OPENUEM_INDIVIDUAL_AGENT_MODE=true", "OPENUEM_AGENT_BROKER_URLS=tls://nats.internal:" + brokerPort,
		"OPENUEM_AGENT_CONSOLE_KEY_FILE=" + filepath.Join(brokerDirectory, "console-user.seed"),
		"OPENUEM_AGENT_BROKER_CA_FILE=" + filepath.Join(pki, "trust/backend-ca.pem"),
		"OPENUEM_TRUSTED_GATEWAY_CERTIFICATES=" + filepath.Join(pki, "console/gateway-leaves.pem"),
		"OPENUEM_INSTALLATION_ID=" + installation.Installation, "OPENUEM_BOOTSTRAP_ADMIN=first-admin",
		"OPENUEM_BOOTSTRAP_PASSWORD_FILE=" + filepath.Join(installationDirectory, secrets.PasswordFile),
		"JWT_KEY_FILE=" + filepath.Join(installationDirectory, secrets.JWTFile),
		"ENCRYPTION_MASTER_KEY_FILE=" + filepath.Join(installationDirectory, secrets.MasterFile),
		"DATABASE_URL_FILE=" + filepath.Join(f.directory, secrets.DatabaseURLFile), "OPENUEM_PUBLIC_ORIGIN=" + origin,
	}
	arguments := []string{"start", "--domain", "example.test", "--org-name", "Fixture", "--server-name", "console.internal",
		"--console-port", consolePort, "--auth-port", authPort, "--cacert", administratorCA,
		"--cert", filepath.Join(pki, "console/server.pem"), "--key", filepath.Join(pki, "console/server.key")}
	startConsole := func() func() {
		return startConsoleFixtureProcess(t, f.ctx, "console", binary, arguments, environment, f.root)
	}
	certificate, err := tls.LoadX509KeyPair(filepath.Join(pki, "gateway/client.pem"), filepath.Join(pki, "gateway/client.key"))
	if err != nil {
		t.Fatal("cannot load the private gateway fixture identity")
	}
	ca, err := os.ReadFile(filepath.Join(pki, "trust/backend-ca.pem"))
	roots := x509.NewCertPool()
	if err != nil || !roots.AppendCertsFromPEM(ca) {
		t.Fatal("cannot load private backend trust")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{certificate}}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Transport: transport, Jar: jar, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request := func(path string, form url.Values) (int, string) {
		t.Helper()
		method := http.MethodGet
		var body io.Reader
		if form != nil {
			method = http.MethodPost
			body = strings.NewReader(form.Encode())
		}
		req, _ := http.NewRequestWithContext(f.ctx, method, origin+path, body)
		req.Header.Set("Accept-Language", "en")
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Origin", origin)
			for _, cookie := range jar.Cookies(req.URL) {
				if cookie.Name == "__Host-openuem-csrf" {
					req.Header.Set("X-CSRF-Token", cookie.Value)
				}
			}
		}
		response, err := client.Do(req)
		if err != nil {
			return 0, ""
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 512<<10))
		if err != nil {
			t.Fatal("console response could not be read")
		}
		return response.StatusCode, string(data)
	}
	awaitLogin := func() {
		t.Helper()
		deadline := time.Now().Add(25 * time.Second)
		for time.Now().Before(deadline) {
			if status, body := request("/login", nil); status == http.StatusOK && strings.Contains(body, `name="username"`) {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal("actual console did not serve its English login form through private gateway TLS")
	}
	stop := startConsole()
	awaitLogin()
	awaitStartupCheck()
	if status, body := request("/assets/js/vendor/pako/LICENSE", nil); status != http.StatusOK || !strings.Contains(body, "Permission is hereby granted") {
		t.Fatal("console distribution assets are unavailable")
	}
	var authResponse *http.Response
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		authResponse, err = client.Get("https://console.internal:" + authPort + "/auth")
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil || authResponse == nil {
		t.Fatal("authentication backend did not accept the pinned gateway transport")
	}
	authResponse.Body.Close()
	if authResponse.StatusCode != http.StatusUnauthorized {
		t.Fatal("gateway transport alone supplied an administrator certificate identity")
	}
	for _, port := range []string{consolePort, authPort} {
		connection, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", "127.0.0.1:"+port,
			&tls.Config{RootCAs: roots, ServerName: "console.internal"})
		if err == nil {
			// TLS 1.3 alerts can arrive on the first application read.
			_, _ = connection.Write([]byte("GET /login HTTP/1.1\r\nHost: console.internal\r\nConnection: close\r\n\r\n"))
			_ = connection.SetReadDeadline(time.Now().Add(time.Second))
			var data [1024]byte
			count, _ := connection.Read(data[:])
			connection.Close()
			if count > 0 {
				t.Fatal("direct client without the pinned gateway reached a console backend")
			}
		}
	}
	password, err := os.ReadFile(filepath.Join(installationDirectory, secrets.PasswordFile))
	if err != nil {
		t.Fatal("cannot read the synthetic initial password")
	}
	defer clear(password)
	if status, body := request("/login/userpass", url.Values{"username": {"first-admin"}, "password": {string(password)}}); status != http.StatusOK || !strings.Contains(body, "confirm-password") || strings.Contains(body, string(password)) {
		t.Fatal("first console login did not require protected password replacement")
	}
	newPassword := "Updated-Fixture-Administrator-Password-123!"
	if status, body := request("/login/changepass", url.Values{"password": {newPassword}, "confirm-password": {newPassword}}); status != http.StatusOK || !strings.Contains(body, `name="username"`) {
		t.Fatal("actual console did not accept first-password replacement")
	}
	db, err := sql.Open("pgx", f.connection)
	if err != nil {
		t.Fatal("cannot verify retained console state")
	}
	defer db.Close()
	var hash, state, recordedID string
	if err := db.QueryRowContext(f.ctx, `SELECT hash,register FROM users WHERE uid='first-admin'`).Scan(&hash, &state); err != nil {
		t.Fatal("console administrator verification query failed")
	}
	if state != "users.completed" {
		t.Fatal("console administrator has an unexpected completion state", state)
	}
	if match, err := argon2id.ComparePasswordAndHash(newPassword, hash); err != nil || !match {
		t.Fatal("actual console persisted an unexpected administrator credential")
	}
	if err := db.QueryRowContext(f.ctx, `SELECT installation FROM uem_installation_secrets`).Scan(&recordedID); err != nil || recordedID != installation.Installation {
		t.Fatal("console lost the generated installation binding")
	}
	stop()
	stopBroker()
	stopBroker = startBroker()
	brokerConnection = awaitBroker()
	stream, err = brokerConnection.JetStream()
	if err != nil {
		brokerConnection.Close()
		t.Fatal("restarted broker did not expose JetStream")
	}
	info, err := stream.StreamInfo("AGENTS_STREAM")
	brokerConnection.Close()
	if err != nil || info.Config.Storage != nats.FileStorage {
		t.Fatal("stock broker restart did not retain its provisioned command stream")
	}
	stop = startConsole()
	awaitLogin()
	awaitStartupCheck()
	var retained string
	if err := db.QueryRowContext(f.ctx, `SELECT hash FROM users WHERE uid='first-admin'`).Scan(&retained); err != nil || retained != hash {
		t.Fatal("console restart reset the administrator credential")
	}
	stop()
	stopBroker()
}

func startConsoleFixtureProcess(t *testing.T, parent context.Context, name, binary string, arguments, environment []string, directory string) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(parent)
	command := exec.CommandContext(ctx, binary, arguments...)
	command.Env, command.Dir = environment, directory
	command.Stdout, command.Stderr = io.Discard, io.Discard
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	command.WaitDelay = 5 * time.Second
	if command.Start() != nil {
		cancel()
		t.Fatal(name, "distribution process could not start")
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	stopped := false
	t.Cleanup(func() {
		cancel()
		if !stopped {
			<-done
		}
	})
	return func() {
		t.Helper()
		cancel()
		err := <-done
		stopped = true
		if err != nil && !errors.Is(err, context.Canceled) || command.ProcessState == nil || !command.ProcessState.Success() {
			t.Fatal(name, "did not complete graceful SIGTERM shutdown")
		}
	}
}

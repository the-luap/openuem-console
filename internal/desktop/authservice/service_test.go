package authservice

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/keyfile"
	"github.com/open-uem/nats/enrollment/registry"
)

func writeKey(t *testing.T, key nkeys.KeyPair) string {
	t.Helper()
	seed, err := key.Seed()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(seed)
	path := filepath.Join(t.TempDir(), "service.seed")
	if err = os.WriteFile(path, seed, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestConfigurationRejectsPublicListenersAndCredentialBearingURLs(t *testing.T) {
	for _, value := range []string{"", "nats://localhost:4222", "tls://user:secret@localhost:4222", "tls://localhost/path", "tls://localhost?secret=x", "tls://localhost?", "tls://localhost#x", "tls://localhost,", strings.Repeat("tls://localhost,", 16) + "tls://localhost"} {
		if privateBrokerURLs(value) {
			t.Fatalf("accepted unsafe broker URL %q", value)
		}
	}
	if !privateBrokerURLs("tls://broker.internal:4222,tls://[::1]:4222") {
		t.Fatal("valid private TLS origins were rejected")
	}
	for _, address := range []string{"0.0.0.0:1326", "[::]:1326", "192.0.2.1:1326", "localhost:1326"} {
		err := Run(context.Background(), Config{DatabaseURL: "postgres://example", BrokerURLs: "tls://localhost", HealthAddress: address}, nil)
		if err == nil || err.Error() != "health listener must use a loopback IP address" {
			t.Fatal("non-loopback listener was not rejected before loading keys", err)
		}
	}
}

func TestServiceKeysEnforceTypeAndPrivateFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows ACL behavior is exercised by the keyfile package on Windows CI")
	}
	user, _ := nkeys.CreateUser()
	path := writeKey(t, user)
	read, err := readKey(path, false)
	if err != nil {
		t.Fatal(err)
	}
	read.Wipe()
	if _, err = readKey(path, true); err == nil {
		t.Fatal("user key accepted as authorization issuer")
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = readKey(path, false); err == nil {
		t.Fatal("world-readable service seed accepted")
	}
}

func registryFixture(t *testing.T) (*registry.Store, *sql.DB, string) {
	t.Helper()
	dsn := os.Getenv("AGENT_ENROLLMENT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set AGENT_ENROLLMENT_TEST_DATABASE_URL for PostgreSQL lifecycle tests")
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "agent_authservice_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`); err != nil {
			t.Error(err)
		}
		admin.Close()
	})
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	db, err := sql.Open("pgx", u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err = db.Exec(`CREATE TABLE tenants(id BIGINT PRIMARY KEY); CREATE TABLE sites(id BIGINT PRIMARY KEY,tenant_sites BIGINT NOT NULL REFERENCES tenants(id)); INSERT INTO tenants VALUES(1); INSERT INTO sites VALUES(1,1)`); err != nil {
		t.Fatal(err)
	}
	store, err := registry.NewStore(db, "isolated-authservice-integration-master")
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err = store.EnsureAuthority(context.Background(), 1, "Test organization", "https://uem.example.test", "test-admin", nil, nil); err != nil {
		t.Fatal(err)
	}
	return store, db, u.String()
}

func TestRunAuthorizesAndDisconnectsDurableIdentityOverTLS(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("service lifecycle runs on Linux with PostgreSQL; Windows ACLs have separate native tests")
	}
	store, db, dsn := registryFixture(t)
	ctx := context.Background()
	invitation, err := store.Invite(ctx, registry.InvitationOptions{Scope: registry.Scope{TenantID: 1, SiteID: 1}, Platform: "windows", Architecture: "amd64", MaxUses: 1, ExpiresAt: time.Now().Add(time.Hour)}, "test-admin")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := enrollment.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	request, err := keys.Request(invitation.URL[strings.LastIndex(invitation.URL, "/")+1:], "windows", "amd64", "Test endpoint")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := store.Claim(ctx, *request)
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := nkeys.CreateAccount()
	issuer, _ := signer.PublicKey()
	authKey, _ := nkeys.CreateUser()
	authPublic, _ := authKey.PublicKey()
	systemKey, _ := nkeys.CreateUser()
	systemPublic, _ := systemKey.PublicKey()
	authAccount, devices, systemAccount := server.NewAccount("UEM_AUTH"), server.NewAccount("UEM_DEVICES"), server.NewAccount("UEM_SYSTEM")
	certServer := httptest.NewTLSServer(http.NotFoundHandler())
	certificate := certServer.TLS.Certificates[0]
	rootCertificate := certServer.Certificate()
	certServer.Close()
	caPath := filepath.Join(t.TempDir(), "broker-ca.pem")
	if err = os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCertificate.Raw}), 0644); err != nil {
		t.Fatal(err)
	}
	broker, err := server.NewServer(&server.Options{
		Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12},
		Websocket: server.WebsocketOpts{Host: "127.0.0.1", Port: -1, TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}},
		Accounts:  []*server.Account{authAccount, devices, systemAccount}, SystemAccount: "UEM_SYSTEM",
		Nkeys: []*server.NkeyUser{
			{Nkey: authPublic, Account: authAccount, Permissions: &server.Permissions{Publish: &server.SubjectPermission{Deny: []string{">"}}, Subscribe: &server.SubjectPermission{Allow: []string{enrollment.AuthorizationSubject}}, Response: &server.ResponsePermission{MaxMsgs: 1, Expires: time.Second}}},
			{Nkey: systemPublic, Account: systemAccount, Permissions: &server.Permissions{Publish: &server.SubjectPermission{Allow: []string{"$SYS.REQ.SERVER.*.KICK"}}, Subscribe: &server.SubjectPermission{Allow: []string{"_INBOX.>"}}}},
		},
		AuthCallout: &server.AuthCallout{Issuer: issuer, Account: "UEM_AUTH", AuthUsers: []string{authPublic}, AllowedAccounts: []string{"UEM_DEVICES"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	broker.Start()
	t.Cleanup(func() { broker.Shutdown(); broker.WaitForShutdown() })
	if !broker.ReadyForConnections(5 * time.Second) {
		t.Fatal("TLS broker did not start")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	databaseFile := filepath.Join(t.TempDir(), "database.url")
	if keyfile.Create(databaseFile, []byte(dsn+"\n")) != nil {
		t.Fatal("cannot create protected database URL")
	}
	config := Config{DatabaseURLFile: databaseFile, BrokerURLs: broker.ClientURL(), BrokerCAFile: caPath, IssuerKeyFile: writeKey(t, signer), AuthKeyFile: writeKey(t, authKey), SystemKeyFile: writeKey(t, systemKey), DeviceAccount: "UEM_DEVICES", HealthAddress: address}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// A trusted name alone must not bypass TLS verification, even with valid NKeys.
	untrusted := config
	untrusted.BrokerCAFile = ""
	if err = Run(ctx, untrusted, logger); err == nil || err.Error() != "private broker connection failed" {
		t.Fatal("untrusted TLS broker was not rejected", err)
	}
	serviceCtx, cancel := context.WithCancel(ctx)
	result := make(chan error, 1)
	go func() { result <- runAuthorizationFixture(serviceCtx, config, logger) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-result:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(8 * time.Second):
			t.Error("authorization service did not stop")
		}
	})
	healthClient := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(8 * time.Second)
	for {
		response, err := healthClient.Get("http://" + address + "/healthz")
		if err == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusNoContent {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("authorization service never became healthy")
		}
		time.Sleep(20 * time.Millisecond)
	}
	roots := x509.NewCertPool()
	roots.AddCert(rootCertificate)
	public, _ := keys.Broker.PublicKey()
	prefix, _ := enrollment.ReplyPrefix(issued.DeviceID)
	closed := make(chan struct{}, 1)
	options := []nats.Option{nats.Nkey(public, keys.Broker.Sign), nats.CustomInboxPrefix(prefix), nats.Secure(&tls.Config{RootCAs: roots}), nats.NoReconnect()}
	client, err := nats.Connect(broker.WebsocketURL()+"/agent-channel", append(options, nats.ClosedHandler(func(*nats.Conn) { closed <- struct{}{} }))...)
	if err != nil {
		t.Fatal("individual identity was rejected by running service", err)
	}
	defer client.Close()
	var sessions int
	if err = db.QueryRow(`SELECT count(*) FROM uem_agent_broker_sessions WHERE device_id=$1`, issued.DeviceID).Scan(&sessions); err != nil || sessions != 1 {
		t.Fatal("authorization did not persist the actual broker connection", err)
	}
	if err = store.RevokeIdentity(ctx, registry.Scope{TenantID: 1}, issued.DeviceID, "test-admin"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
	case <-time.After(8 * time.Second):
		t.Fatal("running service did not disconnect revoked identity")
	}
	if retry, err := nats.Connect(broker.WebsocketURL()+"/agent-channel", options...); err == nil {
		retry.Close()
		t.Fatal("revoked identity reconnected")
	}
	// Losing the broker must also withdraw readiness while reconnection is pending.
	broker.Shutdown()
	broker.WaitForShutdown()
	deadline = time.Now().Add(3 * time.Second)
	for {
		response, err := healthClient.Get("http://" + address + "/healthz")
		if err == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusServiceUnavailable {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("readiness did not reflect the broker outage")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

package commandservice

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
	openuem "github.com/open-uem/nats"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/keyfile"
	"github.com/open-uem/nats/enrollment/registry"
)

func commandRegistry(t *testing.T) (*registry.Store, *sql.DB, string) {
	t.Helper()
	dsn := os.Getenv("AGENT_ENROLLMENT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set AGENT_ENROLLMENT_TEST_DATABASE_URL for command service integration")
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "command_service_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	store, err := registry.NewStore(db, "isolated-command-service-master-key")
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

func TestCommandServiceRunsGeneratedBrokerConfigAndDurableReconciliation(t *testing.T) {
	store, db, dsn := commandRegistry(t)
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
	directory := t.TempDir()
	certServer := httptest.NewTLSServer(http.NotFoundHandler())
	certificate := certServer.TLS.Certificates[0]
	root := certServer.Certificate()
	certServer.Close()
	certPath, keyPath := filepath.Join(directory, "broker.pem"), filepath.Join(directory, "broker.key")
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})
	if err = os.WriteFile(certPath, certificatePEM, 0644); err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = keyfile.Create(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})); err != nil {
		t.Fatal(err)
	}
	freeAddress := func() string {
		t.Helper()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address := listener.Addr().String()
		listener.Close()
		return address
	}
	issuerKey, _ := nkeys.CreateAccount()
	issuer, _ := issuerKey.PublicKey()
	users, public := make([]nkeys.KeyPair, 5), make([]string, 5)
	for i := range users {
		users[i], _ = nkeys.CreateUser()
		public[i], _ = users[i].PublicKey()
	}
	seed, _ := users[4].Seed()
	seedPath := filepath.Join(directory, "provisioner.seed")
	if err = keyfile.Create(seedPath, seed); err != nil {
		t.Fatal(err)
	}
	brokerConfig := enrollment.BrokerConfiguration{Name: "command-service-test", Listen: freeAddress(), WebsocketListen: freeAddress(), CertificateFile: certPath, KeyFile: keyPath, GatewayCAFile: certPath, StoreDirectory: filepath.Join(directory, "jetstream"), Issuer: issuer, AuthorizationUser: public[0], RevocationUser: public[1], WorkerUser: public[2], ConsoleUser: public[3], ProvisionerUser: public[4]}
	encoded, err := brokerConfig.Render()
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "broker.json")
	if err = os.WriteFile(configPath, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	options, err := server.ProcessConfigFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	options.NoLog, options.NoSigs = true, true
	broker, err := server.NewServer(options)
	if err != nil {
		t.Fatal(err)
	}
	broker.Start()
	t.Cleanup(func() { broker.Shutdown(); broker.WaitForShutdown() })
	if !broker.ReadyForConnections(5 * time.Second) {
		t.Fatal("configured broker did not start")
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	monitor, err := nats.Connect(broker.ClientURL(), nats.Nkey(public[4], users[4].Sign), nats.Secure(&tls.Config{RootCAs: roots}), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	defer monitor.Close()
	js, err := jetstream.New(monitor)
	if err != nil {
		t.Fatal(err)
	}
	healthAddress := freeAddress()
	serviceContext, stop := context.WithCancel(ctx)
	result := make(chan error, 1)
	go func() {
		result <- Run(serviceContext, Config{DatabaseURL: dsn, HealthAddress: healthAddress, Broker: openuem.ServiceConnection{Servers: broker.ClientURL(), KeyFile: seedPath, CAFile: certPath}}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()
	t.Cleanup(func() {
		stop()
		select {
		case err := <-result:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(8 * time.Second):
			t.Error("command service did not stop")
		}
	})
	waitFor := func(description string, condition func() bool) {
		t.Helper()
		deadline := time.Now().Add(8 * time.Second)
		for !condition() {
			if time.Now().After(deadline) {
				t.Fatal(description)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	healthClient := &http.Client{Timeout: time.Second}
	healthStatus := func() int {
		response, err := healthClient.Get("http://" + healthAddress + "/healthz")
		if err != nil {
			return 0
		}
		defer response.Body.Close()
		return response.StatusCode
	}
	waitFor("command service never became ready", func() bool { return healthStatus() == http.StatusNoContent })
	name, _ := enrollment.ConsumerName(issued.DeviceID)
	if _, err = js.Consumer(ctx, "AGENTS_STREAM", name); err != nil {
		t.Fatal("ready service had not provisioned the durable device consumer", err)
	}
	// Reconciliation also repairs broker state lost after the database ack.
	if err = js.DeleteConsumer(ctx, "AGENTS_STREAM", name); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE uem_agent_command_consumers SET attempted_at=NULL,reconcile_at=clock_timestamp()-INTERVAL '1 second'`); err != nil {
		t.Fatal(err)
	}
	waitFor("lost consumer was not recreated", func() bool { _, err := js.Consumer(ctx, "AGENTS_STREAM", name); return err == nil })
	if err = store.RevokeIdentity(ctx, registry.Scope{TenantID: 1}, issued.DeviceID, "test-admin"); err != nil {
		t.Fatal(err)
	}
	waitFor("revoked consumer was not deleted", func() bool {
		_, err := js.Consumer(ctx, "AGENTS_STREAM", name)
		return errors.Is(err, jetstream.ErrConsumerNotFound)
	})
	broker.Shutdown()
	broker.WaitForShutdown()
	waitFor("broker outage did not withdraw readiness", func() bool { return healthStatus() == http.StatusServiceUnavailable })
}

func TestCommandServiceRejectsPublicHealthListener(t *testing.T) {
	for _, address := range []string{"0.0.0.0:1327", "[::]:1327", "192.0.2.1:1327", "localhost:1327"} {
		err := Run(context.Background(), Config{HealthAddress: address}, nil)
		if err == nil || err.Error() != "command service health listener must use a loopback IP address" {
			t.Fatal("non-loopback health listener accepted", err)
		}
	}
}

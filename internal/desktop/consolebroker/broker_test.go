package consolebroker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
	openuem "github.com/open-uem/nats"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/keyfile"
)

func TestEnvironment(t *testing.T) {
	t.Setenv("OPENUEM_INDIVIDUAL_AGENT_MODE", "true")
	t.Setenv("OPENUEM_AGENT_BROKER_URLS", "tls://broker.internal:4222")
	t.Setenv("OPENUEM_AGENT_CONSOLE_KEY_FILE", "/private/console.seed")
	t.Setenv("OPENUEM_AGENT_BROKER_CA_FILE", "/trust/backend.pem")
	t.Setenv("OPENUEM_AGENT_BROKER_CLIENT_CERT_FILE", "")
	t.Setenv("OPENUEM_AGENT_BROKER_CLIENT_KEY_FILE", "")
	if config, err := FromEnvironment(); err != nil || config == nil {
		t.Fatal(config, err)
	}
	for _, tc := range []struct{ key, value string }{
		{"OPENUEM_INDIVIDUAL_AGENT_MODE", "TRUE"},
		{"OPENUEM_INDIVIDUAL_AGENT_MODE", " true"},
		{"OPENUEM_AGENT_BROKER_URLS", "nats://broker.internal:4222"},
		{"OPENUEM_AGENT_BROKER_URLS", "wss://broker.internal:443"},
		{"OPENUEM_AGENT_BROKER_URLS", "tls://user:secret@broker.internal:4222"},
		{"OPENUEM_AGENT_BROKER_URLS", "tls://broker.internal:4222/path"},
		{"OPENUEM_AGENT_BROKER_URLS", ""},
		{"OPENUEM_AGENT_CONSOLE_KEY_FILE", ""},
		{"OPENUEM_AGENT_BROKER_CA_FILE", ""},
		{"OPENUEM_AGENT_BROKER_CLIENT_CERT_FILE", "/unpaired.pem"},
		{"OPENUEM_AGENT_BROKER_CLIENT_KEY_FILE", "/unpaired.key"},
	} {
		t.Run(tc.key+tc.value, func(t *testing.T) {
			t.Setenv(tc.key, tc.value)
			if config, err := FromEnvironment(); err == nil || config != nil {
				t.Fatal("invalid mode accepted", config, err)
			}
		})
	}
	for _, mode := range []string{"", "false"} {
		t.Setenv("OPENUEM_INDIVIDUAL_AGENT_MODE", mode)
		if config, err := FromEnvironment(); err != nil || config != nil {
			t.Fatal("legacy selection changed", config, err)
		}
	}
}

func TestGeneratedBrokerPermissionsAndReconnect(t *testing.T) {
	directory := t.TempDir()
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	certificate, root := fixture.TLS.Certificates[0], fixture.Certificate()
	fixture.Close()
	write := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(directory, name)
		if err := keyfile.Create(path, data); err != nil {
			t.Fatal(err)
		}
		return path
	}
	certPath := write("broker.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}))
	private, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := write("broker.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
	freeAddress := func() string {
		t.Helper()
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		return l.Addr().String()
	}
	issuerKey, _ := nkeys.CreateAccount()
	defer issuerKey.Wipe()
	issuer, _ := issuerKey.PublicKey()
	var users [5]nkeys.KeyPair
	var public [5]string
	for i := range users {
		users[i], _ = nkeys.CreateUser()
		defer users[i].Wipe()
		public[i], _ = users[i].PublicKey()
	}
	seed, _ := users[3].Seed()
	seedPath := write("console.seed", seed)
	clear(seed)
	config := enrollment.BrokerConfiguration{Name: "console-test", Listen: freeAddress(), WebsocketListen: freeAddress(), CertificateFile: certPath, KeyFile: keyPath, GatewayCAFile: certPath, StoreDirectory: filepath.Join(directory, "jetstream"), Issuer: issuer, AuthorizationUser: public[0], RevocationUser: public[1], WorkerUser: public[2], ConsoleUser: public[3], ProvisionerUser: public[4]}
	encoded, err := config.Render()
	if err != nil {
		t.Fatal(err)
	}
	configPath := write("broker.json", encoded)
	start := func() *server.Server {
		t.Helper()
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
			t.Fatal("broker did not start")
		}
		return broker
	}
	broker := start()
	connectionConfig := openuem.ServiceConnection{Servers: "tls://" + config.Listen, KeyFile: seedPath, CAFile: certPath}
	console, err := Connect(connectionConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer console.Close()
	roots := x509.NewCertPool()
	roots.AddCert(root)
	provisioner, err := nats.Connect(connectionConfig.Servers, nats.Nkey(public[4], users[4].Sign), nats.Secure(&tls.Config{RootCAs: roots}), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	defer provisioner.Close()
	js, err := jetstream.New(provisioner)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	stream, err := js.CreateStream(ctx, jetstream.StreamConfig{Name: "AGENTS_STREAM", Subjects: []string{"agent.report.>"}})
	if err != nil {
		t.Fatal("console created or modified a stream during startup", err)
	}
	if _, err = console.JetStream.Publish(ctx, "agent.report.test-device", []byte("first")); err != nil {
		t.Fatal(err)
	}
	info, err := stream.Info(ctx)
	if err != nil || info.State.Msgs != 1 {
		t.Fatal("command was not retained", info, err)
	}
	// Observe both transitions: an immediate IsConnected check after server
	// shutdown can still report the old transport before its reader sees EOF.
	disconnected := console.Connection.StatusChanged(nats.RECONNECTING)
	defer console.Connection.RemoveStatusListener(disconnected)
	reconnected := console.Connection.StatusChanged(nats.CONNECTED)
	defer console.Connection.RemoveStatusListener(reconnected)
	broker.Shutdown()
	broker.WaitForShutdown()
	select {
	case <-disconnected:
	case <-time.After(5 * time.Second):
		t.Fatal("console did not observe the broker outage")
	}
	select {
	case <-console.Failure():
		t.Fatal("temporary outage treated as terminal")
	default:
	}
	broker = start()
	select {
	case <-reconnected:
	case <-time.After(8 * time.Second):
		t.Fatal("console did not reconnect")
	}
	if err = console.Connection.FlushWithContext(ctx); err != nil {
		t.Fatal("reconnected transport did not acknowledge subscriptions", err)
	}
	if _, err = console.JetStream.Publish(ctx, "agent.report.test-device", []byte("after-restart")); err != nil {
		t.Fatal(err)
	}
	// The generated console grant cannot alter streams. Verify the actual server
	// denial and terminal error notification, rather than expanding its grant.
	denied, stop := context.WithTimeout(ctx, time.Second)
	_, err = console.JetStream.CreateStream(denied, jetstream.StreamConfig{Name: "SERVERS_STREAM", Subjects: []string{"server.>"}})
	stop()
	if err == nil {
		t.Fatal("console could create a server stream")
	}
	select {
	case <-console.Failure():
	case <-time.After(time.Second):
		t.Fatal("permission error was not reported")
	}
	console.Close()
	console.Close()
	if !console.Connection.IsClosed() {
		t.Fatal("console connection survived close")
	}
	// A wrong seed and a wrong CA never fall back to the configured TLS identity.
	other, _ := nkeys.CreateUser()
	defer other.Wipe()
	wrongSeed, _ := other.Seed()
	badKey := connectionConfig
	badKey.KeyFile = write("wrong.seed", wrongSeed)
	clear(wrongSeed)
	if c, err := Connect(badKey); err == nil {
		c.Close()
		t.Fatal("unregistered key accepted")
	}
	badCA := connectionConfig
	badCA.CAFile = write("bad-ca.pem", []byte("not a CA"))
	if c, err := Connect(badCA); err == nil {
		c.Close()
		t.Fatal("invalid trust accepted")
	}
	if err = os.Remove(seedPath); err != nil {
		t.Fatal(err)
	}
	if c, err := Connect(connectionConfig); err == nil {
		c.Close()
		t.Fatal("missing key accepted")
	}
}

// Package authservice runs the private individual-agent broker services without
// obtaining an organization CA key or the enrollment encryption master key.
package authservice

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	openuem "github.com/open-uem/nats"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/keyfile"
	"github.com/open-uem/nats/enrollment/registry"
	"github.com/open-uem/nats/enrollment/servicecredentials"
)

type Config struct {
	DatabaseURL           string
	DatabaseURLFile       string
	BrokerURLs            string
	BrokerCAFile          string
	ClientCertificateFile string
	ClientKeyFile         string
	IssuerKeyFile         string
	AuthKeyFile           string
	SystemKeyFile         string
	DeviceAccount         string
	HealthAddress         string
}

func privateBrokerURLs(value string) bool {
	addresses := strings.Split(value, ",")
	if len(addresses) > 16 {
		return false
	}
	for _, address := range addresses {
		u, err := url.Parse(address)
		if err != nil || u.Scheme != "tls" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
			return false
		}
	}
	return true
}

func readPublicFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("broker trust file is unavailable")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("invalid broker trust file")
	}
	return data, nil
}

func readKey(path string, account bool) (nkeys.KeyPair, error) {
	data, err := keyfile.Read(path, 512)
	if err != nil {
		return nil, errors.New("broker key file is unavailable or insufficiently protected")
	}
	defer clear(data)
	key, err := nkeys.FromSeed(bytes.TrimSpace(data))
	if err != nil {
		return nil, errors.New("invalid broker key file")
	}
	public, err := key.PublicKey()
	if err != nil || (account && !nkeys.IsValidPublicAccountKey(public)) || (!account && !nkeys.IsValidPublicUserKey(public)) {
		key.Wipe()
		return nil, errors.New("incorrect broker key type")
	}
	return key, nil
}

func transport(config Config) (*tls.Config, error) {
	trust := &tls.Config{MinVersion: tls.VersionTLS12}
	if config.BrokerCAFile != "" {
		data, err := readPublicFile(config.BrokerCAFile, 1<<20)
		if err != nil {
			return nil, err
		}
		trust.RootCAs = x509.NewCertPool()
		if !trust.RootCAs.AppendCertsFromPEM(data) {
			return nil, errors.New("broker trust contains no certificates")
		}
	}
	if config.ClientCertificateFile != "" || config.ClientKeyFile != "" {
		certificate, err := readPublicFile(config.ClientCertificateFile, 64<<10)
		if err != nil {
			return nil, err
		}
		private, err := keyfile.Read(config.ClientKeyFile, 32<<10)
		if err != nil {
			return nil, errors.New("broker TLS key is unavailable or insufficiently protected")
		}
		defer clear(private)
		pair, err := tls.X509KeyPair(certificate, private)
		if err != nil {
			return nil, errors.New("invalid broker TLS identity")
		}
		trust.Certificates = []tls.Certificate{pair}
	}
	return trust, nil
}

func connect(config Config, trust *tls.Config, key nkeys.KeyPair, name string, failures chan<- struct{}) (*nats.Conn, error) {
	public, err := key.PublicKey()
	if err != nil {
		return nil, errors.New("invalid broker service key")
	}
	connection, err := nats.Connect(config.BrokerURLs, nats.Secure(trust.Clone()), nats.Nkey(public, key.Sign), nats.Name(name), nats.Timeout(3*time.Second), nats.MaxReconnects(-1), nats.ReconnectWait(2*time.Second), nats.IgnoreDiscoveredServers(), nats.ErrorHandler(func(*nats.Conn, *nats.Subscription, error) {
		select {
		case failures <- struct{}{}:
		default:
		}
	}))
	if err != nil {
		return nil, errors.New("private broker connection failed")
	}
	return connection, nil
}

func Run(ctx context.Context, config Config, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	if config.DatabaseURL == "" && config.DatabaseURLFile == "" || !privateBrokerURLs(config.BrokerURLs) {
		return errors.New("database and credential-free private TLS broker URLs are required")
	}
	address, err := netip.ParseAddrPort(config.HealthAddress)
	if err != nil || !address.Addr().IsLoopback() {
		return errors.New("health listener must use a loopback IP address")
	}
	config.DatabaseURL, err = servicecredentials.DatabaseURL(config.DatabaseURL, config.DatabaseURLFile)
	if err != nil {
		return err
	}
	issuer, err := readKey(config.IssuerKeyFile, true)
	if err != nil {
		return err
	}
	defer issuer.Wipe()
	authKey, err := readKey(config.AuthKeyFile, false)
	if err != nil {
		return err
	}
	defer authKey.Wipe()
	systemKey, err := readKey(config.SystemKeyFile, false)
	if err != nil {
		return err
	}
	defer systemKey.Wipe()
	authPublic, _ := authKey.PublicKey()
	systemPublic, _ := systemKey.PublicKey()
	if authPublic == systemPublic {
		return errors.New("authorization and system service keys must be separate")
	}
	trust, err := transport(config)
	if err != nil {
		return err
	}
	db, err := sql.Open("pgx", config.DatabaseURL)
	if err != nil {
		return errors.New("agent registry database configuration is invalid")
	}
	defer db.Close()
	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(8)
	db.SetConnMaxLifetime(30 * time.Minute)
	startup, cancel := context.WithTimeout(ctx, 5*time.Second)
	var initialized bool
	err = db.QueryRowContext(startup, `SELECT EXISTS(SELECT 1 FROM uem_agent_migrations WHERE name='migrations/001_registry.sql')`).Scan(&initialized)
	cancel()
	if err != nil || !initialized {
		return errors.New("agent registry must be initialized before starting broker authorization")
	}
	access, err := registry.NewAccessStore(db)
	if err != nil {
		return errors.New("agent registry is unavailable")
	}
	authorizer, err := enrollment.NewBrokerAuthorizer(issuer, config.DeviceAccount, access.AuthorizeDevice)
	if err != nil {
		return errors.New("invalid agent authorization account")
	}
	failures := make(chan struct{}, 1)
	auth, err := connect(config, trust, authKey, "openuem-agent-authorization", failures)
	if err != nil {
		return err
	}
	defer auth.Close()
	system, err := connect(config, trust, systemKey, "openuem-agent-revocation", failures)
	if err != nil {
		return err
	}
	defer system.Close()
	service, err := openuem.StartAgentAuthorizationService(ctx, auth, authorizer)
	if err != nil {
		return errors.New("agent authorization subscription failed")
	}
	defer service.Close()
	listener, err := net.Listen("tcp", config.HealthAddress)
	if err != nil {
		return errors.New("agent authorization health listener is unavailable")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		check, cancel := context.WithTimeout(r.Context(), 500*time.Millisecond)
		defer cancel()
		if ctx.Err() != nil || !auth.IsConnected() || !system.IsConnected() || db.PingContext(check) != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	health := &http.Server{Handler: mux, ReadHeaderTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 4096}
	defer health.Close()
	stopped := make(chan error, 1)
	go func() { stopped <- health.Serve(listener) }()
	logger.Info("individual agent authorization service connected")
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-failures:
			return errors.New("broker service permissions or messaging failed")
		case <-stopped:
			return errors.New("agent authorization health listener stopped")
		case <-ticker.C:
			attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := openuem.DisconnectRevokedSessions(attempt, system, access)
			cancel()
			if err != nil && ctx.Err() == nil {
				logger.Warn("broker disconnect retry deferred")
			}
		}
	}
}

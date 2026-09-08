// Package commandservice runs durable individual-device consumer reconciliation.
package commandservice

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	openuem "github.com/open-uem/nats"
	"github.com/open-uem/nats/enrollment/registry"
)

type Config struct {
	DatabaseURL   string
	Broker        openuem.ServiceConnection
	HealthAddress string
}

func Run(ctx context.Context, config Config, logger *slog.Logger) (result error) {
	defer func() {
		if ctx.Err() != nil {
			result = nil
		}
	}()
	if logger == nil {
		logger = slog.Default()
	}
	address, err := netip.ParseAddrPort(config.HealthAddress)
	if err != nil || !address.Addr().IsLoopback() {
		return errors.New("command service health listener must use a loopback IP address")
	}
	if config.DatabaseURL == "" || !openuem.ValidServiceURLs(config.Broker.Servers) {
		return errors.New("command service requires a database URL and explicit private TLS broker origins")
	}
	db, err := sql.Open("pgx", config.DatabaseURL)
	if err != nil {
		return errors.New("command registry database configuration is invalid")
	}
	defer db.Close()
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(30 * time.Minute)
	startup, cancel := context.WithTimeout(ctx, 5*time.Second)
	var initialized bool
	err = db.QueryRowContext(startup, `SELECT EXISTS(SELECT 1 FROM uem_agent_migrations WHERE name='migrations/002_command_consumers.sql')`).Scan(&initialized)
	cancel()
	if err != nil || !initialized {
		return errors.New("command consumer registry must be initialized before starting reconciliation")
	}
	access, err := registry.NewAccessStore(db)
	if err != nil {
		return errors.New("command registry is unavailable")
	}
	failures := make(chan struct{}, 1)
	fail := func() {
		select {
		case failures <- struct{}{}:
		default:
		}
	}
	brokerConfig := config.Broker
	brokerConfig.Name = "openuem-agent-command-provisioner"
	brokerConfig.ErrorHandler = func(*nats.Conn, *nats.Subscription, error) { fail() }
	brokerConfig.Event = func(state string) {
		logger.Info("command provisioner broker state", "state", state)
		if state == "closed" {
			fail()
		}
	}
	connection, err := openuem.ConnectService(brokerConfig)
	if err != nil {
		return err
	}
	defer connection.Close()
	js, err := jetstream.New(connection)
	if err != nil {
		return errors.New("command broker API is unavailable")
	}
	var lastSuccessful atomic.Int64
	reconcile := func() error {
		attempt, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		if err := openuem.ReconcileAgentCommandConsumers(attempt, js, access); err != nil {
			return err
		}
		lastSuccessful.Store(time.Now().UnixNano())
		return nil
	}
	if err = reconcile(); err != nil {
		return errors.New("initial command consumer reconciliation failed")
	}
	listener, err := net.Listen("tcp", config.HealthAddress)
	if err != nil {
		return errors.New("command service health listener is unavailable")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		check, cancel := context.WithTimeout(r.Context(), 500*time.Millisecond)
		defer cancel()
		if ctx.Err() != nil || !connection.IsConnected() || time.Since(time.Unix(0, lastSuccessful.Load())) > 30*time.Second || db.PingContext(check) != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	health := &http.Server{Handler: mux, ReadHeaderTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 4096}
	defer health.Close()
	stopped := make(chan error, 1)
	go func() { stopped <- health.Serve(listener) }()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-failures:
			return errors.New("command broker permissions or messaging failed")
		case <-stopped:
			return errors.New("command service health listener stopped")
		case <-ticker.C:
			if err := reconcile(); err != nil && ctx.Err() == nil {
				logger.Warn("command consumer reconciliation retry deferred")
			}
		}
	}
}

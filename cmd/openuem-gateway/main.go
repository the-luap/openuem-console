// OpenUEM gateway terminates public HTTPS and authenticates to private backends.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/open-uem/openuem-console/internal/gateway"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	listen := flag.String("listen", ":443", "Public HTTPS listen address")
	origin := flag.String("public-origin", "", "Canonical public HTTPS origin")
	certPath := flag.String("tls-cert", "", "Public server certificate PEM file")
	keyPath := flag.String("tls-key", "", "Public server private key PEM file")
	clientCertPath := flag.String("gateway-cert", "", "Gateway client certificate PEM file")
	clientKeyPath := flag.String("gateway-key", "", "Gateway client private key PEM file")
	caPath := flag.String("backend-ca", "", "Trusted backend server CA PEM bundle")
	apple := flag.String("apple-url", "", "Private Apple HTTPS origin")
	console := flag.String("console-url", "", "Private console HTTPS origin")
	auth := flag.String("auth-url", "", "Private certificate login HTTPS origin")
	agent := flag.String("agent-url", "", "Optional private NATS WebSocket HTTPS origin")
	desktop := flag.String("desktop-url", "", "Optional private desktop enrollment HTTPS origin")
	agentLimit := flag.Int("agent-connection-limit", 4096, "Maximum simultaneous agent upgrades and streams")
	admin := flag.String("admin-networks", "", "Comma-separated administrator source CIDRs (for example VPN networks)")
	flag.Parse()
	identity, err := tls.LoadX509KeyPair(*clientCertPath, *clientKeyPath)
	if err != nil {
		return fmt.Errorf("load gateway identity: %w", err)
	}
	ca, err := os.ReadFile(*caPath)
	if err != nil {
		return fmt.Errorf("load backend trust: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return errors.New("backend trust bundle contains no certificates")
	}
	var networks []netip.Prefix
	for _, raw := range strings.Split(*admin, ",") {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return errors.New("admin-networks must contain valid source CIDRs")
		}
		networks = append(networks, prefix)
	}
	handler, err := gateway.New(gateway.Config{
		PublicOrigin: *origin, AppleURL: *apple, ConsoleURL: *console, AuthURL: *auth,
		AgentURL: *agent, AgentConnectionLimit: *agentLimit, DesktopURL: *desktop,
		AdminNetworks: networks,
		BackendTLS:    &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{identity}, RootCAs: roots},
	})
	if err != nil {
		return err
	}
	defer handler.Close()
	server := &http.Server{
		Addr: *listen, Handler: handler,
		// TLS proves possession; backends validate the end-client issuer and
		// device/account binding. Anonymous enrollment remains possible.
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequestClientCert},
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second,
		WriteTimeout: 60 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 32 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		_ = handler.Close()
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			_ = server.Close()
		}
	}()
	err = server.ListenAndServeTLS(*certPath, *keyPath)
	stop()
	<-done
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/open-uem/openuem-console/internal/desktop/commandservice"
)

func main() {
	var config commandservice.Config
	flag.StringVar(&config.Broker.Servers, "broker-urls", "", "Comma-separated private tls:// NATS origins")
	flag.StringVar(&config.Broker.CAFile, "broker-ca", "", "Private broker CA PEM bundle; defaults to system roots")
	flag.StringVar(&config.Broker.CertificateFile, "broker-client-cert", "", "Optional broker TLS client certificate PEM file")
	flag.StringVar(&config.Broker.TLSKeyFile, "broker-client-key", "", "Optional protected broker TLS client key PEM file")
	flag.StringVar(&config.Broker.KeyFile, "provisioner-key-file", "", "Protected command provisioning user NKey seed file")
	flag.StringVar(&config.HealthAddress, "health-listen", "127.0.0.1:1327", "Loopback health listener")
	flag.Parse()
	config.DatabaseURL = os.Getenv("OPENUEM_AGENT_DATABASE_URL")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := commandservice.Run(ctx, config, slog.Default()); err != nil {
		log.Fatal(err)
	}
}

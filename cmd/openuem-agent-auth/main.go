// OpenUEM individual-agent authorization uses separate private broker accounts.
package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/open-uem/openuem-console/internal/desktop/authservice"
)

func main() {
	var config authservice.Config
	flag.StringVar(&config.BrokerURLs, "broker-urls", "", "Comma-separated private tls:// NATS origins")
	flag.StringVar(&config.BrokerCAFile, "broker-ca", "", "Private broker CA PEM bundle; defaults to system roots")
	flag.StringVar(&config.ClientCertificateFile, "broker-client-cert", "", "Optional broker TLS client certificate PEM file")
	flag.StringVar(&config.ClientKeyFile, "broker-client-key", "", "Optional protected broker TLS client key PEM file")
	flag.StringVar(&config.IssuerKeyFile, "issuer-key-file", "", "Protected authorization issuer account NKey seed file")
	flag.StringVar(&config.AuthKeyFile, "auth-key-file", "", "Protected isolated authorization user NKey seed file")
	flag.StringVar(&config.SystemKeyFile, "system-key-file", "", "Protected revocation system user NKey seed file")
	flag.StringVar(&config.DeviceAccount, "device-account", "UEM_DEVICES", "Configured individual-device broker account")
	flag.StringVar(&config.HealthAddress, "health-listen", "127.0.0.1:1326", "Loopback health listener")
	flag.Parse()
	config.DatabaseURL = os.Getenv("OPENUEM_AGENT_DATABASE_URL")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := authservice.Run(ctx, config, slog.Default()); err != nil {
		log.Fatal(err)
	}
}

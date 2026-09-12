//go:build linux || darwin

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/open-uem/openuem-console/internal/acmeissuer"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	configuration := flag.String("config", "", "Protected JSON configuration file for DNS-01 issuance")
	binary := flag.String("lego-binary", "/lego", "Absolute path to the installed, pinned lego executable")
	once := flag.Bool("once", false, "Run one bounded issuance/renewal check and publish a valid result")
	check := flag.Bool("check", false, "Validate protected local inputs without writing state or contacting a provider")
	ready := flag.Bool("ready", false, "Check the active renewal service through its private local socket")
	socket := flag.String("readiness-socket", "", "Private absolute Unix socket for renewal service readiness")
	flag.Parse()
	if flag.NArg() != 0 || *once && *check || *ready && (*once || *check || *socket == "") || *socket != "" && (*once || *check) {
		return acmeissuer.ErrConfiguration
	}
	config, err := acmeissuer.ReadConfig(*configuration)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *ready {
		if err := acmeissuer.CheckReadiness(ctx, config, *socket); err != nil {
			return err
		}
		_, err := fmt.Fprintln(os.Stdout, `{"ready":true}`)
		return err
	}
	if *check {
		if err := config.CheckInputs(*binary); err != nil {
			return err
		}
		_, err := fmt.Fprintln(os.Stdout, `{"inputs_valid":true}`)
		return err
	}
	service, err := acmeissuer.Open(config, *binary)
	if err != nil {
		return err
	}
	defer service.Close()
	if *socket != "" {
		readiness, err := service.ListenReadiness(*socket)
		if err != nil {
			return err
		}
		defer readiness.Close()
	}
	report := func(result acmeissuer.Result, err error) { log.Print(acmeissuer.LogLine(result, err)) }
	if *once {
		result, err := service.Once(ctx)
		report(result, err)
		return err
	}
	return service.Run(ctx, report)
}

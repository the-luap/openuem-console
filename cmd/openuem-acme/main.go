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
	flag.Parse()
	if flag.NArg() != 0 || *once && *check {
		return acmeissuer.ErrConfiguration
	}
	config, err := acmeissuer.ReadConfig(*configuration)
	if err != nil {
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	report := func(result acmeissuer.Result, err error) { log.Print(acmeissuer.LogLine(result, err)) }
	if *once {
		result, err := service.Once(ctx)
		report(result, err)
		return err
	}
	return service.Run(ctx, report)
}

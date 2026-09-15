package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/open-uem/openuem-console/internal/desktop"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string, output io.Writer) error {
	if ctx == nil || output == nil {
		return errors.New("release command requires a context and output writer")
	}
	var config desktop.ReleaseAdminConfig
	flags := flag.NewFlagSet("openuem-agent-releases", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&config.Action, "action", "show", "Release action: inspect, show, accept or withdraw")
	flags.StringVar(&config.Directory, "directory", "", "Read-only package repository, containing one directory per manifest digest")
	flags.StringVar(&config.TrustedKeysFile, "trusted-keys", "", "Protected PEM file containing pinned Ed25519 release public keys")
	flags.StringVar(&config.ManifestFile, "manifest", "", "Signed installer manifest envelope to accept")
	flags.StringVar(&config.Digest, "digest", "", "Exact current manifest digest to withdraw")
	flags.StringVar(&config.Actor, "actor", "", "Administrator or release-pipeline identifier for the audit record")
	flags.StringVar(&config.DatabaseURLFile, "dburl-file", "", "Protected PostgreSQL URL file; defaults to OPENUEM_AGENT_DATABASE_URL_FILE")
	if err := flags.Parse(arguments); errors.Is(err, flag.ErrHelp) {
		if _, err := io.WriteString(output, "Usage: openuem-agent-releases [options]\n"); err != nil {
			return errors.New("release command help could not be written")
		}
		flags.SetOutput(output)
		flags.PrintDefaults()
		return nil
	} else if err != nil || flags.NArg() != 0 {
		return errors.New("release command arguments are invalid")
	}
	if config.Action != "inspect" {
		config.DatabaseURL = os.Getenv("OPENUEM_AGENT_DATABASE_URL")
		if config.DatabaseURLFile == "" {
			config.DatabaseURLFile = os.Getenv("OPENUEM_AGENT_DATABASE_URL_FILE")
		}
	}
	return desktop.RunReleaseAdmin(ctx, config, output)
}

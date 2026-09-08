package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/open-uem/openuem-console/internal/desktop"
)

func main() {
	var config desktop.ReleaseAdminConfig
	flag.StringVar(&config.Action, "action", "show", "Release action: inspect, show, accept or withdraw")
	flag.StringVar(&config.Directory, "directory", "", "Read-only package repository, containing one directory per manifest digest")
	flag.StringVar(&config.TrustedKeysFile, "trusted-keys", "", "Protected PEM file containing pinned Ed25519 release public keys")
	flag.StringVar(&config.ManifestFile, "manifest", "", "Signed installer manifest envelope to accept")
	flag.StringVar(&config.Digest, "digest", "", "Exact current manifest digest to withdraw")
	flag.StringVar(&config.Actor, "actor", "", "Administrator or release-pipeline identifier for the audit record")
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatal("unexpected positional arguments")
	}
	config.DatabaseURL = os.Getenv("OPENUEM_AGENT_DATABASE_URL")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := desktop.RunReleaseAdmin(ctx, config, os.Stdout); err != nil {
		log.Fatal(err)
	}
}

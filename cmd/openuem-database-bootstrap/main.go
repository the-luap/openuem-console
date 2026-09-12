package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/open-uem/openuem-console/internal/setup/secrets"
)

func run(ctx context.Context, args []string, output io.Writer) error {
	if output == nil {
		return secrets.ErrConfiguration
	}
	flags := flag.NewFlagSet("openuem-database-bootstrap", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configFile := flags.String("config", "", "Protected deployment metadata")
	credentials := flags.String("credentials", "", "Completed protected credential directory")
	state := flags.String("state", "", "Separate protected bootstrap journal directory")
	if err := flags.Parse(args); errors.Is(err, flag.ErrHelp) {
		_, err = io.WriteString(output, "Usage: openuem-database-bootstrap --config <protected-json-file> --credentials <completed-credential-directory> --state <private-state-directory>\nCreates or verifies the bound PostgreSQL 17 application database on Linux/macOS; never resets existing objects.\n")
		return err
	} else if err != nil || flags.NArg() != 0 {
		return secrets.ErrConfiguration
	}
	config, err := secrets.LoadDatabaseConfig(*configFile)
	if err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	result, err := secrets.BootstrapDatabase(bounded, *credentials, *state, config)
	if err != nil {
		return err
	}
	if json.NewEncoder(output).Encode(result) != nil {
		return errors.New("could not write database readiness metadata; bound state was retained")
	}
	return nil
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/open-uem/openuem-console/internal/setup/secrets"
)

func run(args []string, output io.Writer) error {
	if output == nil {
		return secrets.ErrConfiguration
	}
	flags := flag.NewFlagSet("openuem-database-credentials", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "Protected deployment metadata file")
	directory := flags.String("directory", "", "Absolute private provisioning directory under a trusted parent")
	if err := flags.Parse(args); errors.Is(err, flag.ErrHelp) {
		_, err = io.WriteString(output, "Usage: openuem-database-credentials --config <protected-json-file> --directory <private-directory>\nGenerates or verifies independent database credentials and a TLS connection URL on Linux/macOS.\n")
		return err
	} else if err != nil || flags.NArg() != 0 {
		return secrets.ErrConfiguration
	}
	config, err := secrets.LoadDatabaseConfig(*configPath)
	if err != nil {
		return err
	}
	result, err := secrets.InitializeDatabaseCredentials(context.Background(), *directory, config)
	if err != nil {
		return err
	}
	if json.NewEncoder(output).Encode(result) != nil {
		return errors.New("could not write database provisioning metadata; protected credentials were retained")
	}
	return nil
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

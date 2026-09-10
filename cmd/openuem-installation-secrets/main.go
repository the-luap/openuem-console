package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/open-uem/openuem-console/internal/setup/secrets"
)

func run(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("openuem-installation-secrets", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	directory := flags.String("directory", "", "Absolute private directory under a trusted parent (Linux/macOS)")
	if flags.Parse(args) != nil || flags.NArg() != 0 || output == nil {
		return secrets.ErrConfiguration
	}
	result, err := secrets.Initialize(context.Background(), *directory)
	if err != nil {
		return err
	}
	if json.NewEncoder(output).Encode(result) != nil {
		return fmt.Errorf("could not write installation metadata; protected secrets were retained")
	}
	return nil
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

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
	flags := flag.NewFlagSet("openuem-installation-secrets", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	directory := flags.String("directory", "", "Absolute private directory under a trusted parent (Linux/macOS)")
	if err := flags.Parse(args); errors.Is(err, flag.ErrHelp) {
		_, err = io.WriteString(output, "Usage: openuem-installation-secrets --directory <private-directory>\nGenerates or verifies retained installation credentials on Linux/macOS.\n")
		return err
	} else if err != nil || flags.NArg() != 0 {
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

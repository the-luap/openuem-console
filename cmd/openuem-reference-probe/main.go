package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/open-uem/openuem-console/internal/setup/readiness"
)

func run(args []string, output io.Writer) error {
	if output == nil {
		return readiness.ErrConfiguration
	}
	flags := flag.NewFlagSet("openuem-reference-probe", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var options readiness.Options
	flags.StringVar(&options.Mode, "mode", "", "Probe mode: broker, http or gateway")
	flags.StringVar(&options.Address, "address", "", "Private listener URL or gateway IP:port")
	flags.StringVar(&options.Origin, "origin", "", "Gateway public HTTPS origin")
	flags.StringVar(&options.TrustFile, "trust-file", "", "Protected broker CA or gateway leaf certificate file")
	flags.StringVar(&options.KeyFile, "key-file", "", "Protected retained worker NKey file (broker mode)")
	timeout := flags.Duration("timeout", 20*time.Second, "Maximum probe duration (1s to 1m)")
	if err := flags.Parse(args); errors.Is(err, flag.ErrHelp) {
		_, err = io.WriteString(output, "Usage: openuem-reference-probe --mode broker|http|gateway --address <private-address> [--origin <https-origin>] [--trust-file <file>] [--key-file <file>] [--timeout 20s]\nChecks reference listeners without modifying deployment state.\n")
		return err
	} else if err != nil || flags.NArg() != 0 || *timeout < time.Second || *timeout > time.Minute {
		return readiness.ErrConfiguration
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if err := readiness.Wait(ctx, options); err != nil {
		return err
	}
	if _, err := io.WriteString(output, "{\"ready\":true}\n"); err != nil {
		return readiness.ErrNotReady
	}
	return nil
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

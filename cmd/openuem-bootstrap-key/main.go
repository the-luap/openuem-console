package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/open-uem/openuem-console/internal/desktop"
)

func main() {
	directory := flag.String("directory", "", "Absolute private directory under a trusted parent; run as the console service account")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected positional arguments")
		os.Exit(1)
	}
	if err := desktop.InitBootstrapKey(*directory, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

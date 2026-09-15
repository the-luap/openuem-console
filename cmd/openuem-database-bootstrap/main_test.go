package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestInstallationSecretsDatabaseBootstrapCommandArguments(t *testing.T) {
	for _, args := range [][]string{nil, {"--unknown=synthetic-secret"}, {"--config"}, {"synthetic-secret"}, {"--config", "/missing/synthetic-secret"}} {
		var output bytes.Buffer
		err := run(t.Context(), args, &output)
		if err == nil || strings.Contains(err.Error(), "synthetic-secret") || output.Len() != 0 {
			t.Fatal("invalid argument accepted or echoed")
		}
	}
	var output bytes.Buffer
	if err := run(t.Context(), []string{"--help"}, &output); err != nil || !strings.Contains(output.String(), "Usage:") {
		t.Fatal("help requires deployment inputs", err)
	}
	if err := run(t.Context(), []string{"--help"}, nil); err == nil {
		t.Fatal("missing output writer accepted")
	}
}

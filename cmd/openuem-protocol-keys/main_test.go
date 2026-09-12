//go:build linux || darwin

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/open-uem/openuem-console/internal/setup/secrets"
)

type failedWriter struct{}

func (failedWriter) Write([]byte) (int, error) { return 0, errors.New("synthetic output failure") }

func TestInstallationSecretsProtocolCommand(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets")
	installation := filepath.Join(t.TempDir(), "installation")
	if _, err := secrets.Initialize(t.Context(), installation); err != nil {
		t.Fatal(err)
	}
	args := []string{"--directory", path, "--installation", installation}
	var output bytes.Buffer
	if err := run(args, &output); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"windows.key", "desktop-bootstrap.key", "secrets.json"} {
		value, err := os.ReadFile(filepath.Join(path, name))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(output.Bytes(), value) {
			t.Fatal("command output leaked a credential")
		}
	}
	original := append([]byte{}, output.Bytes()...)
	output.Reset()
	if err := run(args, &output); err != nil || !bytes.Equal(original, output.Bytes()) {
		t.Fatal("restart changed metadata", err)
	}
	if err := run(args, failedWriter{}); err == nil {
		t.Fatal("output failure ignored")
	}
	if err := run(args, &output); err != nil {
		t.Fatal("output failure damaged state", err)
	}
	for _, args := range [][]string{{"--unknown=synthetic-secret"}, {"--directory", path, "synthetic-secret"}, {"--directory"}} {
		output.Reset()
		if err := run(args, &output); err == nil || bytes.Contains(output.Bytes(), []byte("synthetic-secret")) || bytes.Contains([]byte(err.Error()), []byte("synthetic-secret")) {
			t.Fatal("invalid input accepted or echoed")
		}
	}
}

func TestInstallationSecretsProtocolCommandHelp(t *testing.T) {
	var output bytes.Buffer
	if err := run([]string{"--help"}, &output); err != nil || !bytes.Contains(output.Bytes(), []byte("--installation")) {
		t.Fatal("missing command help", err)
	}
	if err := run([]string{"--help"}, nil); err == nil {
		t.Fatal("nil output accepted")
	}
}

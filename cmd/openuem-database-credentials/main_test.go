//go:build linux || darwin

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-uem/nats/enrollment/keyfile"
	"github.com/open-uem/openuem-console/internal/setup/secrets"
)

type failedWriter struct{}

func (failedWriter) Write([]byte) (int, error) { return 0, errors.New("synthetic output failure") }

func TestInstallationSecretsDatabaseCommand(t *testing.T) {
	root := t.TempDir()
	config := secrets.DatabaseConfig{Version: 1, Installation: strings.Repeat("1", 32), Host: "database.internal", Port: 5432, Database: "openuem", User: "console", TrustFile: "/run/trust/database.pem"}
	data, _ := json.Marshal(config)
	configPath := filepath.Join(root, "database.json")
	if keyfile.Create(configPath, data) != nil {
		t.Fatal("fixture metadata creation failed")
	}
	directory := filepath.Join(root, "credentials")
	args := []string{"--config", configPath, "--directory", directory}
	var output bytes.Buffer
	if err := run(args, &output); err != nil {
		t.Fatal("database command failed", err)
	}
	for _, name := range []string{secrets.DatabasePasswordFile, secrets.DatabaseAdministratorPasswordFile, secrets.DatabaseURLFile} {
		value, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(output.Bytes(), value) {
			t.Fatal("command output exposed database credentials")
		}
	}
	original := append([]byte{}, output.Bytes()...)
	output.Reset()
	if err := run(args, &output); err != nil || !bytes.Equal(output.Bytes(), original) {
		t.Fatal("restart changed metadata", err)
	}
	if err := run(args, failedWriter{}); err == nil {
		t.Fatal("output failure ignored")
	}
	if err := run(args, &output); err != nil {
		t.Fatal("output failure damaged protected credentials", err)
	}
	for _, args := range [][]string{{"--unknown=synthetic-secret"}, {"--config"}, {"synthetic-secret"}} {
		output.Reset()
		err := run(args, &output)
		if err == nil || strings.Contains(err.Error(), "synthetic-secret") || strings.Contains(output.String(), "synthetic-secret") {
			t.Fatal("invalid argument accepted or echoed")
		}
	}
	output.Reset()
	if err := run([]string{"--help"}, &output); err != nil || !strings.Contains(output.String(), "Usage:") {
		t.Fatal("help requires provisioning inputs", err)
	}
}

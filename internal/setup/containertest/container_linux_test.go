package containertest

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// This standard-library-only fixture runs the exact stripped executables from
// the distribution images in a read-only, unprivileged scratch filesystem.
func TestSetupContainerCommands(t *testing.T) {
	if os.Getenv("OPENUEM_SETUP_CONTAINER_TEST") != "1" {
		t.Skip("requires the isolated setup smoke image")
	}
	if os.Geteuid() != 65532 {
		t.Fatal("setup fixture is not using the runtime UID")
	}
	run := func(binary string, args ...string) ([]byte, error) {
		t.Helper()
		command := exec.CommandContext(t.Context(), binary, args...)
		return command.CombinedOutput()
	}
	for _, binary := range []string{"/openuem-installation-secrets", "/openuem-protocol-keys", "/openuem-reference-probe", "/openuem-database-credentials", "/openuem-database-bootstrap"} {
		if output, err := run(binary, "--help"); err != nil || !bytes.Contains(output, []byte("Usage:")) {
			t.Fatal("runtime command help failed")
		}
		if output, err := run(binary, "--unknown=synthetic-secret"); err == nil || bytes.Contains(output, []byte("synthetic-secret")) {
			t.Fatal("invalid command input was accepted or echoed")
		}
	}
	root := t.TempDir()
	installation := filepath.Join(root, "installation")
	output, err := run("/openuem-installation-secrets", "--directory", installation)
	if err != nil {
		t.Fatal("actual installation credential generation failed")
	}
	var metadata struct {
		Installation string `json:"installation"`
	}
	if json.Unmarshal(output, &metadata) != nil || len(metadata.Installation) != 32 {
		t.Fatal("missing public installation identifier")
	}
	checkPrivacy := func(directory string, output []byte, names ...string) {
		t.Helper()
		for _, name := range names {
			data, err := os.ReadFile(filepath.Join(directory, name))
			if err != nil || len(data) == 0 {
				t.Fatal("missing generated credential")
			}
			leaked := bytes.Contains(output, data)
			clear(data)
			if leaked {
				t.Fatal("runtime command exposed a generated credential")
			}
		}
	}
	checkPrivacy(installation, output, "jwt.key", "encryption.key", "initial-password")
	protocol := filepath.Join(root, "protocol")
	protocolArgs := []string{"--directory", protocol, "--installation", installation}
	protocolOutput, err := run("/openuem-protocol-keys", protocolArgs...)
	if err != nil || !bytes.Equal(output, protocolOutput) {
		t.Fatal("protocol keys do not bind the same installation")
	}
	checkPrivacy(protocol, protocolOutput, "windows.key", "desktop-bootstrap.key", "secrets.json")
	config, err := json.Marshal(map[string]any{"version": 1, "installation": metadata.Installation, "host": "database.internal", "port": 5432, "database": "openuem", "user": "console", "trust_file": "/run/trust/database.pem"})
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "database.json")
	if os.WriteFile(configPath, config, 0600) != nil {
		t.Fatal("cannot write protected fixture metadata")
	}
	database := filepath.Join(root, "database")
	args := []string{"--config", configPath, "--directory", database}
	databaseOutput, err := run("/openuem-database-credentials", args...)
	if err != nil || !bytes.Equal(output, databaseOutput) {
		t.Fatal("database credentials do not bind the same installation")
	}
	checkPrivacy(database, databaseOutput, "database-password", "administrator-password", "database.url")
	snapshot := func(directory string) map[string][32]byte {
		t.Helper()
		result := map[string][32]byte{}
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatal("cannot inspect fixture inventory")
		}
		for _, entry := range entries {
			path := filepath.Join(directory, entry.Name())
			info, err := os.Lstat(path)
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
				t.Fatal("runtime export is not a private regular file")
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal("cannot read fixture inventory")
			}
			result[entry.Name()] = sha256.Sum256(data)
			clear(data)
		}
		return result
	}
	installationBefore, databaseBefore, protocolBefore := snapshot(installation), snapshot(database), snapshot(protocol)
	if retry, err := run("/openuem-installation-secrets", "--directory", installation); err != nil || !bytes.Equal(retry, output) {
		t.Fatal("actual installation retry failed")
	}
	if retry, err := run("/openuem-database-credentials", args...); err != nil || !bytes.Equal(retry, output) {
		t.Fatal("actual database credential retry failed")
	}
	if retry, err := run("/openuem-protocol-keys", protocolArgs...); err != nil || !bytes.Equal(retry, output) {
		t.Fatal("actual protocol key retry failed")
	}
	if !reflect.DeepEqual(protocolBefore, snapshot(protocol)) {
		t.Fatal("runtime retry replaced protocol keys")
	}
	if err := os.Remove(filepath.Join(protocol, "windows.key")); err != nil {
		t.Fatal("cannot remove synthetic committed key")
	}
	protocolDamaged := snapshot(protocol)
	if _, err := run("/openuem-protocol-keys", protocolArgs...); err == nil || !reflect.DeepEqual(protocolDamaged, snapshot(protocol)) {
		t.Fatal("runtime repaired a missing committed protocol key")
	}
	if !reflect.DeepEqual(installationBefore, snapshot(installation)) || !reflect.DeepEqual(databaseBefore, snapshot(database)) {
		t.Fatal("runtime retry replaced a retained credential")
	}
	if err := os.Remove(filepath.Join(database, "database-password")); err != nil {
		t.Fatal("cannot remove synthetic committed password")
	}
	damaged := snapshot(database)
	if _, err := run("/openuem-database-credentials", args...); err == nil || !reflect.DeepEqual(damaged, snapshot(database)) {
		t.Fatal("runtime repaired a missing committed password")
	}
	state := filepath.Join(root, "bootstrap")
	if rejected, err := run("/openuem-database-bootstrap", "--config", configPath, "--credentials", database, "--state", state); err == nil || strings.Contains(string(rejected), "postgres://") {
		t.Fatal("runtime bootstrap accepted incomplete credentials or exposed a URL")
	}
	if _, err := os.Lstat(state); !os.IsNotExist(err) {
		t.Fatal("invalid bootstrap input reached online initialization")
	}
	if !reflect.DeepEqual(damaged, snapshot(database)) {
		t.Fatal("online bootstrap changed its read-only credential inputs")
	}
}

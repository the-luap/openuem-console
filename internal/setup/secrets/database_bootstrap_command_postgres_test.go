//go:build linux

package secrets_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/open-uem/nats/enrollment/keyfile"
	"github.com/open-uem/openuem-console/internal/setup/secrets"
)

func TestInstallationSecretsDatabasePostgresCommand(t *testing.T) {
	binary := os.Getenv("OPENUEM_DATABASE_TEST_BOOTSTRAP")
	if binary == "" {
		t.Skip("requires the compiled database bootstrap command")
	}
	f := startDatabaseFixture(t)
	data, _ := json.Marshal(f.config)
	configPath := filepath.Join(f.root, "database.json")
	if keyfile.Create(configPath, data) != nil {
		t.Fatal("cannot create protected command metadata")
	}
	args := []string{"--config", configPath, "--credentials", f.directory, "--state", bootstrapState(f)}
	checkOutput := func(output, stderr []byte, success bool) {
		t.Helper()
		for _, name := range []string{secrets.DatabasePasswordFile, secrets.DatabaseAdministratorPasswordFile, secrets.DatabaseURLFile} {
			secret, err := os.ReadFile(filepath.Join(f.directory, name))
			if err != nil {
				t.Fatal("missing privacy fixture")
			}
			leaked := bytes.Contains(output, secret) || bytes.Contains(stderr, secret)
			clear(secret)
			if leaked {
				t.Fatal("command exposed a protected credential")
			}
		}
		if success {
			expected, _ := json.Marshal(secrets.Result{Installation: f.config.Installation})
			if !bytes.Equal(output, append(expected, '\n')) || len(stderr) != 0 {
				t.Fatal("command did not emit only public readiness metadata")
			}
		} else if len(output) != 0 || !bytes.Contains(stderr, []byte(secrets.ErrDatabaseBootstrap.Error())) {
			t.Fatal("failed command did not retain fixed diagnostic output")
		}
	}
	for range 2 {
		command := exec.CommandContext(f.ctx, binary, args...)
		var output, stderr bytes.Buffer
		command.Stdout, command.Stderr = &output, &stderr
		if command.Run() != nil {
			t.Fatal("actual bootstrap command failed")
		}
		checkOutput(output.Bytes(), stderr.Bytes(), true)
	}
	// Hold the control row read behind a real database lock, then send the
	// process the same termination signal used by container shutdown.
	tx, err := f.admin.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal("cannot acquire synthetic blocking transaction")
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(f.ctx, `LOCK TABLE openuem_bootstrap.installations IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal("cannot block the control table")
	}
	command := exec.CommandContext(f.ctx, binary, args...)
	var output, stderr bytes.Buffer
	command.Stdout, command.Stderr = &output, &stderr
	if command.Start() != nil {
		t.Fatal("cannot start cancellable command")
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	joined := false
	t.Cleanup(func() {
		if !joined {
			_ = command.Process.Kill()
			<-done
		}
	})
	for {
		var waiting bool
		if err := f.admin.QueryRowContext(f.ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE relation='openuem_bootstrap.installations'::regclass AND NOT granted)`).Scan(&waiting); err != nil {
			t.Fatal("cannot inspect waiting command")
		}
		if waiting {
			break
		}
		select {
		case <-done:
			joined = true
			t.Fatal("command exited before the cancellation gate")
		case <-f.ctx.Done():
			t.Fatal("command did not reach the cancellation gate")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if command.Process.Signal(syscall.SIGTERM) != nil {
		t.Fatal("cannot terminate waiting command")
	}
	select {
	case err := <-done:
		joined = true
		if err == nil {
			t.Fatal("cancelled command reported readiness")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("command did not join after SIGTERM")
	}
	checkOutput(output.Bytes(), stderr.Bytes(), false)
	if tx.Rollback() != nil {
		t.Fatal("cannot release blocking transaction")
	}
	bootstrapFixture(t, f)
}

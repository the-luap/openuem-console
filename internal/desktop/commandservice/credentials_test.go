package commandservice

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	openuem "github.com/open-uem/nats"
	"github.com/open-uem/nats/enrollment/keyfile"
	"github.com/open-uem/nats/enrollment/servicecredentials"
)

func TestIndividualCommandServiceRejectsAmbiguousDatabaseInputs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "database.url")
	if keyfile.Create(path, []byte("postgres://user:synthetic-password@db.internal/uem")) != nil {
		t.Fatal("cannot create protected input")
	}
	for _, sources := range [][2]string{{"postgres://legacy/uem", path}, {"", path + ".missing"}} {
		err := Run(t.Context(), Config{DatabaseURL: sources[0], DatabaseURLFile: sources[1], Broker: openuem.ServiceConnection{Servers: "tls://localhost:4222"}, HealthAddress: "127.0.0.1:1327"}, nil)
		if !errors.Is(err, servicecredentials.ErrConfiguration) {
			t.Fatal("invalid database input reached broker startup", err)
		}
	}
}

func runCommandFixture(ctx context.Context, config Config, logger *slog.Logger) error {
	binary := os.Getenv("OPENUEM_COMMAND_SERVICE_TEST_BINARY")
	if binary == "" {
		return Run(ctx, config, logger)
	}
	command := exec.CommandContext(ctx, binary, "--broker-urls", config.Broker.Servers, "--broker-ca", config.Broker.CAFile, "--provisioner-key-file", config.Broker.KeyFile, "--health-listen", config.HealthAddress)
	command.Env = []string{"OPENUEM_AGENT_DATABASE_URL_FILE=" + config.DatabaseURLFile}
	command.Stdout, command.Stderr = io.Discard, io.Discard
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	command.WaitDelay = 5 * time.Second
	err := command.Run()
	if ctx.Err() != nil && command.ProcessState != nil && command.ProcessState.Success() {
		return nil
	}
	return err
}

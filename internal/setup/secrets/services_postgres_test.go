//go:build linux

package secrets_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func TestInstallationSecretsDatabasePostgresServices(t *testing.T) {
	cases := []struct{ name, tests, binary, selection string }{
		{"authorization", "OPENUEM_AUTH_SERVICE_TESTS", "OPENUEM_AUTH_SERVICE_TEST_BINARY", "TestRunAuthorizesAndDisconnectsDurableIdentityOverTLS"},
		{"commands", "OPENUEM_COMMAND_SERVICE_TESTS", "OPENUEM_COMMAND_SERVICE_TEST_BINARY", "TestCommandServiceRunsGeneratedBrokerConfigAndDurableReconciliation"},
		{"worker", "OPENUEM_WORKER_TESTS", "OPENUEM_WORKER_TEST_BINARY", "TestIndividualWorkerRejectsForgedBodiesRepliesAndRevokedSenders"},
	}
	configured := 0
	for _, test := range cases {
		if os.Getenv(test.tests) != "" {
			configured++
		}
		if os.Getenv(test.binary) != "" {
			configured++
		}
	}
	if configured == 0 {
		t.Skip("requires the compiled private service fixtures and executables")
	}
	if configured != 2*len(cases) {
		t.Fatal("private service process fixtures are incomplete")
	}
	f := startDatabaseFixtureWithTLS(t, true)
	bootstrapFixture(t, f)
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(f.ctx, 45*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Getenv(test.tests), "-test.v", "-test.run=^"+test.selection+"$", "-test.timeout=40s")
			command.Env = []string{"GOMAXPROCS=2", "AGENT_ENROLLMENT_TEST_DATABASE_URL=" + f.connection, test.binary + "=" + os.Getenv(test.binary)}
			command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			command.Cancel = func() error { return syscall.Kill(-command.Process.Pid, syscall.SIGTERM) }
			command.WaitDelay = 5 * time.Second
			var output serviceFixtureOutput
			command.Stdout, command.Stderr = &output, &output
			err := command.Run()
			if command.Process != nil {
				_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			}
			defer clear(output.data)
			if err != nil || !bytes.Contains(output.data, []byte("--- PASS: "+test.selection+" ")) || bytes.Contains(output.data, []byte("--- SKIP: "+test.selection)) {
				t.Fatal("actual private service failed its database, TLS broker and process lifecycle fixture")
			}
		})
	}
}

// Keep diagnostic output bounded and private: underlying drivers may include
// connection details on failure. Only explicit pass/fail markers leave the test.
type serviceFixtureOutput struct{ data []byte }

func (output *serviceFixtureOutput) Write(data []byte) (int, error) {
	count := len(data)
	if remaining := (32 << 10) - len(output.data); remaining > 0 {
		if len(data) > remaining {
			data = data[:remaining]
		}
		output.data = append(output.data, data...)
	}
	return count, nil
}

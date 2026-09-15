package recovery

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// Re-exec the test binary to exercise real child I/O, environment and cancellation
// on Unix and Windows without scripts, database services or installed tools.
func TestRecoveryProcessHelper(t *testing.T) {
	index := -1
	for i, arg := range os.Args {
		if arg == "--" {
			index = i + 1
			break
		}
	}
	if index < 0 || index >= len(os.Args) {
		return
	}
	switch os.Args[index] {
	case "warning":
		fmt.Fprintln(os.Stderr, "synthetic SQL and password must remain private")
	case "blocked-output":
		os.Stdout.Write(bytes.Repeat([]byte("x"), 32768))
		time.Sleep(time.Minute)
	case "environment":
		for _, name := range []string{"ENCRYPTION_MASTER_KEY", "PGPASSWORD", "PGOPTIONS", "OPENUEM_RECOVERY_DATABASE_URL"} {
			if os.Getenv(name) != "" {
				os.Exit(41)
			}
		}
		for _, arg := range os.Args {
			if strings.Contains(arg, "private-child-password") {
				os.Exit(42)
			}
		}
		data, err := os.ReadFile(os.Getenv("PGPASSFILE"))
		if err != nil || !bytes.Contains(data, []byte("private-child-password")) {
			os.Exit(43)
		}
		clear(data)
	default:
		os.Exit(44)
	}
	os.Exit(0)
}

func TestRecoveryChildPrivacyAndFailedOutputCancellation(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("postgres://synthetic:private-child-password@127.0.0.1:55440/fixture?sslmode=disable")
	c := &databaseConnection{uri: u, password: "private-child-password"}
	dir := privateDirectory(t)
	for _, name := range []string{"ENCRYPTION_MASTER_KEY", "PGPASSWORD", "PGOPTIONS", "OPENUEM_RECOVERY_DATABASE_URL"} {
		t.Setenv(name, "must not reach child")
	}
	for _, mode := range []string{"environment", "warning", "blocked-output"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			var out io.Writer = io.Discard
			if mode == "blocked-output" {
				out = &boundedWriter{writer: io.Discard, remaining: 0}
			}
			started := time.Now()
			err := c.run(ctx, executable, dir, []string{"-test.run=^TestRecoveryProcessHelper$", "--", mode}, out)
			if mode == "environment" && err != nil {
				t.Fatal("child inherited secrets or lost private password file", err)
			}
			if mode != "environment" && !errors.Is(err, ErrDatabase) {
				t.Fatal("child warning or output failure accepted", err)
			}
			if time.Since(started) > 4*time.Second {
				t.Fatal("failed stdout did not promptly terminate and reap child")
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatal("child left password file", err)
			}
		})
	}
}

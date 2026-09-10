//go:build linux || darwin

package acmeissuer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIssuerReapsImmediateExit(t *testing.T) {
	directory := t.TempDir()
	helper := filepath.Join(directory, "provider")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nexit \"$1\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	for range 20 {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		err := runLego(ctx, helper, directory, []string{"0"}, []string{})
		cancel()
		if err != nil {
			t.Fatal("normal exit was not observed and reaped", err)
		}
	}
	if err := runLego(t.Context(), helper, directory, []string{"1"}, []string{}); !errors.Is(err, ErrIssuance) {
		t.Fatal("failed command lost its status", err)
	}
}

func TestIssuerCancellationStopsOwnedProviderDescendants(t *testing.T) {
	directory := t.TempDir()
	helper := filepath.Join(directory, "provider")
	// This deliberately uncooperative owned provider inherits the process group.
	// Its activity must cease before another issuer can use the same state.
	script := "#!/bin/sh\ntrap '' TERM\n(while :; do printf 'tick\\n' >> \"$1\"; sleep 0.02; done) &\nprintf 'ready' > \"$2\"\nwait\n"
	if err := os.WriteFile(helper, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	activity, ready := filepath.Join(directory, "activity"), filepath.Join(directory, "ready")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- runLego(ctx, helper, directory, []string{activity, ready}, []string{"SYNTHETIC_SECRET=must-not-be-logged"})
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatal("owned provider did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("provider cancellation was not retained", err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("owned provider did not stop within its grace period")
	}
	before, err := os.Stat(activity)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(80 * time.Millisecond)
	after, err := os.Stat(activity)
	if err != nil {
		t.Fatal(err)
	}
	if before.Size() != after.Size() {
		t.Fatal("provider descendant kept writing after return")
	}
}

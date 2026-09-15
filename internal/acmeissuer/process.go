//go:build linux || darwin

package acmeissuer

import (
	"context"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// The caller retains both directory leases through termination and reaping of
// the issuer command. Provider output may contain secrets and is never forwarded.
func runLego(ctx context.Context, binary, directory string, args, environment []string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	command := exec.Command(binary, args...)
	command.Dir = directory
	command.Env = environment
	command.Stdin = nil
	command.Stdout, command.Stderr = io.Discard, io.Discard
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.WaitDelay = 5 * time.Second
	if err := command.Start(); err != nil {
		return ErrIssuance
	}
	done := make(chan error, 1)
	// Observe exit without reaping: the group leader's PID cannot be reused
	// between this notification and the final process-group signal.
	go func() { done <- observeExit(command.Process.Pid) }()
	var observation error
	select {
	case observation = <-done:
	case <-ctx.Done():
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
		timer := time.NewTimer(5 * time.Second)
		select {
		case observation = <-done:
			timer.Stop()
		case <-timer.C:
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			observation = <-done
		}
	}
	// Terminate descendants in the owned group before releasing its leader's PID.
	// Providers must not daemonize or escape this group. The reference container
	// additionally confines the command to its own PID and filesystem namespaces.
	_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	result := command.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if result != nil || observation != nil {
		return ErrIssuance
	}
	return nil
}

func validExecutable(path string) bool {
	if !cleanAbsolute(path) {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 && protected(info, false)
}

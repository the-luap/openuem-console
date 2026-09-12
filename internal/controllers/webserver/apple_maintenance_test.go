package webserver

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/inventory"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/access"
)

type appleMaintenanceFixture struct {
	updates, reminders, release chan struct{}
	sources                     inventory.DeviceSources
	permissions                 *access.Store
}

func (f *appleMaintenanceFixture) RunPushReminders(ctx context.Context, _ *slog.Logger, _ apple.PushReminderSender) {
	close(f.reminders)
	<-ctx.Done()
	<-f.release
}
func (f *appleMaintenanceFixture) RunUpdateSchedules(ctx context.Context, permissions *access.Store, sources inventory.DeviceSources, _ *slog.Logger) {
	f.sources, f.permissions = sources, permissions
	close(f.updates)
	<-ctx.Done()
}
func TestAppleMaintenanceWorkersStartIndependentlyAndJoin(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	f := &appleMaintenanceFixture{updates: make(chan struct{}), reminders: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	sources := inventory.DeviceSources{Apple: true, Windows: true}
	permissions := &access.Store{}
	go func() {
		defer close(done)
		runAppleMaintenance(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), f, permissions, sources, nil)
	}()
	for _, started := range []chan struct{}{f.updates, f.reminders} {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("independent Apple maintenance worker did not start")
		}
	}
	if f.sources != sources || f.permissions != permissions {
		t.Fatal("schedule worker lost server sources or current access store")
	}
	cancel()
	select {
	case <-done:
		t.Fatal("maintenance did not join the reminder worker")
	default:
	}
	close(f.release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Apple maintenance did not stop")
	}
}

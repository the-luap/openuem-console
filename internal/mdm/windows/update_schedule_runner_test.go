package windows

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestUpdateScheduleRunnerDeadlinesRetryAndShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	var calls atomic.Int32
	entered := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		runUpdateSchedules(ctx, time.Millisecond, 20*time.Millisecond, func(pass context.Context, limit int) (UpdateScheduleProgress, error) {
			if limit != 25 {
				t.Error("unbounded worker batch")
			}
			if deadline, ok := pass.Deadline(); !ok || time.Until(deadline) > 20*time.Millisecond {
				t.Error("unbounded worker pass")
			}
			switch calls.Add(1) {
			case 1:
				<-pass.Done()
				return UpdateScheduleProgress{}, errors.New("synthetic-private-database-detail")
			case 2:
				close(entered)
				<-ctx.Done()
			default:
				t.Error("unexpected pass after shutdown")
			}
			return UpdateScheduleProgress{}, pass.Err()
		}, logger)
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("failed pass did not retry")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not drain canceled pass")
	}
	if calls.Load() != 2 || strings.Contains(logs.String(), "synthetic-private") || !strings.Contains(logs.String(), "schedule processing failed") {
		t.Fatal("worker retry/logging boundary failed")
	}
	runUpdateSchedules(ctx, time.Hour, time.Hour, func(context.Context, int) (UpdateScheduleProgress, error) {
		t.Error("canceled worker started")
		return UpdateScheduleProgress{}, nil
	}, logger)
}

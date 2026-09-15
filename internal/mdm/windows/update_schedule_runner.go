package windows

import (
	"context"
	"log/slog"
	"time"
)

// RunUpdateSchedules resumes durable schedules immediately, then admits at most
// 25 due schedules per pass. Database transactions arbitrate concurrent servers;
// this loop does not overlap its own passes or reserve device queue capacity.
func (s *Store) RunUpdateSchedules(ctx context.Context, logger *slog.Logger) {
	runUpdateSchedules(ctx, 15*time.Second, 30*time.Second, s.ProcessDueUpdateSchedules, logger)
}

func runUpdateSchedules(ctx context.Context, interval, timeout time.Duration, process func(context.Context, int) (UpdateScheduleProgress, error), logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	for ctx.Err() == nil {
		pass, cancel := context.WithTimeout(ctx, timeout)
		_, err := process(pass, 25)
		cancel()
		if err != nil && ctx.Err() == nil {
			// SQL errors may contain protected schedule data. Do not log raw
			// errors, targets, request keys or decrypted policy values.
			logger.Error("native Windows update schedule processing failed")
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

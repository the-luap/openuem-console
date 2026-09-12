package audit

import (
	"context"
	"log/slog"
	"time"
)

// RunRetention joins the caller's lifetime. Database row locks coordinate
// multiple console replicas; only explicitly configured policies delete data.
func (s *Store) RunRetention(ctx context.Context, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for ctx.Err() == nil {
		batch, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := s.PruneRetention(batch)
		cancel()
		if err != nil && ctx.Err() == nil {
			// Do not put database parameters or event metadata in process logs.
			logger.Error("Audit retention sweep failed; it will retry")
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

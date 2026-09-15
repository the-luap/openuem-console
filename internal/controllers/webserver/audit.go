package webserver

import (
	"context"
	"log/slog"
)

func (w *WebServer) startAuditRetention() {
	w.auditMu.Lock()
	defer w.auditMu.Unlock()
	if w.auditCancel != nil || w.Handler.Audit == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	w.auditCancel = cancel
	done := make(chan struct{})
	w.auditDone = done
	go func() {
		defer close(done)
		w.Handler.Audit.RunRetention(ctx, slog.Default())
	}()
}

func (w *WebServer) stopAuditRetention() {
	w.auditMu.Lock()
	cancel, done := w.auditCancel, w.auditDone
	w.auditMu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

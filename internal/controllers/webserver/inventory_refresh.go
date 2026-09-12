package webserver

import (
	"context"
	"log/slog"

	"github.com/open-uem/openuem-console/internal/inventory"
)

func (w *WebServer) startInventoryRefresh(ctx context.Context) error {
	w.inventoryMu.Lock()
	defer w.inventoryMu.Unlock()
	if w.inventoryCancel != nil {
		return nil
	}
	store, err := inventory.NewRefreshStore(w.Handler.Model.DB, w.Handler.Access, w.Handler.IndividualAgentService != nil, w.Handler.PublishInventoryReport)
	if err != nil {
		return err
	}
	if err = store.Migrate(ctx); err != nil {
		return err
	}
	w.Handler.InventoryRefresh = store
	run, cancel := context.WithCancel(context.Background())
	w.inventoryCancel = cancel
	w.inventoryDone = make(chan struct{})
	done := w.inventoryDone
	go func() {
		defer close(done)
		store.Run(run, slog.Default())
	}()
	return nil
}

func (w *WebServer) stopInventoryRefresh() {
	w.inventoryMu.Lock()
	cancel, done := w.inventoryCancel, w.inventoryDone
	w.inventoryMu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

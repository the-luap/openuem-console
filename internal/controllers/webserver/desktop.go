package webserver

import (
	"context"
	"log/slog"
	"time"

	"github.com/open-uem/openuem-console/internal/desktop"
)

func (w *WebServer) initDesktop(masterKey string) {
	if len(masterKey) < 32 {
		w.Handler.DesktopSetupError = "A server administrator must configure encryption before desktop enrollment can be enabled."
		return
	}
	store, err := desktop.NewStore(w.Handler.Model.DB, masterKey)
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err = store.Migrate(ctx)
		cancel()
	}
	if err != nil {
		w.Handler.DesktopSetupError = "Desktop enrollment is unavailable. A server administrator must check its database configuration."
		slog.Error("desktop enrollment registry initialization failed")
		return
	}
	w.Handler.Desktop = store
}

package webserver

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/open-uem/openuem-console/internal/mdm/apple"
)

func (w *WebServer) initApple(masterKey string) {
	if masterKey == "" {
		w.Handler.AppleSetupError = "Set a 32-byte ENCRYPTION_MASTER_KEY to enable encrypted Apple management."
		return
	}
	s, err := apple.NewStore(w.Handler.Model.DB, masterKey)
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err = s.Migrate(ctx)
		cancel()
	}
	if err != nil {
		w.Handler.AppleSetupError = "Apple management initialization failed. Check the server log."
		slog.Error("initialize native Apple management", "error", err)
		return
	}
	w.Handler.Apple = s
}

func (w *WebServer) startApple(certFile, keyFile string) error {
	address := os.Getenv("APPLE_MDM_LISTEN_ADDR")
	if address == "" || w.Handler.Apple == nil {
		return nil
	}
	if v := os.Getenv("APPLE_MDM_TLS_CERT"); v != "" {
		certFile = v
	}
	if v := os.Getenv("APPLE_MDM_TLS_KEY"); v != "" {
		keyFile = v
	}
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	w.AppleServer = w.Handler.Apple.ProtocolServer(address, slog.Default())
	w.AppleServer.TLSConfig.Certificates = []tls.Certificate{certificate}
	ctx, cancel := context.WithCancel(context.Background())
	w.AppleCancel = cancel
	go w.Handler.Apple.Run(ctx, slog.Default())
	go func() {
		defer listener.Close()
		if err := w.AppleServer.ServeTLS(listener, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			cancel()
			slog.Error("native Apple listener stopped", "error", err)
		}
	}()
	return nil
}

package webserver

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/clientidentity"
)

func (w *WebServer) initApple(masterKey string) {
	if masterKey == "" {
		w.Handler.AppleSetupError = "Set a 32-byte ENCRYPTION_MASTER_KEY to enable encrypted Apple management."
		return
	}
	var vendor *apple.VendorTrust
	if pins := strings.TrimSpace(os.Getenv("APPLE_MDM_VENDOR_CERT_SHA256")); pins != "" {
		var err error
		vendor, err = apple.NewVendorTrust(strings.Split(pins, ","))
		if err != nil {
			// An optional signer configuration must not disable active device
			// management. Invalid pins disable only vendor envelope operations.
			slog.Error("Apple vendor certificate pins are invalid; portal request verification is disabled")
		}
	}
	s, err := apple.NewStoreWithVendor(w.Handler.Model.DB, masterKey, vendor)
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
	identity, err := clientidentity.FromEnvironment()
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	w.AppleServer = w.Handler.Apple.ProtocolServerWithIdentity(address, slog.Default(), identity)
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

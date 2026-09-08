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

	"github.com/open-uem/openuem-console/internal/desktop"
	"github.com/open-uem/openuem-console/internal/security/clientidentity"
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

func (w *WebServer) startDesktop(certFile, keyFile string) error {
	address := os.Getenv("OPENUEM_AGENT_ENROLLMENT_LISTEN_ADDR")
	directory := os.Getenv("OPENUEM_AGENT_RELEASES_DIRECTORY")
	keysFile := os.Getenv("OPENUEM_AGENT_RELEASE_KEYS_FILE")
	if address == "" && directory == "" && keysFile == "" {
		return nil
	}
	if address == "" || directory == "" || keysFile == "" || w.Handler.Desktop == nil {
		return errors.New("desktop enrollment requires its listener, release directory, release keys and encrypted registry")
	}
	keys, err := desktop.LoadReleaseKeys(keysFile)
	if err != nil {
		return errors.New("desktop release trust configuration is invalid")
	}
	catalog, err := desktop.NewCatalog(w.Handler.Model.DB, directory, keys)
	if err != nil {
		return errors.New("desktop release repository is unavailable")
	}
	ready := false
	defer func() {
		if !ready {
			catalog.Close()
		}
	}()
	identity, err := clientidentity.FromEnvironment()
	if err != nil {
		return errors.New("desktop gateway trust configuration is invalid")
	}
	public, err := desktop.NewPublicHandler(w.Handler.Desktop, catalog, w.Handler.PublicOrigin, identity)
	if err != nil {
		return err
	}
	defer func() {
		if !ready {
			public.Close()
		}
	}()
	if cert, key := os.Getenv("OPENUEM_AGENT_ENROLLMENT_TLS_CERT"), os.Getenv("OPENUEM_AGENT_ENROLLMENT_TLS_KEY"); cert != "" || key != "" {
		if cert == "" || key == "" {
			return errors.New("desktop listener requires both TLS certificate and private key")
		}
		certFile, keyFile = cert, key
	}
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return errors.New("desktop listener TLS identity is invalid")
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return errors.New("desktop enrollment listener could not start")
	}
	server := public.Server(address)
	server.TLSConfig.Certificates = []tls.Certificate{certificate}
	w.DesktopServer, w.desktopPublic, w.Handler.DesktopCatalog = server, public, catalog
	ready = true
	go func() {
		defer listener.Close()
		if err := server.ServeTLS(listener, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			_ = server.Close()
			public.Close()
			slog.Error("desktop enrollment listener stopped")
		}
	}()
	return nil
}

func (w *WebServer) stopDesktop() {
	if w.DesktopServer != nil {
		_ = w.DesktopServer.Close()
	}
	if w.desktopPublic != nil {
		w.desktopPublic.Close()
	}
	if w.Handler != nil && w.Handler.DesktopCatalog != nil {
		_ = w.Handler.DesktopCatalog.Close()
	}
}

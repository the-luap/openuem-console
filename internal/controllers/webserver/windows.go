package webserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/open-uem/nats/enrollment/keyfile"
	"github.com/open-uem/openuem-console/internal/mdm/windows"
	"github.com/open-uem/openuem-console/internal/security/clientidentity"
)

type windowsConfig struct {
	address, certFile, keyFile string
	masterKey                  string
	options                    windows.ProtocolOptions
}

func windowsConfiguration(origin, certFile, keyFile string, getenv func(string) string) (*windowsConfig, error) {
	configured := false
	for _, name := range []string{"WINDOWS_MDM_LISTEN_ADDR", "WINDOWS_MDM_MASTER_KEY", "WINDOWS_MDM_MASTER_KEY_FILE", "WINDOWS_MDM_PROVIDER_ID", "WINDOWS_MDM_DISPLAY_NAME", "WINDOWS_MDM_TLS_CERT", "WINDOWS_MDM_TLS_KEY"} {
		configured = configured || getenv(name) != ""
	}
	if !configured {
		return nil, nil
	}
	c := &windowsConfig{address: getenv("WINDOWS_MDM_LISTEN_ADDR"), certFile: certFile, keyFile: keyFile, options: windows.ProtocolOptions{PublicOrigin: origin, ProviderID: getenv("WINDOWS_MDM_PROVIDER_ID"), DisplayName: getenv("WINDOWS_MDM_DISPLAY_NAME")}}
	if c.address == "" || getenv("WINDOWS_MDM_MASTER_KEY") == "" && getenv("WINDOWS_MDM_MASTER_KEY_FILE") == "" {
		return nil, errors.New("native Windows management requires its listener and protected master key")
	}
	var err error
	c.masterKey, err = windowsMasterKey(getenv("WINDOWS_MDM_MASTER_KEY"), getenv("WINDOWS_MDM_MASTER_KEY_FILE"))
	if err != nil {
		return nil, err
	}
	if c.options.ProviderID == "" {
		c.options.ProviderID = "OpenUEM"
	}
	if c.options.DisplayName == "" {
		c.options.DisplayName = "OpenUEM Windows Management"
	}
	if _, err := c.options.EnrollmentOptions(); err != nil {
		return nil, errors.New("native Windows management requires a valid public HTTPS origin and enrollment identity")
	}
	if cert, key := getenv("WINDOWS_MDM_TLS_CERT"), getenv("WINDOWS_MDM_TLS_KEY"); cert != "" || key != "" {
		if cert == "" || key == "" {
			return nil, errors.New("native Windows listener requires both TLS certificate and private key")
		}
		c.certFile, c.keyFile = cert, key
	}
	return c, nil
}

// File input keeps the Windows authority key outside container environments.
// Legacy raw input retains its store-level validation; a selected file must be
// protected, bounded and canonical, and never falls back to another source.
func windowsMasterKey(raw, path string) (string, error) {
	if path == "" {
		return raw, nil
	}
	if raw != "" {
		return "", windows.ErrMasterKey
	}
	data, err := keyfile.Read(path, 46)
	if err != nil {
		return "", windows.ErrMasterKey
	}
	defer clear(data)
	value := bytes.TrimSuffix(data, []byte("\n"))
	if len(value) != len(data) {
		value = bytes.TrimSuffix(value, []byte("\r"))
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(string(value))
	defer clear(decoded)
	if err != nil || len(value) != 44 || len(decoded) != 32 || base64.StdEncoding.EncodeToString(decoded) != string(value) {
		return "", windows.ErrMasterKey
	}
	return string(value), nil
}

type windowsRuntime struct {
	server *http.Server
	cancel context.CancelFunc
	done   chan struct{}
}

// Access migrations must run before this method. Invalid partial configuration
// fails startup; no listener or worker is launched with an uninitialized store.
func (w *WebServer) startWindows(certFile, keyFile string, identity clientidentity.Policy) error {
	w.windowsMu.Lock()
	defer w.windowsMu.Unlock()
	if w.windowsRuntime != nil {
		return errors.New("native Windows management is already running")
	}
	config, err := windowsConfiguration(w.Handler.PublicOrigin, certFile, keyFile, os.Getenv)
	if err != nil {
		return err
	}
	if config == nil {
		w.Handler.WindowsSetupError = "A server administrator must configure native Windows management before enrollment can be enabled."
		return nil
	}
	certificate, err := tls.LoadX509KeyPair(config.certFile, config.keyFile)
	if err != nil {
		return errors.New("native Windows listener TLS identity is invalid")
	}
	store, err := windows.NewStoreWithMasterKey(w.Handler.Model.DB, config.masterKey)
	if err != nil {
		return errors.New("native Windows encrypted registry configuration is invalid")
	}
	public, err := windows.NewProtocolHandler(store, config.options, identity)
	if err != nil {
		return errors.New("native Windows protocol configuration is invalid")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	err = store.Migrate(ctx)
	if err == nil && w.Handler.Audit != nil {
		err = w.Handler.Audit.Migrate(ctx)
	}
	cancel()
	if err != nil {
		return errors.New("native Windows database initialization failed")
	}
	server := public.Server(config.address)
	server.TLSConfig.Certificates = []tls.Certificate{certificate}
	runtime, err := startWindowsRuntime(server, func(ctx context.Context, logger *slog.Logger) {
		runWindowsMaintenance(ctx, logger, store, windowsCertificateSender(w.Handler.EncryptionMasterKey))
	})
	if err != nil {
		return err
	}
	w.windowsRuntime = runtime
	w.Handler.Windows = store
	w.Handler.WindowsOptions, _ = config.options.EnrollmentOptions()
	w.Handler.WindowsSetupError = ""
	return nil
}

func startWindowsRuntime(server *http.Server, run func(context.Context, *slog.Logger)) (*windowsRuntime, error) {
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return nil, errors.New("native Windows listener could not start")
	}
	ctx, cancel := context.WithCancel(context.Background())
	server.BaseContext = func(net.Listener) context.Context { return ctx }
	runtime := &windowsRuntime{server: server, cancel: cancel, done: make(chan struct{})}
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		run(ctx, slog.Default())
	}()
	go func() {
		defer workers.Done()
		defer listener.Close()
		defer cancel()
		defer server.Close()
		if err := server.ServeTLS(listener, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("native Windows listener stopped")
		}
	}()
	go func() { workers.Wait(); close(runtime.done) }()
	return runtime, nil
}

func (w *WebServer) stopWindows() {
	w.windowsMu.Lock()
	defer w.windowsMu.Unlock()
	if runtime := w.windowsRuntime; runtime != nil {
		runtime.cancel()
		_ = runtime.server.Close()
		<-runtime.done
		w.windowsRuntime = nil
	}
}

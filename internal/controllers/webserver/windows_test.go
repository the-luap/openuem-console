package webserver

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/open-uem/openuem-console/internal/controllers/webserver/handlers"
	"github.com/open-uem/openuem-console/internal/security/clientidentity"
)

func TestWindowsConfigurationRequiresCompleteOptIn(t *testing.T) {
	get := func(values map[string]string) func(string) string {
		return func(key string) string { return values[key] }
	}
	if config, err := windowsConfiguration("", "", "", get(nil)); err != nil || config != nil {
		t.Fatal("disabled Windows setup required configuration")
	}
	for _, values := range []map[string]string{
		{"WINDOWS_MDM_LISTEN_ADDR": "127.0.0.1:0"},
		{"WINDOWS_MDM_MASTER_KEY": "synthetic-key"},
		{"WINDOWS_MDM_TLS_CERT": "synthetic-cert"},
		{"WINDOWS_MDM_PROVIDER_ID": "OpenUEM"},
		{"WINDOWS_MDM_LISTEN_ADDR": "127.0.0.1:0", "WINDOWS_MDM_MASTER_KEY": "synthetic-key", "WINDOWS_MDM_TLS_KEY": "synthetic-private-key"},
		{"WINDOWS_MDM_LISTEN_ADDR": "127.0.0.1:0", "WINDOWS_MDM_MASTER_KEY": "synthetic-key", "WINDOWS_MDM_PROVIDER_ID": "invalid provider"},
	} {
		if c, err := windowsConfiguration("https://uem.example.test", "default-cert", "default-key", get(values)); err == nil || c != nil {
			t.Fatal("partial setup admitted")
		}
	}
	values := map[string]string{"WINDOWS_MDM_LISTEN_ADDR": "127.0.0.1:0", "WINDOWS_MDM_MASTER_KEY": "synthetic-key"}
	c, err := windowsConfiguration("https://uem.example.test", "default-cert", "default-key", get(values))
	if err != nil || c.options.ProviderID != "OpenUEM" || c.options.DisplayName != "OpenUEM Windows Management" || c.certFile != "default-cert" || c.keyFile != "default-key" {
		t.Fatal("complete setup failed")
	}
	if _, err := windowsConfiguration("", "", "", get(values)); err == nil {
		t.Fatal("missing public origin admitted")
	}
	values["WINDOWS_MDM_TLS_CERT"], values["WINDOWS_MDM_TLS_KEY"] = "windows-cert", "windows-key"
	c, err = windowsConfiguration("https://uem.example.test", "default-cert", "default-key", get(values))
	if err != nil || c.certFile != "windows-cert" || c.keyFile != "windows-key" {
		t.Fatal("TLS override not used as a pair")
	}
	for _, name := range []string{"WINDOWS_MDM_LISTEN_ADDR", "WINDOWS_MDM_MASTER_KEY", "WINDOWS_MDM_PROVIDER_ID", "WINDOWS_MDM_DISPLAY_NAME", "WINDOWS_MDM_TLS_CERT", "WINDOWS_MDM_TLS_KEY"} {
		t.Setenv(name, "")
	}
	w := &WebServer{Handler: &handlers.Handler{}}
	if err := w.startWindows("", "", clientidentity.Policy{}); err != nil || w.windowsRuntime != nil || w.Handler.Windows != nil || w.Handler.WindowsSetupError == "" {
		t.Fatal("disabled listener launched work")
	}
	t.Setenv("WINDOWS_MDM_LISTEN_ADDR", "127.0.0.1:0")
	if err := w.startWindows("", "", clientidentity.Policy{}); err == nil || w.windowsRuntime != nil {
		t.Fatal("partial setup launched work")
	}
	w.stopWindows()
}

func TestWindowsRuntimeStopsRequestsAndWorkerTogether(t *testing.T) {
	certificateServer := httptest.NewTLSServer(http.NotFoundHandler())
	certificate := certificateServer.TLS.Certificates[0]
	certificateServer.Close()
	started, stopped := make(chan struct{}), make(chan struct{})
	server := &http.Server{Addr: "127.0.0.1:0", Handler: http.NotFoundHandler(), TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}}
	runtime, err := startWindowsRuntime(server, func(ctx context.Context, _ *slog.Logger) { close(started); <-ctx.Done(); close(stopped) })
	if err != nil {
		t.Fatal(err)
	}
	w := &WebServer{windowsRuntime: runtime}
	t.Cleanup(w.stopWindows)
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not start")
	}
	if server.BaseContext(nil).Err() != nil {
		t.Fatal("server context canceled before shutdown")
	}
	var group sync.WaitGroup
	for range 8 {
		group.Go(w.stopWindows)
	}
	done := make(chan struct{})
	go func() { group.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent shutdown stalled")
	}
	select {
	case <-stopped:
	default:
		t.Fatal("shutdown returned before worker finished")
	}
	if server.BaseContext(nil).Err() != context.Canceled || w.windowsRuntime != nil {
		t.Fatal("HTTP context or lifecycle state survived shutdown")
	}
	// Binding failure must not launch the scheduler.
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	if runtime, err := startWindowsRuntime(&http.Server{Addr: occupied.Addr().String()}, func(context.Context, *slog.Logger) { t.Error("worker launched after binding failure") }); err == nil || runtime != nil {
		t.Fatal("occupied listener admitted")
	}
	// A serving failure cancels the worker even without an explicit Close call.
	failed, err := startWindowsRuntime(&http.Server{Addr: "127.0.0.1:0"}, func(ctx context.Context, _ *slog.Logger) { <-ctx.Done() })
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-failed.done:
	case <-time.After(5 * time.Second):
		failed.cancel()
		failed.server.Close()
		t.Fatal("listener failure orphaned worker")
	}
}

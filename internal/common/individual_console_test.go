//go:build linux || windows

package common_test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-uem/openuem-console/internal/commands"
	"github.com/open-uem/openuem-console/internal/common"
	"github.com/urfave/cli/v2"
)

func TestIndividualConsoleCLIWithoutLegacySFTPOrBroker(t *testing.T) {
	t.Setenv("OPENUEM_INDIVIDUAL_AGENT_MODE", "true")
	t.Setenv("OPENUEM_AGENT_BROKER_URLS", "tls://broker.internal:4222")
	t.Setenv("OPENUEM_AGENT_CONSOLE_KEY_FILE", "/private/console.seed")
	t.Setenv("OPENUEM_AGENT_BROKER_CA_FILE", "/trust/backend.pem")
	t.Setenv("OPENUEM_AGENT_BROKER_CLIENT_CERT_FILE", "")
	t.Setenv("OPENUEM_AGENT_BROKER_CLIENT_KEY_FILE", "")
	t.Setenv("NATS_SERVERS", "")
	t.Setenv("OPENUEM_BOOTSTRAP_ADMIN", "first-admin")
	t.Setenv("OPENUEM_BOOTSTRAP_PASSWORD_FILE", "/private/first-password")
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	certificate, private := fixture.Certificate(), fixture.TLS.Certificates[0].PrivateKey.(*rsa.PrivateKey)
	fixture.Close()
	directory := t.TempDir()
	write := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	certFile := write("console.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}))
	keyFile := write("console.key", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(private)}))
	w := &common.Worker{}
	run := func(args []string) error {
		return (&cli.App{Writer: io.Discard, ErrWriter: io.Discard, Flags: commands.StartConsoleFlags(), Action: w.GenerateConsoleConfigFromCLI}).Run(args)
	}
	args := []string{"test", "--cacert", certFile, "--cert", certFile, "--key", keyFile, "--sftpkey", filepath.Join(directory, "missing-sftp.key"), "--dburl", "postgres://unused", "--jwt-key", "test-only", "--domain", "example.test", "--org-name", "Test"}
	if err := run(args); err != nil {
		t.Fatal("individual CLI still needs legacy credentials", err)
	}
	if w.IndividualAgentService == nil || w.NATSServers != "tls://broker.internal:4222" || w.SFTPPrivateKeyPath != "" {
		t.Fatal("individual configuration not retained")
	}
	if w.ProtectedAdministrator == nil || w.ProtectedAdministrator.UserID != "first-admin" || w.ProtectedAdministrator.PasswordFile != "/private/first-password" {
		t.Fatal("CLI lost protected administrator configuration")
	}
	if err := run(append(append([]string{}, args...), "--reset-openuem-user")); err == nil {
		t.Fatal("protected bootstrap allowed a password reset")
	}
	t.Setenv("OPENUEM_BOOTSTRAP_PASSWORD_FILE", "")
	t.Setenv("OPENUEM_INDIVIDUAL_AGENT_MODE", "false")
	if err := run(args); err == nil {
		t.Fatal("legacy mode no longer requires SFTP key")
	}
	legacy := append(append([]string{}, args...), "--sftpkey", keyFile, "--nats-servers", "tls://legacy.internal:4222")
	if err := run(legacy); err != nil {
		t.Fatal("legacy CLI no longer works", err)
	}
	if w.ProtectedAdministrator != nil || w.IndividualAgentService != nil || w.SFTPPrivateKeyPath != keyFile || w.NATSServers != "tls://legacy.internal:4222" {
		t.Fatal("legacy configuration changed")
	}
}

func TestIndividualConsoleInvalidModeStopsBeforeINI(t *testing.T) {
	t.Setenv("OPENUEM_INDIVIDUAL_AGENT_MODE", "TRUE")
	w := &common.Worker{}
	if err := w.GenerateConsoleConfig(); err == nil || !strings.Contains(err.Error(), "must be true or false") {
		t.Fatal("installed service read legacy INI before validating mode", err)
	}
	w.StopWorker()
}

package webserver

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-uem/openuem-console/internal/controllers/webserver/handlers"
	"github.com/open-uem/openuem-console/internal/models"
	"github.com/open-uem/openuem-console/internal/security/access"
	"github.com/open-uem/openuem-console/internal/security/audit"
	"github.com/open-uem/openuem-console/internal/security/clientidentity"
)

func windowsStartupTestDatabase(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("WINDOWS_MDM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set WINDOWS_MDM_TEST_DATABASE_URL for isolated Windows startup integration")
	}
	u, err := url.Parse(dsn)
	port := "55440"
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		port = "5432"
	}
	if err != nil || u.Scheme != "postgres" || u.Hostname() != "127.0.0.1" || u.Port() != port || u.Path != "/openuem_test" || u.User == nil || u.User.Username() != "openuem_test" {
		t.Fatal("Windows startup tests require the reserved loopback test database")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal("open isolated PostgreSQL connection")
	}
	t.Cleanup(func() { admin.Close() })
	var database, user string
	var actualPort, version int
	if err := admin.QueryRowContext(ctx, `SELECT current_database(),current_user,inet_server_port(),current_setting('server_version_num')::integer`).Scan(&database, &user, &actualPort, &version); err != nil {
		t.Fatal(err)
	}
	if database != "openuem_test" || user != "openuem_test" || strconv.Itoa(actualPort) != port || version < 170000 || version >= 180000 {
		t.Fatal("unexpected test database identity or version")
	}
	schema := "windows_startup_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	db, err := sql.Open("pgx", u.String())
	if err != nil {
		t.Fatal("open isolated startup schema")
	}
	t.Cleanup(func() {
		db.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.ExecContext(ctx, `DROP SCHEMA `+schema+` CASCADE`); err != nil {
			t.Error(err)
		}
	})
	if _, err := db.ExecContext(ctx, `CREATE TABLE users(uid TEXT PRIMARY KEY); CREATE TABLE tenants(id BIGINT PRIMARY KEY); CREATE TABLE sites(id BIGINT PRIMARY KEY,tenant_sites BIGINT REFERENCES tenants(id)); INSERT INTO users VALUES('admin'); INSERT INTO tenants VALUES(1); INSERT INTO sites VALUES(11,1)`); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestWindowsStartupMigratesProtectedStoreAndResumesAfterRestart(t *testing.T) {
	db := windowsStartupTestDatabase(t)
	permissions, err := access.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := permissions.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := permissions.Bootstrap(t.Context(), "admin"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"WINDOWS_MDM_LISTEN_ADDR", "WINDOWS_MDM_MASTER_KEY", "WINDOWS_MDM_MASTER_KEY_FILE", "WINDOWS_MDM_PROVIDER_ID", "WINDOWS_MDM_DISPLAY_NAME", "WINDOWS_MDM_TLS_CERT", "WINDOWS_MDM_TLS_KEY"} {
		t.Setenv(name, "")
	}
	t.Setenv("WINDOWS_MDM_LISTEN_ADDR", "127.0.0.1:0")
	t.Setenv("WINDOWS_MDM_MASTER_KEY", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32))))
	certificateServer := httptest.NewTLSServer(http.NotFoundHandler())
	certificate := certificateServer.TLS.Certificates[0]
	certificateServer.Close()
	key, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	directory := t.TempDir()
	certFile, keyFile := filepath.Join(directory, "synthetic-cert.pem"), filepath.Join(directory, "synthetic-key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	auditStore, err := audit.NewStore(db, permissions)
	if err != nil {
		t.Fatal(err)
	}
	// Shared audit starts before the optional Windows schema on a new install.
	if err := auditStore.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	w := &WebServer{Handler: &handlers.Handler{Model: &models.Model{DB: db}, Access: permissions, Audit: auditStore, PublicOrigin: "https://uem.example.test"}}
	if err := w.startWindows(certFile, keyFile, clientidentity.Policy{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.stopWindows)
	if w.Handler.Windows == nil || w.Handler.WindowsOptions.ManagementURL != "https://uem.example.test/mdm/windows/syncml" || w.windowsRuntime == nil || w.Handler.WindowsSetupError != "" {
		t.Fatal("startup did not publish initialized Windows service")
	}
	if err := w.startWindows(certFile, keyFile, clientidentity.Policy{}); err == nil {
		t.Fatal("duplicate startup admitted")
	}
	invitation, credential, err := w.Handler.Windows.CreateEnrollmentInvitation(t.Context(), "admin", access.Scope{TenantID: 1, SiteID: 11}, "synthetic@example.test", time.Hour)
	if err != nil {
		t.Fatal("startup store did not enforce usable access schema", err)
	}
	if invitation.CreatedBy != "admin" {
		t.Fatal("invitation authority changed")
	}
	var guards int
	if err := db.QueryRow(`SELECT count(*) FROM pg_trigger WHERE tgname='uem_audit_windows_history' AND tgenabled='O' AND tgfoid='uem_audit_guard_windows_history()'::regprocedure`).Scan(&guards); err != nil || guards != 12 {
		t.Fatal("startup omitted optional Windows audit guards", guards, err)
	}
	page, err := auditStore.List(t.Context(), "admin", audit.Filter{Scope: access.Scope{TenantID: 1, SiteID: 11}, Source: "windows_enrollment", From: time.Now().Add(-time.Hour), Until: time.Now().Add(time.Minute)}, "")
	if err != nil || len(page.Events) == 0 || page.Events[0].Resource != invitation.ID {
		t.Fatal("startup audit source omitted enrollment metadata", err)
	}
	w.stopWindows()
	if err := w.startWindows(certFile, keyFile, clientidentity.Policy{}); err != nil {
		t.Fatal("idempotent restart failed", err)
	}
	if _, err := w.Handler.Windows.CheckPolicyCredential(t.Context(), *credential); err != nil {
		t.Fatal("restart lost durable credential", err)
	}
	w.stopWindows()
	// A failed optional source registration must not launch the native runtime.
	if _, err := db.Exec(`ALTER FUNCTION uem_audit_guard_windows_history() RENAME TO unavailable_windows_audit_guard`); err != nil {
		t.Fatal(err)
	}
	if err := w.startWindows(certFile, keyFile, clientidentity.Policy{}); err == nil || w.windowsRuntime != nil {
		t.Fatal("failed audit registration launched listener")
	}
	t.Setenv("WINDOWS_MDM_MASTER_KEY", "invalid synthetic key")
	if err := w.startWindows(certFile, keyFile, clientidentity.Policy{}); err == nil || w.windowsRuntime != nil {
		t.Fatal("invalid encryption configuration launched listener")
	}
}

package webserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-uem/openuem-console/internal/controllers/webserver/handlers"
	"github.com/open-uem/openuem-console/internal/mdm/apple"
	"github.com/open-uem/openuem-console/internal/security/access"
)

func TestPushExpiryEmailEscapesOrganization(t *testing.T) {
	m := apple.PushExpiryMessage{ID: uuid.NewString(), TenantID: 42, Recipient: "admin@example.test", Organization: `<img src=x onerror=alert(1)>`, Fingerprint: strings.Repeat("a", 64), Stage: 0, CreatedAt: time.Now(), ExpiresAt: time.Now()}
	got := pushExpiryEmail(m)
	if strings.Contains(got.HTML, m.Organization) || !strings.Contains(got.HTML, "&lt;img") || !strings.Contains(got.Text, m.Organization) {
		t.Fatal("organization escaping")
	}
	if !strings.Contains(got.Subject, "has expired") || !strings.Contains(got.Text, "same Apple account and MDM topic") || got.ID != m.ID || got.To != m.Recipient {
		t.Fatal("renewal message metadata")
	}
}

func TestPushRemindersRunWithoutListenerAndStopSMTP(t *testing.T) {
	dsn := os.Getenv("APPLE_MDM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set APPLE_MDM_TEST_DATABASE_URL for reminder lifecycle integration")
	}
	t.Setenv("APPLE_MDM_LISTEN_ADDR", "")
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "reminder_lifecycle_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	db, err := sql.Open("pgx", u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
		if _, err := admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`); err != nil {
			t.Error(err)
		}
		admin.Close()
	})
	if _, err = db.Exec(`CREATE TABLE tenants(id BIGINT PRIMARY KEY); CREATE TABLE sites(id BIGINT PRIMARY KEY,tenant_sites BIGINT REFERENCES tenants(id)); INSERT INTO tenants VALUES(1); INSERT INTO sites VALUES(1,1);
 CREATE TABLE users(uid TEXT PRIMARY KEY,email TEXT,email_verified BOOLEAN,register TEXT); INSERT INTO users VALUES('admin','admin@example.test',true,'users.completed');
 CREATE TABLE settings(smtp_server TEXT,smtp_port INTEGER,smtp_user TEXT,smtp_password TEXT,smtp_auth TEXT,message_from TEXT,smtp_encryption_type TEXT,tenant_settings BIGINT)`); err != nil {
		t.Fatal(err)
	}
	s, err := apple.NewStore(db, strings.Repeat("k", 32))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	permissions, err := access.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err = permissions.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = permissions.Bootstrap(t.Context(), "admin"); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(12 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	// Isolated legacy row: the worker only reads the public certificate. No
	// synthetic APNs trust or production credential validation bypass is added.
	if _, err = db.Exec(`INSERT INTO mdm_apple_settings(tenant_id,public_url,organization,topic,push_expires_at,push_certificate,push_key,ca_certificate,ca_key) VALUES(1,'https://example.test','Fixture','com.apple.mgmt.fixture',$1,$2,'unused','unused','unused')`, leaf.NotAfter, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	entered, closed := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(closed)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		close(entered)
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = io.Copy(io.Discard, conn)
	}()
	if _, err = db.Exec(`INSERT INTO settings(smtp_server,smtp_port,smtp_auth,message_from,smtp_encryption_type,tenant_settings) VALUES('127.0.0.1',$1,'NOAUTH','from@example.test','none',1)`, listener.Addr().(*net.TCPAddr).Port); err != nil {
		t.Fatal(err)
	}
	w := &WebServer{Handler: &handlers.Handler{Apple: s, EncryptionMasterKey: strings.Repeat("k", 32)}}
	w.startAppleReminders()
	defer w.stopAppleReminders()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("reminder worker requires public listener or did not start")
	}
	stopped := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		for range 2 {
			wg.Go(w.stopAppleReminders)
		}
		wg.Wait()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not cancel SMTP and join worker")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("SMTP connection survived shutdown")
	}
	var status string
	if err = db.QueryRow(`SELECT status FROM mdm_apple_push_reminder_deliveries`).Scan(&status); err != nil || status != "pending" {
		t.Fatal("cancelled delivery not retryable", status, err)
	}
}

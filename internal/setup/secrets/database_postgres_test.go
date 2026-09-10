//go:build linux

package secrets_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-uem/nats/enrollment/keyfile"
	"github.com/open-uem/openuem-console/internal/models"
	"github.com/open-uem/openuem-console/internal/setup/secrets"
)

// Run only inside an explicitly configured disposable PostgreSQL image. The
// cluster, TLS authority and both database roles are synthetic and loopback-only.
func TestInstallationSecretsDatabasePostgres(t *testing.T) {
	f := startDatabaseFixture(t)
	ctx, config, credentialDirectory, connection, administratorPassword := f.ctx, f.config, f.directory, f.connection, f.administratorPassword
	state := filepath.Join(f.root, "bootstrap")
	if _, err := secrets.BootstrapDatabase(ctx, credentialDirectory, state, config); err != nil {
		entries, _ := os.ReadDir(state)
		for _, entry := range entries {
			t.Log("retained bootstrap phase", entry.Name())
		}
		var rolePresent, rowPresent bool
		_ = f.admin.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='console'),EXISTS(SELECT 1 FROM openuem_bootstrap.installations)`).Scan(&rolePresent, &rowPresent)
		t.Log("retained role and control row", rolePresent, rowPresent)
		t.Fatal("automatic database bootstrap failed", err)
	}
	t.Setenv("ENV", "test")
	model, err := models.New(connection, "pgx", "example.test")
	if err != nil {
		t.Fatal("console schema migration failed using the generated database credential")
	}
	defer model.Close()
	var user, database string
	var privileged bool
	if err := model.DB.QueryRowContext(ctx, `SELECT current_user,current_database(),rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls FROM pg_roles WHERE rolname=current_user`).Scan(&user, &database, &privileged); err != nil || user != "console" || database != "openuem" || privileged {
		t.Fatal("console did not use the unprivileged application role")
	}
	if _, err := model.DB.ExecContext(ctx, `CREATE ROLE forbidden_fixture_role`); err == nil {
		t.Fatal("application role can create cluster identities")
	}
	var tlsActive bool
	if err := model.DB.QueryRowContext(ctx, `SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()`).Scan(&tlsActive); err != nil || !tlsActive {
		t.Fatal("application did not authenticate over TLS")
	}
	if err := model.CreateInitialSettings(); err != nil {
		t.Fatal("normal console initialization failed under application ownership")
	}
	if _, err := secrets.InitializeDatabaseCredentials(ctx, credentialDirectory, config); err != nil {
		t.Fatal("credential restart failed", err)
	}
	if err := model.DB.PingContext(ctx); err != nil {
		t.Fatal("idempotent provisioning broke the existing database connection")
	}
	if _, err := secrets.BootstrapDatabase(ctx, credentialDirectory, state, config); err != nil {
		t.Fatal("bound database restart failed", err)
	}
	checkRejected := func(value *url.URL) error {
		t.Helper()
		db, err := sql.Open("pgx", value.String())
		if err != nil {
			t.Fatal("cannot configure negative fixture")
		}
		defer db.Close()
		attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		err = db.PingContext(attempt)
		if err == nil {
			t.Fatal("invalid database credentials or TLS identity were accepted")
		}
		return err
	}
	wrongPassword, _ := url.Parse(connection)
	wrongPassword.User = url.UserPassword(config.User, administratorPassword)
	var authentication *pgconn.PgError
	if err := checkRejected(wrongPassword); !errors.As(err, &authentication) || authentication.Code != "28P01" {
		t.Fatal("separate administrator password did not fail application authentication")
	}
	wrongHost, _ := url.Parse(connection)
	wrongHost.Host = net.JoinHostPort("localhost", strconv.Itoa(config.Port))
	var hostnameError x509.HostnameError
	if err := checkRejected(wrongHost); !errors.As(err, &hostnameError) {
		t.Fatal("verify-full did not reject the wrong server name")
	}
}

type databaseFixture struct {
	ctx                                                context.Context
	root, directory, connection, administratorPassword string
	config                                             secrets.DatabaseConfig
	admin                                              *sql.DB
}

func startDatabaseFixture(t *testing.T) databaseFixture {
	t.Helper()
	initdb, postgres := os.Getenv("OPENUEM_DATABASE_TEST_INITDB"), os.Getenv("OPENUEM_DATABASE_TEST_POSTGRES")
	if initdb == "" || postgres == "" {
		t.Skip("requires the disposable PostgreSQL credential container")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	t.Cleanup(cancel)
	root := t.TempDir()
	caFile, certificateFile, keyFile := databaseTLS(t, root)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal("cannot allocate a fixture port")
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	config := secrets.DatabaseConfig{Version: 1, Installation: strings.Repeat("1", 32), Host: "127.0.0.1", Port: port, Database: "openuem", User: "console", TrustFile: caFile}
	credentialDirectory := filepath.Join(root, "credentials")
	if _, err := secrets.InitializeDatabaseCredentials(ctx, credentialDirectory, config); err != nil {
		t.Fatal("credential provisioning failed", err)
	}
	dataDirectory := filepath.Join(root, "postgres")
	initialize := exec.CommandContext(ctx, initdb, "-D", dataDirectory, "--username=postgres", "--auth=scram-sha-256", "--pwfile", filepath.Join(credentialDirectory, secrets.DatabaseAdministratorPasswordFile), "--no-instructions")
	initialize.Stdout, initialize.Stderr = io.Discard, io.Discard
	if initialize.Run() != nil {
		t.Fatal("disposable PostgreSQL initialization failed")
	}
	server := exec.CommandContext(ctx, postgres, "-D", dataDirectory, "-h", "127.0.0.1", "-p", strconv.Itoa(port), "-k", root,
		"-c", "ssl=on", "-c", "ssl_cert_file="+certificateFile, "-c", "ssl_key_file="+keyFile,
		"-c", "shared_buffers=16MB", "-c", "max_connections=20", "-c", "log_statement=none", "-c", "log_min_error_statement=panic")
	server.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	server.Stdout, server.Stderr = io.Discard, io.Discard
	server.Cancel = func() error { return syscall.Kill(-server.Process.Pid, syscall.SIGINT) }
	if server.Start() != nil {
		t.Fatal("disposable PostgreSQL startup failed")
	}
	done := make(chan error, 1)
	go func() { done <- server.Wait() }()
	t.Cleanup(func() {
		_ = syscall.Kill(-server.Process.Pid, syscall.SIGINT)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = syscall.Kill(-server.Process.Pid, syscall.SIGKILL)
			<-done
		}
	})
	read := func(name string) string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(credentialDirectory, name))
		if err != nil {
			t.Fatal("credential fixture is missing")
		}
		defer clear(data)
		return string(data)
	}
	administratorPassword := read(secrets.DatabaseAdministratorPasswordFile)
	connection, err := secrets.DatabaseURL("", filepath.Join(credentialDirectory, secrets.DatabaseURLFile))
	if err != nil {
		t.Fatal("generated application connection is invalid", err)
	}
	administratorURL, _ := url.Parse(connection)
	administratorURL.User = url.UserPassword("postgres", administratorPassword)
	administratorURL.Path = "/postgres"
	admin, err := sql.Open("pgx", administratorURL.String())
	if err != nil {
		t.Fatal("cannot configure the fixture administrator connection")
	}
	t.Cleanup(func() { admin.Close() })
	for admin.PingContext(ctx) != nil {
		select {
		case <-ctx.Done():
			t.Fatal("database did not become ready with its generated administrator password")
		case <-time.After(25 * time.Millisecond):
		}
	}
	return databaseFixture{ctx: ctx, root: root, directory: credentialDirectory, connection: connection, administratorPassword: administratorPassword, config: config, admin: admin}
}

func databaseTLS(t *testing.T, directory string) (string, string, string) {
	t.Helper()
	ca, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic database test CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &ca.PublicKey, ca)
	if err != nil {
		t.Fatal(err)
	}
	server := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Synthetic database test server"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: root.NotBefore, NotAfter: root.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	serverDER, err := x509.CreateCertificate(rand.Reader, server, root, &leaf.PublicKey, ca)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leaf)
	if err != nil {
		t.Fatal(err)
	}
	paths := []string{filepath.Join(directory, "ca.pem"), filepath.Join(directory, "server.pem"), filepath.Join(directory, "server.key")}
	for index, block := range []*pem.Block{{Type: "CERTIFICATE", Bytes: rootDER}, {Type: "CERTIFICATE", Bytes: serverDER}, {Type: "PRIVATE KEY", Bytes: keyDER}} {
		data := pem.EncodeToMemory(block)
		if keyfile.Create(paths[index], data) != nil {
			t.Fatal("TLS fixture file creation failed")
		}
		clear(data)
	}
	clear(keyDER)
	return paths[0], paths[1], paths[2]
}

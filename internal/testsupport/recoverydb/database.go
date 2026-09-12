// Package recoverydb owns disposable whole databases for recovery integration tests.
package recoverydb

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func New(t *testing.T) (*sql.DB, string) {
	t.Helper()
	raw := os.Getenv("OPENUEM_RECOVERY_TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("set OPENUEM_RECOVERY_TEST_DATABASE_URL for isolated backup/restore integration")
	}
	u, err := url.Parse(raw)
	port := "55440"
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		port = "5432"
	}
	if err != nil || u.Scheme != "postgres" || u.Hostname() != "127.0.0.1" || u.Port() != port || u.Path != "/openuem_test" || u.User == nil || u.User.Username() != "openuem_test" || u.RawQuery != "sslmode=disable" || u.Fragment != "" {
		t.Fatal("recovery tests require the reserved loopback database")
	}
	for _, value := range os.Environ() {
		name, value, _ := strings.Cut(value, "=")
		if strings.HasPrefix(strings.ToUpper(name), "PG") && value != "" {
			t.Fatal("recovery test database must not inherit PostgreSQL settings")
		}
	}
	admin, err := sql.Open("pgx", raw)
	if err != nil {
		t.Fatal(err)
	}
	var database, user string
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	var actualPort, version int
	if err := admin.QueryRowContext(ctx, `SELECT current_database(),current_user,inet_server_port(),current_setting('server_version_num')::integer`).Scan(&database, &user, &actualPort, &version); err != nil || database != "openuem_test" || user != "openuem_test" || strconv.Itoa(actualPort) != port || version/10000 != 17 {
		admin.Close()
		t.Fatal("unexpected recovery test database identity")
	}
	name := "openuem_recovery_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.ExecContext(ctx, `CREATE DATABASE `+name+` TEMPLATE template0`); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	var db *sql.DB
	t.Cleanup(func() {
		if db != nil {
			db.Close()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.ExecContext(ctx, `DROP DATABASE `+name+` WITH (FORCE)`); err != nil {
			t.Error(err)
		}
		admin.Close()
	})
	u.Path = "/" + name
	db, err = sql.Open("pgx", u.String())
	if err != nil {
		t.Fatal(err)
	}
	return db, u.String()
}

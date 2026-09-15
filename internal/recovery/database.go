package recovery

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

type databaseConnection struct {
	db       *sql.DB
	uri      *url.URL
	password string
	database string
	major    int
}

func connectDatabase(ctx context.Context, raw string) (*databaseConnection, error) {
	// pgx and libpq must select the same explicit destination. Do not temporarily
	// mutate process environment: other in-process database clients may be running.
	for _, value := range os.Environ() {
		name, value, _ := strings.Cut(value, "=")
		if strings.HasPrefix(strings.ToUpper(name), "PG") && value != "" {
			return nil, ErrConfig
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "postgres" && u.Scheme != "postgresql" || u.User == nil || u.User.Username() == "" || u.Hostname() == "" || u.Fragment != "" || strings.Contains(u.Hostname(), ",") || len(u.Path) < 2 || !validDatabaseName(u.Path[1:]) {
		return nil, ErrConfig
	}
	for _, r := range raw {
		if r < 32 || r == 127 {
			return nil, ErrConfig
		}
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, ErrConfig
	}
	allowed := map[string]bool{"sslmode": true, "sslrootcert": true, "sslcert": true, "sslkey": true, "connect_timeout": true}
	for k, v := range q {
		if !allowed[k] || len(v) != 1 {
			return nil, ErrConfig
		}
	}
	for _, name := range []string{"sslrootcert", "sslcert", "sslkey"} {
		if value := q.Get(name); value != "" && !filepath.IsAbs(value) {
			return nil, ErrConfig
		}
	}
	local := u.Hostname() == "localhost"
	if ip := net.ParseIP(u.Hostname()); ip != nil && ip.IsLoopback() {
		local = true
	}
	if q.Get("sslmode") != "verify-full" && !(local && q.Get("sslmode") == "disable") {
		return nil, ErrConfig
	}
	password, _ := u.User.Password()
	for _, value := range []string{u.User.Username(), password, u.Path[1:]} {
		if strings.ContainsAny(value, "\r\n\x00") {
			return nil, ErrConfig
		}
	}
	q.Set("connect_timeout", "10")
	u.RawQuery = q.Encode()
	config, err := pgx.ParseConfig(u.String())
	if err != nil {
		return nil, ErrDatabase
	}
	// Explicitly clear an automatically discovered password file and role-level
	// search_path/options for the catalog preflight. The child uses its own pgpass.
	config.Password = password
	config.RuntimeParams = map[string]string{"search_path": "pg_catalog", "application_name": "openuem-recovery-preflight"}
	db := stdlib.OpenDB(*config)
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	c := &databaseConnection{db: db, uri: u, password: password}
	var version int
	if err := db.QueryRowContext(ctx, `SELECT current_database(),current_setting('server_version_num')::integer`).Scan(&c.database, &version); err != nil {
		db.Close()
		return nil, ErrDatabase
	}
	c.major = version / 10000
	if c.major < 17 || c.major > 99 || c.database != u.Path[1:] {
		db.Close()
		return nil, ErrConfig
	}
	return c, nil
}

func (c *databaseConnection) requiredKeys(ctx context.Context, b *recoveryBundle) error {
	var apple, desktop, windows bool
	if err := c.db.QueryRowContext(ctx, `SELECT COALESCE(bool_or(c.relname='mdm_apple_devices'),false),COALESCE(bool_or(c.relname='uem_agent_identities'),false),COALESCE(bool_or(c.relname='mdm_windows_authorities'),false) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind IN ('r','p') AND n.nspname !~ '^pg_' AND n.nspname<>'information_schema'`).Scan(&apple, &desktop, &windows); err != nil {
		return ErrDatabase
	}
	if (apple || desktop) && len(b.Environment["ENCRYPTION_MASTER_KEY"]) < 32 {
		return ErrConfig
	}
	if windows {
		value := b.Environment["WINDOWS_MDM_MASTER_KEY"]
		key, err := base64.StdEncoding.Strict().DecodeString(value)
		defer clear(key)
		if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != value {
			return ErrConfig
		}
	}
	return nil
}

func (c *databaseConnection) emptyTarget(ctx context.Context, confirm string, sourceMajor int) error {
	if confirm != c.database || c.major < sourceMajor {
		return ErrTarget
	}
	var objects, others int
	err := c.db.QueryRowContext(ctx, `SELECT
 (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema')+
 (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema')+
 (SELECT count(*) FROM pg_namespace WHERE nspname !~ '^pg_' AND nspname NOT IN ('public','information_schema'))+
 (SELECT count(*) FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema')+
 (SELECT count(*) FROM pg_extension WHERE extname<>'plpgsql')+
 (SELECT count(*) FROM pg_largeobject_metadata)+
 (SELECT count(*) FROM pg_event_trigger)+
 (SELECT count(*) FROM pg_foreign_data_wrapper)+
 (SELECT count(*) FROM pg_foreign_server)+
 (SELECT count(*) FROM pg_publication)+
 (SELECT count(*) FROM pg_subscription WHERE subdbid=(SELECT oid FROM pg_database WHERE datname=current_database()))+
 (SELECT count(*) FROM pg_language WHERE lanname NOT IN ('internal','c','sql','plpgsql'))+
 (SELECT count(*) FROM pg_collation c JOIN pg_namespace n ON n.oid=c.collnamespace WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema')+
 (SELECT count(*) FROM pg_conversion c JOIN pg_namespace n ON n.oid=c.connamespace WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema')+
 (SELECT count(*) FROM pg_operator o JOIN pg_namespace n ON n.oid=o.oprnamespace WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema')+
 (SELECT count(*) FROM pg_opclass o JOIN pg_namespace n ON n.oid=o.opcnamespace WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema')+
 (SELECT count(*) FROM pg_opfamily o JOIN pg_namespace n ON n.oid=o.opfnamespace WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema')+
 (SELECT count(*) FROM pg_ts_config c JOIN pg_namespace n ON n.oid=c.cfgnamespace WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema')+
 (SELECT count(*) FROM pg_ts_dict d JOIN pg_namespace n ON n.oid=d.dictnamespace WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema'),
 (SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid())`).Scan(&objects, &others)
	if err != nil || objects != 0 || others != 0 {
		return ErrTarget
	}
	return nil
}

// Child diagnostics are bounded and withheld: PostgreSQL errors can include
// passwords, connection strings, SQL literals and restored device data.
type diagnosticSink struct{ count int }

func (d *diagnosticSink) Write(p []byte) (int, error) { d.count += len(p); return len(p), nil }

func postgresTool(ctx context.Context, path, name string, major int) (string, error) {
	if path == "" {
		var err error
		path, err = exec.LookPath(name)
		if err != nil {
			return "", ErrConfig
		}
	}
	if !filepath.IsAbs(path) {
		return "", ErrConfig
	}
	check, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(check, path, "--version")
	cmd.Env = processEnvironment()
	cmd.WaitDelay = time.Second
	var output bytes.Buffer
	cmd.Stdout = &cancelWriter{writer: &boundedWriter{writer: &output, remaining: 4096}, cancel: cancel}
	cmd.Stderr = &diagnosticSink{}
	if err := cmd.Run(); err != nil {
		return "", ErrConfig
	}
	match := regexp.MustCompile(`^` + name + ` \(PostgreSQL\) ([0-9]+)\.`).FindStringSubmatch(output.String())
	if len(match) != 2 {
		return "", ErrConfig
	}
	actual, _ := strconv.Atoi(match[1])
	if actual != major {
		return "", ErrConfig
	}
	return path, nil
}

func (c *databaseConnection) run(ctx context.Context, tool, work string, args []string, stdout io.Writer) error {
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	passPath := filepath.Join(work, ".pgpass-"+uuid.NewString())
	escape := strings.NewReplacer(`\`, `\\`, ":", `\:`)
	pass := []byte("*:*:*:" + escape.Replace(c.uri.User.Username()) + ":" + escape.Replace(c.password) + "\n")
	defer clear(pass)
	if err := writePrivate(passPath, pass); err != nil {
		return ErrFile
	}
	defer os.Remove(passPath)
	u := *c.uri
	u.User = url.User(c.uri.User.Username())
	args = append(args, "--no-password", "--dbname="+u.String())
	cmd := exec.CommandContext(child, tool, args...)
	cmd.WaitDelay = 5 * time.Second
	cmd.Env = processEnvironment()
	cmd.Env = append(cmd.Env, "PGPASSFILE="+passPath, "PGAPPNAME=openuem-recovery")
	cmd.Dir = work
	cmd.Stdout = &cancelWriter{writer: stdout, cancel: cancel}
	diagnostics := &diagnosticSink{}
	cmd.Stderr = diagnostics
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrDatabase
	}
	if diagnostics.count > 0 {
		return ErrDatabase
	}
	return nil
}

func processEnvironment() []string {
	result := []string{}
	for _, value := range os.Environ() {
		name := strings.SplitN(value, "=", 2)[0]
		// Only operating-system process essentials are inherited. Application
		// secrets and ambient libpq credentials/options do not reach the tool.
		switch strings.ToUpper(name) {
		case "PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL":
			result = append(result, value)
		}
	}
	return result
}

type cancelWriter struct {
	writer io.Writer
	cancel context.CancelFunc
}

func (w *cancelWriter) Write(p []byte) (int, error) {
	n, err := w.writer.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	if err != nil {
		w.cancel()
	}
	return n, err
}

type boundedWriter struct {
	writer    io.Writer
	remaining int64
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.remaining {
		return 0, ErrArchive
	}
	n, err := w.writer.Write(p)
	w.remaining -= int64(n)
	return n, err
}

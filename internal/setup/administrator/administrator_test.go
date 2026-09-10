package administrator

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/google/uuid"
	openuem "github.com/open-uem/nats"
	"github.com/open-uem/nats/enrollment/keyfile"
	"github.com/open-uem/openuem-console/internal/models"
	"github.com/open-uem/openuem-console/internal/security/access"
)

const testPassword = "Bootstrap-Only_Random-Test-Secret-123456789"

func passwordFile(t *testing.T, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "password.txt")
	if err := keyfile.Create(path, []byte(data)); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestProtectedAdministratorEnvironment(t *testing.T) {
	t.Setenv("OPENUEM_BOOTSTRAP_PASSWORD_FILE", "")
	t.Setenv("OPENUEM_BOOTSTRAP_ADMIN", "")
	config, err := FromEnvironment(false)
	if config != nil || err != nil {
		t.Fatal("legacy mode changed", config, err)
	}
	config, err = FromEnvironment(true)
	if err != nil || config == nil || config.UserID != "openuem" || config.PasswordFile != "" {
		t.Fatal("individual default configuration failed", config, err)
	}
	t.Setenv("OPENUEM_BOOTSTRAP_PASSWORD_FILE", "/private/password.txt")
	if config, err = FromEnvironment(false); err != nil || config == nil {
		t.Fatal("explicit protected setup ignored", config, err)
	}
	for _, id := range []string{"administrator", "admin@example.test", "Company.Admin+setup"} {
		if err := (Config{UserID: id}).Validate(); err != nil {
			t.Fatal("valid administrator name rejected", id, err)
		}
	}
	for _, id := range []string{"", "..", "@", "-admin", " leading", "trailing ", "admin\nsecret", "../admin", "admin:name", strings.Repeat("a", 129)} {
		if err := (Config{UserID: id}).Validate(); err == nil {
			t.Fatal("invalid administrator name accepted", id)
		}
	}
	t.Setenv("OPENUEM_BOOTSTRAP_ADMIN", "invalid/name")
	if config, err := FromEnvironment(true); config != nil || err == nil {
		t.Fatal("invalid configuration accepted", config, err)
	}
}

func TestProtectedAdministratorPasswordFile(t *testing.T) {
	for _, suffix := range []string{"", "\n", "\r\n"} {
		data, err := password(passwordFile(t, testPassword+suffix))
		if err != nil || string(data) != testPassword {
			t.Fatal("protected password did not round trip", err)
		}
		clear(data)
	}
	for _, data := range []string{"short", "", strings.Repeat("x", 129), testPassword + "\n\n", testPassword + "\r", testPassword + " secret", testPassword + "\x00", testPassword + "é"} {
		// Create also rejects empty credentials, so write this negative fixture
		// through the already protected descriptor.
		path := passwordFile(t, "fixture")
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if value, err := password(path); value != nil || err == nil {
			clear(value)
			t.Fatal("malformed password accepted")
		}
	}
	if _, err := password(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing password file accepted")
	}
	if _, err := password(t.TempDir()); err == nil {
		t.Fatal("directory accepted as a password")
	}
	if runtime.GOOS != "windows" {
		path := passwordFile(t, testPassword)
		link := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(path, link); err != nil {
			t.Fatal(err)
		}
		if _, err := password(link); err == nil {
			t.Fatal("password symlink accepted")
		}
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := password(path); err == nil {
			t.Fatal("public password file accepted")
		}
	}
}

type testAccountModel struct {
	*models.Model
	databaseURL string
}

func accountModel(t *testing.T) *testAccountModel {
	t.Helper()
	dsn := os.Getenv("APPLE_MDM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set APPLE_MDM_TEST_DATABASE_URL for protected administrator integration")
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "administrator_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`); err != nil {
			t.Error(err)
		}
		admin.Close()
	})
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	t.Setenv("ENV", "test")
	model, err := models.New(u.String(), "pgx", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { model.Close() })
	return &testAccountModel{Model: model, databaseURL: u.String()}
}

func TestProtectedAdministratorAtomicCreationAndRestart(t *testing.T) {
	m := accountModel(t)
	config := Config{UserID: "first-admin", PasswordFile: passwordFile(t, testPassword)}
	var output bytes.Buffer
	writer := log.Writer()
	log.SetOutput(&output)
	defer log.SetOutput(writer)
	ctx := context.Background()
	created, err := Initialize(ctx, m.DB, config)
	if err != nil || !created {
		t.Fatal("first administrator was not initialized", created, err)
	}
	user, err := m.Client.User.Get(ctx, config.UserID)
	if err != nil {
		t.Fatal("account does not match the real Ent schema", err)
	}
	if !user.Passwd || user.Use2fa || user.Register != openuem.REGISTER_FORCE_PASSWORD_CHANGE || user.Hash == "" || user.Hash == testPassword {
		t.Fatal("initial password state is invalid")
	}
	if matched, err := argon2id.ComparePasswordAndHash(testPassword, user.Hash); err != nil || !matched {
		t.Fatal("normal console password authentication cannot verify initial credential", err)
	}
	permissions, err := access.NewStore(m.DB)
	if err != nil {
		t.Fatal(err)
	}
	p, err := permissions.Principal(ctx, config.UserID)
	if err != nil || !p.IsAdministrator() || p.Revision != 1 {
		t.Fatal("initial account lacks its atomic administrator grant", p, err)
	}
	var count int
	if err = m.DB.QueryRow(`SELECT COUNT(*) FROM uem_access_audit WHERE action='bootstrap'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("bootstrap audit was not committed once", count, err)
	}
	if strings.Contains(output.String(), testPassword) || strings.Contains(output.String(), user.Hash) {
		t.Fatal("bootstrap leaked credentials to the log")
	}
	// The file may be removed after initialization. Later password/MFA/grant
	// changes must survive startup, even after the bootstrap audit is retained out.
	if err = os.Remove(config.PasswordFile); err != nil {
		t.Fatal(err)
	}
	if err = m.Client.User.Create().SetID("replacement-admin").SetName("Replacement").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if err = permissions.ReplaceGrants(ctx, config.UserID, "replacement-admin", 0, []access.Grant{{Role: access.Administrator}}); err != nil {
		t.Fatal(err)
	}
	if err = permissions.ReplaceGrants(ctx, "replacement-admin", config.UserID, 1, nil); err != nil {
		t.Fatal(err)
	}
	if err = m.Client.User.UpdateOneID(config.UserID).SetHash("changed-password-hash").SetUse2fa(true).SetTotpSecret("retained-mfa").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = m.DB.Exec(`DELETE FROM uem_access_audit WHERE action='bootstrap'`); err != nil {
		t.Fatal(err)
	}
	created, err = Initialize(ctx, m.DB, config)
	if err != nil || created {
		t.Fatal("restart required the original password or repeated initialization", created, err)
	}
	user, err = m.Client.User.Get(ctx, config.UserID)
	if err != nil || user.Hash != "changed-password-hash" || !user.Use2fa || user.TotpSecret != "retained-mfa" {
		t.Fatal("restart reset account credentials", err)
	}
	p, err = permissions.Principal(ctx, config.UserID)
	if err != nil || len(p.Grants) != 0 || p.Revision != 2 {
		t.Fatal("restart restored revoked privileges", p, err)
	}
	if err = m.Client.User.DeleteOneID(config.UserID).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if created, err = Initialize(ctx, m.DB, config); err != nil || created {
		t.Fatal("deleted initial account was recreated", created, err)
	}
	if _, err = m.Client.User.Get(ctx, config.UserID); err == nil {
		t.Fatal("deleted account returned")
	}
	changed := config
	changed.UserID = "replacement-admin"
	if _, err = Initialize(ctx, m.DB, changed); err == nil {
		t.Fatal("changed first-account binding accepted")
	}
}

func TestProtectedAdministratorFailureRollback(t *testing.T) {
	m := accountModel(t)
	ctx := context.Background()
	config := Config{UserID: "initial-admin", PasswordFile: filepath.Join(t.TempDir(), "missing-password")}
	if _, err := Initialize(ctx, m.DB, config); err == nil {
		t.Fatal("missing password accepted")
	}
	assertEmpty := func() {
		t.Helper()
		var count int
		if err := m.DB.QueryRow(`SELECT (SELECT COUNT(*) FROM users)+(SELECT COUNT(*) FROM uem_access_grants)+(SELECT COUNT(*) FROM uem_access_revisions)+(SELECT COUNT(*) FROM uem_access_bootstrap_account)+(SELECT COUNT(*) FROM uem_access_audit)+(SELECT COUNT(*) FROM uem_access_migrations WHERE name='bootstrap')`).Scan(&count); err != nil || count != 0 {
			t.Fatal("failed setup left an account, grant or completion record", count, err)
		}
	}
	assertEmpty()
	config.PasswordFile = passwordFile(t, testPassword)
	if _, err := m.DB.Exec(`CREATE FUNCTION reject_bootstrap_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic audit failure'; END $$; CREATE TRIGGER reject_bootstrap_audit BEFORE INSERT ON uem_access_audit FOR EACH ROW EXECUTE FUNCTION reject_bootstrap_audit()`); err != nil {
		t.Fatal(err)
	}
	if _, err := Initialize(ctx, m.DB, config); err == nil {
		t.Fatal("audit failure accepted")
	}
	assertEmpty()
	data, err := os.ReadFile(config.PasswordFile)
	if err != nil || string(data) != testPassword {
		t.Fatal("failed transaction modified the input credential", err)
	}
	if _, err = m.DB.Exec(`DROP TRIGGER reject_bootstrap_audit ON uem_access_audit`); err != nil {
		t.Fatal(err)
	}
	if created, err := Initialize(ctx, m.DB, config); err != nil || !created {
		t.Fatal("exact retry did not recover", created, err)
	}
	// A retained binding with a lost completion marker is corruption, not a new
	// installation. Do not repair it by re-reading a setup password.
	if _, err = m.DB.Exec(`DELETE FROM uem_access_migrations WHERE name='bootstrap'`); err != nil {
		t.Fatal(err)
	}
	if _, err = Initialize(ctx, m.DB, config); err == nil {
		t.Fatal("lost completion marker silently repaired")
	}
}

func TestProtectedAdministratorConcurrentInitialization(t *testing.T) {
	m := accountModel(t)
	config := Config{UserID: "initial-admin", PasswordFile: passwordFile(t, testPassword)}
	var wg sync.WaitGroup
	results := make(chan bool, 6)
	for range 6 {
		wg.Go(func() {
			created, err := Initialize(context.Background(), m.DB, config)
			if err != nil {
				t.Error(err)
			}
			results <- created
		})
	}
	wg.Wait()
	close(results)
	count := 0
	for created := range results {
		if created {
			count++
		}
	}
	if count != 1 {
		t.Fatal("competing setup processes did not initialize exactly once", count)
	}
	var accounts int
	if err := m.DB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&accounts); err != nil || accounts != 1 {
		t.Fatal("competing setup created extra accounts", accounts, err)
	}
}

func TestProtectedAdministratorDoesNotAdoptUninitializedAccounts(t *testing.T) {
	m := accountModel(t)
	ctx := context.Background()
	if err := m.Client.User.Create().SetID("existing").SetName("Existing").SetHash("unchanged").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	config := Config{UserID: "existing", PasswordFile: passwordFile(t, testPassword)}
	if _, err := Initialize(ctx, m.DB, config); err == nil {
		t.Fatal("existing uninitialized account silently elevated")
	}
	config.UserID = "another"
	if _, err := Initialize(ctx, m.DB, config); err == nil {
		t.Fatal("setup created a new administrator in an occupied installation")
	}
	permissions, _ := access.NewStore(m.DB)
	if err := permissions.Bootstrap(ctx, "existing"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(config.PasswordFile); err != nil {
		t.Fatal(err)
	}
	if created, err := Initialize(ctx, m.DB, config); err != nil || created {
		t.Fatal("already bootstrapped legacy installation was changed", created, err)
	}
	u, err := m.Client.User.Get(ctx, "existing")
	if err != nil || u.Hash != "unchanged" {
		t.Fatal("legacy account changed", err)
	}
}

func TestProtectedAdministratorCancellationAndErrors(t *testing.T) {
	m := accountModel(t)
	config := Config{UserID: "first-admin", PasswordFile: passwordFile(t, testPassword)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Initialize(ctx, m.DB, config); err == nil {
		t.Fatal("cancelled setup succeeded")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	permissions, _ := access.NewStore(m.DB)
	if err := permissions.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := permissions.BootstrapNewAccount(ctx, "first-admin", func(context.Context, *sql.Tx) error { return errors.New("synthetic account failure") }); err == nil {
		t.Fatal("account creation error lost")
	}
	var count int
	if err := m.DB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed/cancelled setup created an account", count, err)
	}
}

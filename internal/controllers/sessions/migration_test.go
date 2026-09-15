package sessions_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-uem/openuem-console/internal/controllers/sessions"
	"github.com/open-uem/openuem-console/internal/models"
	"github.com/open-uem/openuem-console/internal/security/sessiontokens"
	"github.com/open-uem/utils"
)

func TestSessionMigrationConcurrentRestartAndKeyBinding(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(sessionMode(encrypted), func(t *testing.T) {
			f := newLegacySessionFixture(t, encrypted)
			if err := f.store.CommitCtx(t.Context(), "before", nil, time.Now()); !errors.Is(err, sessions.ErrNotInitialized) {
				t.Fatal("unmigrated store admitted writes", err)
			}
			stores := make([]*sessions.PostgresStore, 8)
			var wg sync.WaitGroup
			results := make(chan error, len(stores))
			for i := range stores {
				stores[i] = sessions.NewWithConfig(f.pool, sessions.Config{EncryptionMasterKey: f.key})
				wg.Go(func() { results <- stores[i].Migrate(t.Context()) })
			}
			wg.Wait()
			close(results)
			for err := range results {
				if err != nil {
					t.Fatal("concurrent migration failed", err)
				}
			}
			if err := stores[0].CommitCtx(t.Context(), "owned", []byte("retained"), time.Now().Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"", strings.Repeat("k", 32), strings.Repeat("x", 32), "invalid"} {
				if key == f.key {
					continue
				}
				bad := sessions.NewWithConfig(f.pool, sessions.Config{EncryptionMasterKey: key})
				if err := bad.Migrate(t.Context()); err == nil {
					t.Fatal("different key/mode accepted")
				}
				if _, _, err := bad.FindCtx(t.Context(), "owned"); !errors.Is(err, sessions.ErrNotInitialized) {
					t.Fatal("failed initialization allowed reads", err)
				}
			}
			// The ordinary Ent startup must retain the additive index and trigger.
			url := f.pool.Config().ConnString()
			model, err := models.New(url, "pgx", "example.test")
			if err != nil {
				t.Fatal(err)
			}
			defer model.Close()
			if _, err = model.Client.Sessions.Delete().Exec(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err = stores[7].CommitCtx(t.Context(), "owned", nil, time.Now().Add(time.Hour)); !errors.Is(err, sessions.ErrRevoked) {
				t.Fatal("schema restart discarded durable revocation", err)
			}
			// Pre-upgrade writers fail rather than silently insert unindexed rows.
			if _, err = f.model.DB.Exec(`INSERT INTO sessions(token,data,expiry) VALUES('old-writer',$1,$2)`, []byte("legacy"), time.Now().Add(time.Hour)); err == nil {
				t.Fatal("old writer bypassed mandatory token index")
			}
		})
	}
}

func TestSessionMigrationRetiresDuplicatesAcrossBatches(t *testing.T) {
	f := newLegacySessionFixture(t, true, 1)
	token := strings.Repeat("d", 43)
	rows := make([][]any, 1002)
	for i := range rows {
		record, err := utils.EncryptSensitiveField(token, f.key)
		if err != nil {
			t.Fatal(err)
		}
		rows[i] = []any{record, []byte("duplicate"), time.Now().Add(time.Hour)}
	}
	if _, err := f.pool.CopyFrom(t.Context(), pgx.Identifier{"sessions"}, []string{"token", "data", "expiry"}, pgx.CopyFromRows(rows)); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	var live, revoked int
	if err := f.model.DB.QueryRow(`SELECT (SELECT count(*) FROM sessions),(SELECT count(*) FROM sessions_revocations)`).Scan(&live, &revoked); err != nil || live != 0 || revoked != 1 {
		t.Fatal("duplicate batches did not converge on one retirement", live, revoked, err)
	}
	if err := f.store.CommitCtx(t.Context(), token, nil, time.Now().Add(time.Hour)); !errors.Is(err, sessions.ErrRevoked) {
		t.Fatal("duplicate token was reusable", err)
	}
}

func TestSessionMigrationWrongLegacyKeyRollsBack(t *testing.T) {
	f := newLegacySessionFixture(t, true)
	record, err := utils.EncryptSensitiveField(strings.Repeat("a", 43), strings.Repeat("x", 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.model.DB.Exec(`INSERT INTO sessions(token,data,expiry) VALUES($1,$2,$3)`, record, []byte("original"), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err = f.store.Migrate(t.Context()); err == nil {
		t.Fatal("wrong legacy key silently double-encrypted a token")
	}
	var unchanged string
	if err = f.model.DB.QueryRow(`SELECT token FROM sessions`).Scan(&unchanged); err != nil || unchanged != record {
		t.Fatal("failed migration changed legacy token", err)
	}
	correct := sessions.NewWithConfig(f.pool, sessions.Config{EncryptionMasterKey: strings.Repeat("x", 32)})
	if err = correct.Migrate(t.Context()); err != nil {
		t.Fatal("rolled-back migration could not be retried", err)
	}
}

func TestSessionMigrationCanceledLockCanRetry(t *testing.T) {
	f := newLegacySessionFixture(t, false)
	tx, err := f.model.DB.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`LOCK TABLE sessions IN ACCESS SHARE MODE`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	if err = f.store.Migrate(ctx); err == nil {
		t.Fatal("migration ignored its blocked deadline")
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err = f.store.Migrate(t.Context()); err != nil {
		t.Fatal("canceled migration could not retry", err)
	}
}

func TestSessionStoreQuotedTableIdentifiers(t *testing.T) {
	f := newLegacySessionFixture(t, true)
	for _, name := range []string{"owned'$$\"\\ session", strings.Repeat("long_", 10) + "one", strings.Repeat("long_", 10) + "two"} {
		table := pgx.Identifier{name}.Sanitize()
		if _, err := f.model.DB.Exec(`CREATE TABLE ` + table + ` (token text PRIMARY KEY,data bytea NOT NULL,expiry timestamptz NOT NULL)`); err != nil {
			t.Fatal(err)
		}
		store := sessions.NewWithConfig(f.pool, sessions.Config{TableName: name, EncryptionMasterKey: f.key})
		if err := store.Migrate(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := store.CommitCtx(t.Context(), "owned", []byte("current"), time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		tx, err := f.model.DB.BeginTx(t.Context(), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		var schema string
		if err = tx.QueryRow(`SELECT current_schema()`).Scan(&schema); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(`SET LOCAL search_path=pg_catalog`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`DELETE FROM ` + pgx.Identifier{schema, name}.Sanitize()); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
		if err := store.CommitCtx(t.Context(), "owned", nil, time.Now().Add(time.Hour)); !errors.Is(err, sessions.ErrRevoked) {
			t.Fatal("custom table deletion did not revoke", err)
		}
	}
}

func TestSessionLookupUsesIndexAndProtectsDigest(t *testing.T) {
	f := newSessionFixture(t, true)
	rows := make([][]any, 2000)
	for i := range rows {
		token := fmt.Sprintf("owned-token-%08d", i)
		record, err := utils.EncryptSensitiveField(token, f.key)
		if err != nil {
			t.Fatal(err)
		}
		rows[i] = []any{record, sessiontokens.Lookup(token), []byte("owned"), time.Now().Add(time.Hour)}
	}
	if _, err := f.pool.CopyFrom(t.Context(), pgx.Identifier{"sessions"}, []string{"token", "token_lookup", "data", "expiry"}, pgx.CopyFromRows(rows)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), `ANALYZE sessions`); err != nil {
		t.Fatal(err)
	}
	target := "owned-token-00001000"
	lookup := sessiontokens.Lookup(target)
	var plan []byte
	if err := f.model.DB.QueryRow(`EXPLAIN(FORMAT JSON) SELECT token,data FROM sessions s WHERE token_lookup=$1 AND current_timestamp<expiry AND NOT EXISTS(SELECT 1 FROM sessions_revocations r WHERE r.token_lookup=s.token_lookup)`, lookup).Scan(&plan); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(plan, []byte(`sessions_lookup_idx`)) {
		t.Fatal("lookup did not use its token index", string(plan))
	}
	data, found, err := f.store.FindCtx(t.Context(), target)
	if err != nil || !found || string(data) != "owned" {
		t.Fatal("indexed lookup failed", err)
	}
	for _, bearer := range []string{fmt.Sprintf("%x", lookup), rows[1000][0].(string)} {
		if _, found, err = f.store.FindCtx(t.Context(), bearer); err != nil || found {
			t.Fatal("database index/ciphertext became a browser credential", err)
		}
	}
	if _, err = f.pool.Exec(t.Context(), `UPDATE sessions SET token='corrupt' WHERE token_lookup=$1`, lookup); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.store.FindCtx(t.Context(), target); err == nil {
		t.Fatal("mismatched indexed token was admitted")
	}
}

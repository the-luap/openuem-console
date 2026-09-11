package sessions

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/open-uem/openuem-console/internal/security/sessiontokens"
	"github.com/open-uem/utils"
)

var ErrNotInitialized = errors.New("session store migration has not completed")
var ErrRevoked = errors.New("session token has been revoked")

// Sibling relations stay in the configured table's schema. Long names use a
// digest suffix so PostgreSQL's identifier truncation cannot alias two stores.
func sessionRelation(parts []string, suffix string) string {
	parts = append([]string(nil), parts...)
	base := parts[len(parts)-1]
	if len(base) > 30 {
		hash := sha256.Sum256([]byte(base))
		base = "uem_session_" + hex.EncodeToString(hash[:10])
	}
	parts[len(parts)-1] = base + suffix
	return pgx.Identifier(parts).Sanitize()
}

// Migrate must complete before serving requests. All old console writers must
// be stopped for this upgrade: their inserts do not supply the required index.
// Deletion receipts are deliberately permanent until a separately proven
// retention policy can bound every outstanding writer's lifetime.
func (p *PostgresStore) Migrate(ctx context.Context) error {
	if _, _, err := sessiontokens.Decode("", p.encryptionMasterKey); err != nil {
		return err
	}
	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer rollbackSession(ctx, tx)
	if _, err = tx.Exec(ctx, fmt.Sprintf(`LOCK TABLE %s IN ACCESS EXCLUSIVE MODE`, p.tableName)); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (singleton boolean PRIMARY KEY CHECK(singleton), key_check bytea NOT NULL CHECK(octet_length(key_check)=32))`, p.configName)); err != nil {
		return err
	}
	expected := sha256.Sum256([]byte("openuem/session-store/config/v1\x00" + p.encryptionMasterKey))
	var actual []byte
	err = tx.QueryRow(ctx, fmt.Sprintf(`SELECT key_check FROM %s WHERE singleton`, p.configName)).Scan(&actual)
	if err == nil {
		if !bytes.Equal(actual, expected[:]) {
			return errors.New("session store encryption configuration does not match its migration")
		}
	} else if errors.Is(err, pgx.ErrNoRows) {
		if err = p.migrateTokens(ctx, tx); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, fmt.Sprintf(`INSERT INTO %s(singleton,key_check) VALUES(true,$1)`, p.configName), expected[:]); err != nil {
			return err
		}
	} else {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	p.ready.Store(true)
	return nil
}

func (p *PostgresStore) migrateTokens(ctx context.Context, tx pgx.Tx) error {
	statements := []string{
		fmt.Sprintf(`ALTER TABLE %s ADD COLUMN IF NOT EXISTS token_lookup bytea CHECK(octet_length(token_lookup)=32)`, p.tableName),
		fmt.Sprintf(`CREATE UNIQUE INDEX IF NOT EXISTS %s ON %s(token_lookup)`, p.indexName, p.tableName),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (token_lookup bytea PRIMARY KEY CHECK(octet_length(token_lookup)=32), revoked_at timestamptz NOT NULL DEFAULT clock_timestamp())`, p.revocationsName),
	}
	for _, statement := range statements {
		if _, err := tx.Exec(ctx, statement); err != nil {
			return err
		}
	}
	// Triggers also execute through other database clients. Bind their relation
	// names now so a caller's different search_path cannot redirect a receipt.
	table, err := qualifiedSessionRelation(ctx, tx, p.tableName)
	if err != nil {
		return err
	}
	receipts, err := qualifiedSessionRelation(ctx, tx, p.revocationsName)
	if err != nil {
		return err
	}
	// SQL identifiers are quoted independently; the entire function body is a
	// SQL string literal, so even unusual configured identifiers remain inert.
	body := fmt.Sprintf(`BEGIN
 IF TG_OP = 'TRUNCATE' THEN
   INSERT INTO %s(token_lookup) SELECT token_lookup FROM %s WHERE token_lookup IS NOT NULL ON CONFLICT DO NOTHING;
   RETURN NULL;
 END IF;
 IF OLD.token_lookup IS NOT NULL THEN
   INSERT INTO %s(token_lookup) VALUES(OLD.token_lookup) ON CONFLICT DO NOTHING;
 END IF;
 RETURN OLD;
END`, receipts, table, receipts)
	statements = []string{
		fmt.Sprintf(`CREATE OR REPLACE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS E'%s'`, p.revokeFunction, strings.NewReplacer(`\`, `\\`, "'", "''").Replace(body)),
		fmt.Sprintf(`CREATE TRIGGER uem_session_delete AFTER DELETE ON %s FOR EACH ROW EXECUTE FUNCTION %s()`, p.tableName, p.revokeFunction),
		fmt.Sprintf(`CREATE TRIGGER uem_session_truncate BEFORE TRUNCATE ON %s FOR EACH STATEMENT EXECUTE FUNCTION %s()`, p.tableName, p.revokeFunction),
	}
	for _, statement := range statements {
		if _, err := tx.Exec(ctx, statement); err != nil {
			return err
		}
	}
	for {
		// Closing each bounded cursor before updates also supports a one-connection pool.
		rows, err := tx.Query(ctx, fmt.Sprintf(`SELECT token FROM %s WHERE token_lookup IS NULL ORDER BY token LIMIT 500`, p.tableName))
		if err != nil {
			return err
		}
		var records []string
		for rows.Next() {
			var record string
			if err = rows.Scan(&record); err != nil {
				rows.Close()
				return err
			}
			records = append(records, record)
		}
		rows.Close()
		if err = rows.Err(); err != nil {
			return err
		}
		if len(records) == 0 {
			break
		}
		for _, record := range records {
			plain, encrypted, err := sessiontokens.Decode(record, p.encryptionMasterKey)
			if err != nil {
				return err
			}
			// A legacy ciphertext which cannot be opened is not a plaintext token.
			// Refuse accidental double encryption or migration under a different key.
			if raw, e := hex.DecodeString(record); e == nil && len(raw) >= 28 && !encrypted {
				return errors.New("legacy session ciphertext requires its original encryption key")
			}
			lookup := sessiontokens.Lookup(plain)
			var duplicate, revoked bool
			if err = tx.QueryRow(ctx, fmt.Sprintf(`SELECT EXISTS(SELECT 1 FROM %s WHERE token_lookup=$1), EXISTS(SELECT 1 FROM %s WHERE token_lookup=$1)`, p.tableName, p.revocationsName), lookup).Scan(&duplicate, &revoked); err != nil {
				return err
			}
			if duplicate || revoked {
				if _, err = tx.Exec(ctx, fmt.Sprintf(`INSERT INTO %s(token_lookup) VALUES($1) ON CONFLICT DO NOTHING`, p.revocationsName), lookup); err != nil {
					return err
				}
				if _, err = tx.Exec(ctx, fmt.Sprintf(`DELETE FROM %s WHERE token=$1 OR token_lookup=$2`, p.tableName), record, lookup); err != nil {
					return err
				}
				continue
			}
			target := record
			if p.encryptionMasterKey != "" && !encrypted {
				if target, err = utils.EncryptSensitiveField(plain, p.encryptionMasterKey); err != nil {
					return err
				}
			}
			if _, err = tx.Exec(ctx, fmt.Sprintf(`UPDATE %s SET token=$2,token_lookup=$3 WHERE token=$1`, p.tableName), record, target, lookup); err != nil {
				return err
			}
		}
	}
	_, err = tx.Exec(ctx, fmt.Sprintf(`ALTER TABLE %s ALTER COLUMN token_lookup SET NOT NULL`, p.tableName))
	return err
}

func qualifiedSessionRelation(ctx context.Context, tx pgx.Tx, name string) (string, error) {
	var schema, relation string
	err := tx.QueryRow(ctx, `SELECT n.nspname,c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE c.oid=pg_catalog.to_regclass($1)`, name).Scan(&schema, &relation)
	if err != nil {
		return "", err
	}
	return pgx.Identifier{schema, relation}.Sanitize(), nil
}

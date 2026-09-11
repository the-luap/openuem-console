package sessions

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-uem/openuem-console/internal/security/sessiontokens"
	"github.com/open-uem/utils"
)

// Originally adapted from the SCS pgxstore, then extended with encrypted token
// records, indexed lookup, durable revocation and joined cleanup.

// PostgresStore represents the session store.
type PostgresStore struct {
	pool                *pgxpool.Pool
	stopCleanup         context.CancelFunc
	cleanupDone         chan struct{}
	tableName           string
	encryptionMasterKey string
	revocationsName     string
	configName          string
	indexName           string
	revokeFunction      string
	ready               atomic.Bool
}

type Config struct {
	// CleanUpInterval is the interval between each cleanup operation.
	// If set to 0, the cleanup operation is disabled.
	CleanUpInterval time.Duration

	// TableName is the name of the table where the session data will be stored.
	// If not set, it will default to "sessions".
	TableName string

	// EncryptionMasterKey is the key used to encrypt tokens
	EncryptionMasterKey string
}

// New returns a new PostgresStore instance, with a background cleanup goroutine
// that runs every 5 minutes to remove expired session data.
func NewPostgresStore(pool *pgxpool.Pool, encryptionMasterKey string) *PostgresStore {
	return NewWithConfig(pool, Config{
		CleanUpInterval:     5 * time.Minute,
		EncryptionMasterKey: encryptionMasterKey,
	})
}

// NewWithCleanupInterval returns a new PostgresStore instance. The cleanupInterval
// parameter controls how frequently expired session data is removed by the
// background cleanup goroutine. Setting it to 0 prevents the cleanup goroutine
// from running (i.e. expired sessions will not be removed).
func NewWithCleanupInterval(pool *pgxpool.Pool, cleanupInterval time.Duration) *PostgresStore {
	return NewWithConfig(pool, Config{
		CleanUpInterval: cleanupInterval,
	})
}

// NewWithConfig returns a new PostgresStore instance with the given configuration.
// If the TableName field is empty, it will be set to "sessions".
// If the CleanUpInterval field is 0, the cleanup goroutine will not be started.
// Call Migrate before use; requests and cleanup cannot access an uninitialized store.
func NewWithConfig(pool *pgxpool.Pool, config Config) *PostgresStore {
	if config.TableName == "" {
		config.TableName = "sessions"
	}
	parts := strings.Split(config.TableName, ".")
	p := &PostgresStore{pool: pool, tableName: pgx.Identifier(parts).Sanitize(), encryptionMasterKey: config.EncryptionMasterKey,
		revocationsName: sessionRelation(parts, "_revocations"), configName: sessionRelation(parts, "_config"),
		indexName: sessionRelation(parts[len(parts)-1:], "_lookup_idx"), revokeFunction: sessionRelation(parts, "_revoke")}
	if config.CleanUpInterval > 0 {
		var ctx context.Context
		ctx, p.stopCleanup = context.WithCancel(context.Background())
		p.cleanupDone = make(chan struct{})
		go p.startCleanup(ctx, config.CleanUpInterval)
	}
	return p
}

// FindCtx uses the unique logical-token index. Verify the actual record as well:
// an encrypted database ID or an incompatible encryption key is never a bearer.
func (p *PostgresStore) FindCtx(ctx context.Context, token string) ([]byte, bool, error) {
	if !p.ready.Load() {
		return nil, false, ErrNotInitialized
	}
	var data []byte
	var record string
	err := p.pool.QueryRow(ctx, fmt.Sprintf(`SELECT token,data FROM %s s WHERE s.token_lookup=$1 AND current_timestamp<s.expiry AND NOT EXISTS(SELECT 1 FROM %s r WHERE r.token_lookup=s.token_lookup)`, p.tableName, p.revocationsName), sessiontokens.Lookup(token)).Scan(&record, &data)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if err = p.verifyRecord(record, token); err != nil {
		return nil, false, err
	}
	return data, true, nil
}

func (p *PostgresStore) verifyRecord(record, token string) error {
	plain, encrypted, err := sessiontokens.Decode(record, p.encryptionMasterKey)
	if err != nil {
		return err
	}
	if plain != token || (p.encryptionMasterKey != "" && !encrypted) {
		return errors.New("session token record does not match its encryption configuration")
	}
	return nil
}

func rollbackSession(parent context.Context, tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 2*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}

// Same-token writers take the advisory lock before the row lock. Ordinary SQL
// deletions take only the row lock and record revocation in that transaction.
// Reading revocation AFTER acquiring the row lock is essential: a delete may
// have completed while the writer was waiting for the row.
func (p *PostgresStore) tokenTransaction(ctx context.Context, lookup []byte) (pgx.Tx, error) {
	if !p.ready.Load() {
		return nil, ErrNotInitialized
	}
	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(binary.BigEndian.Uint64(lookup[:8]))); err != nil {
		rollbackSession(ctx, tx)
		return nil, err
	}
	return tx, nil
}

func (p *PostgresStore) CommitCtx(ctx context.Context, token string, data []byte, expiry time.Time) error {
	lookup := sessiontokens.Lookup(token)
	tx, err := p.tokenTransaction(ctx, lookup)
	if err != nil {
		return err
	}
	defer rollbackSession(ctx, tx)
	var record string
	err = tx.QueryRow(ctx, fmt.Sprintf(`SELECT token FROM %s WHERE token_lookup=$1 FOR UPDATE`, p.tableName), lookup).Scan(&record)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if record != "" {
		if err = p.verifyRecord(record, token); err != nil {
			return err
		}
	}
	var revoked bool
	if err = tx.QueryRow(ctx, fmt.Sprintf(`SELECT EXISTS(SELECT 1 FROM %s WHERE token_lookup=$1)`, p.revocationsName), lookup).Scan(&revoked); err != nil {
		return err
	}
	if revoked {
		return ErrRevoked
	}
	if record == "" {
		record = token
		if p.encryptionMasterKey != "" {
			if record, err = utils.EncryptSensitiveField(token, p.encryptionMasterKey); err != nil {
				return err
			}
		}
	}
	if _, err = tx.Exec(ctx, fmt.Sprintf(`INSERT INTO %s(token,token_lookup,data,expiry) VALUES($1,$2,$3,$4) ON CONFLICT(token_lookup) DO UPDATE SET data=EXCLUDED.data,expiry=EXCLUDED.expiry`, p.tableName), record, lookup, data, expiry); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (p *PostgresStore) DeleteCtx(ctx context.Context, token string) error {
	if !p.ready.Load() {
		return ErrNotInitialized
	}
	// SCS destroys an empty, never-committed session without a token.
	if token == "" {
		return nil
	}
	lookup := sessiontokens.Lookup(token)
	tx, err := p.tokenTransaction(ctx, lookup)
	if err != nil {
		return err
	}
	defer rollbackSession(ctx, tx)
	if _, err = tx.Exec(ctx, fmt.Sprintf(`DELETE FROM %s WHERE token_lookup=$1`, p.tableName), lookup); err != nil {
		return err
	}
	// Also fence a generated token whose first commit is still outstanding.
	if _, err = tx.Exec(ctx, fmt.Sprintf(`INSERT INTO %s(token_lookup) VALUES($1) ON CONFLICT DO NOTHING`, p.revocationsName), lookup); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (p *PostgresStore) AllCtx(ctx context.Context) (map[string][]byte, error) {
	if !p.ready.Load() {
		return nil, ErrNotInitialized
	}
	rows, err := p.pool.Query(ctx, fmt.Sprintf(`SELECT token,token_lookup,data FROM %s s WHERE current_timestamp<s.expiry AND NOT EXISTS(SELECT 1 FROM %s r WHERE r.token_lookup=s.token_lookup)`, p.tableName, p.revocationsName))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string][]byte)
	for rows.Next() {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		var record string
		var lookup, data []byte
		if err = rows.Scan(&record, &lookup, &data); err != nil {
			return nil, err
		}
		token, _, err := sessiontokens.Decode(record, p.encryptionMasterKey)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(lookup, sessiontokens.Lookup(token)) {
			return nil, errors.New("session token index does not match its record")
		}
		if err = p.verifyRecord(record, token); err != nil {
			return nil, err
		}
		result[token] = data
	}
	return result, rows.Err()
}

func (p *PostgresStore) startCleanup(ctx context.Context, interval time.Duration) {
	defer close(p.cleanupDone)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if !p.ready.Load() {
				continue
			}
			attempt, cancel := context.WithTimeout(ctx, 30*time.Second)
			err := p.deleteExpired(attempt)
			cancel()
			if err != nil && ctx.Err() == nil {
				log.Println(err)
			}
		case <-ctx.Done():
			return
		}
	}
}

// StopCleanup cancels active database work and joins the worker. Concurrent and
// repeated calls are safe; disabled cleanup needs no shutdown operation.
func (p *PostgresStore) StopCleanup() {
	if p.stopCleanup != nil {
		p.stopCleanup()
		<-p.cleanupDone
	}
}

func (p *PostgresStore) deleteExpired(ctx context.Context) error {
	stmt := fmt.Sprintf("DELETE FROM %s WHERE expiry < current_timestamp", p.tableName)
	_, err := p.pool.Exec(ctx, stmt)
	return err
}

// We have to add the plain Store methods here to be recognized a Store
// by the go compiler. Not using a separate type makes any errors caught
// only at runtime instead of compile time.

func (p *PostgresStore) Find(token string) (b []byte, exists bool, err error) {
	panic("missing context arg")
}

func (p *PostgresStore) Commit(token string, b []byte, expiry time.Time) error {
	panic("missing context arg")
}

func (p *PostgresStore) Delete(token string) error {
	panic("missing context arg")
}

func (p *PostgresStore) All() (map[string][]byte, error) {
	panic("missing context arg")
}

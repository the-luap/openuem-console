package sessions

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-uem/openuem-console/internal/security/sessiontokens"
	"github.com/open-uem/utils"
)

// This code is cherry-picked from https://github.com/alexedwards/scs/blob/209de6e426de9259665975ce16b91331d228f052/pgxstore/pgxstore.go#L11
// so we can support token encryption/decryption

// PostgresStore represents the session store.
type PostgresStore struct {
	pool                *pgxpool.Pool
	stopCleanup         chan bool
	tableName           string
	encryptionMasterKey string
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
func NewWithConfig(pool *pgxpool.Pool, config Config) *PostgresStore {
	if config.TableName == "" {
		config.TableName = "sessions"
	}
	config.TableName = pgx.Identifier(strings.Split(config.TableName, ".")).Sanitize()

	p := &PostgresStore{pool: pool, tableName: config.TableName, encryptionMasterKey: config.EncryptionMasterKey}
	if config.CleanUpInterval > 0 {
		p.stopCleanup = make(chan bool)
		go p.startCleanup(config.CleanUpInterval)
	}
	return p
}

// FindCtx returns the data for a given session token from the PostgresStore instance.
// If the session token is not found or is expired, the returned exists flag will
// be set to false.
var errAmbiguousSession = errors.New("multiple records represent one session token")

func (p *PostgresStore) FindCtx(ctx context.Context, token string) ([]byte, bool, error) {
	if p.encryptionMasterKey == "" {
		var data []byte
		err := p.pool.QueryRow(ctx, fmt.Sprintf("SELECT data FROM %s WHERE token=$1 AND current_timestamp<expiry", p.tableName), token).Scan(&data)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, nil
		}
		return data, err == nil, err
	}
	rows, err := p.pool.Query(ctx, fmt.Sprintf("SELECT token,data FROM %s WHERE current_timestamp<expiry", p.tableName))
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var result []byte
	found := false
	for rows.Next() {
		if err = ctx.Err(); err != nil {
			return nil, false, err
		}
		var record string
		var data []byte
		if err = rows.Scan(&record, &data); err != nil {
			return nil, false, err
		}
		plain, encrypted, err := sessiontokens.Decode(record, p.encryptionMasterKey)
		if err != nil {
			return nil, false, err
		}
		// Plaintext rows await the existing startup migration; they must not make a
		// ciphertext database value usable as a browser credential under another key.
		if encrypted && plain == token {
			if found {
				// Retire ambiguous legacy credentials and let the browser start
				// a new session. Release the cursor before opening a transaction.
				rows.Close()
				return nil, false, p.DeleteCtx(ctx, token)
			}
			result = append([]byte(nil), data...)
			found = true
		}
	}
	if err = rows.Err(); err != nil {
		return nil, false, err
	}
	return result, found, nil
}

// Encrypted updates hold a table write lock while resolving randomized legacy
// ciphertext keys. This also serializes ordinary SQL token migration/deletion.
// Readers retain PostgreSQL's statement snapshot and do not need this lock.
func (p *PostgresStore) tokenTransaction(ctx context.Context) (pgx.Tx, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, fmt.Sprintf("LOCK TABLE %s IN SHARE ROW EXCLUSIVE MODE", p.tableName)); err != nil {
		rollbackSession(ctx, tx)
		return nil, err
	}
	return tx, nil
}

func rollbackSession(parent context.Context, tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 2*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}

func (p *PostgresStore) matchingRecords(ctx context.Context, tx pgx.Tx, token string) ([]string, error) {
	rows, err := tx.Query(ctx, fmt.Sprintf("SELECT token FROM %s", p.tableName))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var found []string
	for rows.Next() {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		var record string
		if err = rows.Scan(&record); err != nil {
			return nil, err
		}
		plain, _, err := sessiontokens.Decode(record, p.encryptionMasterKey)
		if err != nil {
			return nil, err
		}
		if plain == token {
			found = append(found, record)
		}
	}
	return found, rows.Err()
}

func (p *PostgresStore) CommitCtx(ctx context.Context, token string, data []byte, expiry time.Time) error {
	if p.encryptionMasterKey == "" {
		_, err := p.pool.Exec(ctx, fmt.Sprintf("INSERT INTO %s(token,data,expiry) VALUES($1,$2,$3) ON CONFLICT(token) DO UPDATE SET data=EXCLUDED.data,expiry=EXCLUDED.expiry", p.tableName), token, data, expiry)
		return err
	}
	tx, err := p.tokenTransaction(ctx)
	if err != nil {
		return err
	}
	defer rollbackSession(ctx, tx)
	found, err := p.matchingRecords(ctx, tx, token)
	if err != nil {
		return err
	}
	if len(found) > 1 {
		return errAmbiguousSession
	}
	record := ""
	if len(found) == 1 {
		record = found[0]
	}
	if record == "" || record == token {
		encrypted, err := utils.EncryptSensitiveField(token, p.encryptionMasterKey)
		if err != nil {
			return err
		}
		if record != "" {
			if _, err = tx.Exec(ctx, fmt.Sprintf("UPDATE %s SET token=$2 WHERE token=$1", p.tableName), record, encrypted); err != nil {
				return err
			}
		}
		record = encrypted
	}
	if _, err = tx.Exec(ctx, fmt.Sprintf("INSERT INTO %s(token,data,expiry) VALUES($1,$2,$3) ON CONFLICT(token) DO UPDATE SET data=EXCLUDED.data,expiry=EXCLUDED.expiry", p.tableName), record, data, expiry); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (p *PostgresStore) DeleteCtx(ctx context.Context, token string) error {
	if p.encryptionMasterKey == "" {
		_, err := p.pool.Exec(ctx, fmt.Sprintf("DELETE FROM %s WHERE token=$1", p.tableName), token)
		return err
	}
	tx, err := p.tokenTransaction(ctx)
	if err != nil {
		return err
	}
	defer rollbackSession(ctx, tx)
	records, err := p.matchingRecords(ctx, tx, token)
	if err != nil {
		return err
	}
	// Remove every old physical representation, including expired duplicates.
	if len(records) > 0 {
		if _, err = tx.Exec(ctx, fmt.Sprintf("DELETE FROM %s WHERE token=ANY($1::text[])", p.tableName), records); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (p *PostgresStore) AllCtx(ctx context.Context) (map[string][]byte, error) {
	rows, err := p.pool.Query(ctx, fmt.Sprintf("SELECT token,data FROM %s WHERE current_timestamp<expiry", p.tableName))
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
		var data []byte
		if err = rows.Scan(&record, &data); err != nil {
			return nil, err
		}
		token, _, err := sessiontokens.Decode(record, p.encryptionMasterKey)
		if err != nil {
			return nil, err
		}
		if _, duplicate := result[token]; duplicate {
			return nil, errAmbiguousSession
		}
		result[token] = data
	}
	return result, rows.Err()
}

func (p *PostgresStore) startCleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	for {
		select {
		case <-ticker.C:
			err := p.deleteExpired()
			if err != nil {
				log.Println(err)
			}
		case <-p.stopCleanup:
			ticker.Stop()
			return
		}
	}
}

// StopCleanup terminates the background cleanup goroutine for the PostgresStore
// instance. It's rare to terminate this; generally PostgresStore instances and
// their cleanup goroutines are intended to be long-lived and run for the lifetime
// of your application.
//
// There may be occasions though when your use of the PostgresStore is transient.
// An example is creating a new PostgresStore instance in a test function. In this
// scenario, the cleanup goroutine (which will run forever) will prevent the
// PostgresStore object from being garbage collected even after the test function
// has finished. You can prevent this by manually calling StopCleanup.
func (p *PostgresStore) StopCleanup() {
	if p.stopCleanup != nil {
		p.stopCleanup <- true
	}
}

func (p *PostgresStore) deleteExpired() error {
	stmt := fmt.Sprintf("DELETE FROM %s WHERE expiry < current_timestamp", p.tableName)
	_, err := p.pool.Exec(context.Background(), stmt)
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

// Package preferences stores non-security account display preferences.
package preferences

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"time"
)

var (
	ErrInvalid  = errors.New("invalid account language")
	ErrNotFound = errors.New("account not found")
)

//go:embed migrations/*.sql
var migrations embed.FS

type Store struct{ db *sql.DB }

func NewStore(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("preferences require a database")
	}
	return &Store{db: db}, nil
}

func (s *Store) Migrate(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684627925)`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS uem_preference_migrations(name TEXT PRIMARY KEY,applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		var applied bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_preference_migrations WHERE name=$1)`, name).Scan(&applied); err != nil {
			return err
		}
		if applied {
			continue
		}
		data, err := migrations.ReadFile(name)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, string(data)); err != nil {
			return fmt.Errorf("preference migration %s: %w", name, err)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO uem_preference_migrations(name) VALUES($1)`, name); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Language returns an empty code when the account follows its browser.
func (s *Store) Language(ctx context.Context, userID string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var code string
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(p.locale,'') FROM users u LEFT JOIN uem_user_preferences p ON p.user_id=u.uid WHERE u.uid=$1`, userID).Scan(&code)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if !ValidLanguage(code) {
		return "", ErrInvalid
	}
	return code, nil
}

// SetLanguage changes only the account selected by the authenticated caller.
// The latest committed selection takes effect on the account's next request.
func (s *Store) SetLanguage(ctx context.Context, userID, code string) error {
	if !ValidLanguage(code) {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	result, err := s.db.ExecContext(ctx, `INSERT INTO uem_user_preferences(user_id,locale) SELECT uid,$2 FROM users WHERE uid=$1 ON CONFLICT(user_id) DO UPDATE SET locale=EXCLUDED.locale`, userID, code)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return ErrNotFound
	}
	return nil
}

package access

import (
	"context"
	"database/sql"
	"errors"
)

// AuthorizeTransaction holds a shared permission lock until the caller commits
// or rolls back. Sensitive bounded reads cannot race a permission replacement.
// The caller authenticates the console session before requesting authorization.
func (s *Store) AuthorizeTransaction(ctx context.Context, tx *sql.Tx, actor string, capability Capability, scope Scope) error {
	if tx == nil || actor == "" {
		return ErrDenied
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock_shared(684627902)`); err != nil {
		return err
	}
	var user string
	if err := tx.QueryRowContext(ctx, `SELECT uid FROM users WHERE uid=$1 FOR SHARE`, actor).Scan(&user); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrDenied
		}
		return err
	}
	p, err := principal(ctx, tx, actor)
	if err != nil {
		return err
	}
	if !p.Can(capability, scope) {
		return ErrDenied
	}
	return nil
}

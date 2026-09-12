package oidcaccounts

import (
	"context"
	"database/sql"
	"time"
)

// CapturePolicy binds current configuration values to a durable generation.
// The returned policy must remain attached to the original authentication flow;
// later changes, including restoring the same values, require a fresh sign-in.
func (s *Store) CapturePolicy(parent context.Context, expected Policy) (Policy, error) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return Policy{}, err
	}
	defer tx.Rollback()
	current, err := readPolicy(ctx, tx)
	if err != nil {
		return Policy{}, err
	}
	values := current
	values.Generation = ""
	if values != expected {
		return Policy{}, ErrConflict
	}
	if err = tx.Commit(); err != nil {
		return Policy{}, err
	}
	return current, nil
}

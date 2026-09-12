package access

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

// BootstrapNewAccount atomically creates the first account, its administrator
// grant, audit and permanent completion record. The callback is called only for
// a fresh account registry, inside the locked transaction, so credentials can be
// removed after a successful bootstrap without breaking subsequent starts.
func (s *Store) BootstrapNewAccount(ctx context.Context, userID string, create func(context.Context, *sql.Tx) error) (bool, error) {
	if userID == "" || create == nil {
		return false, errors.New("first-administrator configuration is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684627902)`); err != nil {
		return false, err
	}
	var initialized bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_access_migrations WHERE name='bootstrap')`).Scan(&initialized); err != nil {
		return false, err
	}
	var original string
	err = tx.QueryRowContext(ctx, `SELECT user_id FROM uem_access_bootstrap_account WHERE singleton`).Scan(&original)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	if err == nil && (!initialized || original != userID) {
		return false, errors.New("first-administrator binding differs from the installation record")
	}
	if initialized {
		// Older installations already have a permanent bootstrap marker. Adopting
		// the protected mode must not add an account or change existing grants.
		return false, tx.Commit()
	}
	// Serialize ordinary registrations as well as competing setup processes.
	if _, err = tx.ExecContext(ctx, `LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return false, err
	}
	var occupied bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM users) OR EXISTS(SELECT 1 FROM uem_access_grants) OR EXISTS(SELECT 1 FROM uem_access_revisions)`).Scan(&occupied); err != nil {
		return false, err
	}
	if occupied {
		return false, errors.New("first-administrator setup requires an empty account registry")
	}
	if err = create(ctx, tx); err != nil {
		return false, err
	}
	var valid bool
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*)=1 AND BOOL_AND(uid=$1) FROM users`, userID).Scan(&valid); err != nil {
		return false, err
	}
	if !valid {
		return false, errors.New("first-administrator account was not created exclusively")
	}
	if err = recordBootstrap(ctx, tx, userID); err != nil {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO uem_access_bootstrap_account(singleton,user_id) VALUES(true,$1)`, userID); err != nil {
		return false, err
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func recordBootstrap(ctx context.Context, tx *sql.Tx, userID string) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO uem_access_revisions(user_id,revision) VALUES($1,1)`, userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO uem_access_grants(user_id,role) VALUES($1,'administrator')`, userID); err != nil {
		return err
	}
	after, _ := json.Marshal([]Grant{{Role: Administrator}})
	if _, err := tx.ExecContext(ctx, `INSERT INTO uem_access_audit(actor,subject,action,before_grants,after_grants) VALUES('installation',$1,'bootstrap','[]',$2)`, userID, after); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO uem_access_migrations(name) VALUES('bootstrap')`)
	return err
}

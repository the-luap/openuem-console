package administrator

import (
	"context"
	"database/sql"
	"errors"

	"github.com/alexedwards/argon2id"
	openuem "github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/setup/secrets"
)

var ErrIncomplete = errors.New("first-administrator setup is not complete for this installation")

// CheckCompletion is a point-in-time, read-only check before retiring the
// initial-password mount. It requires the original bound account, current global
// administrator access, completed registration and a different password. It
// neither signs in nor repairs missing state, grants access or replaces a secret.
func CheckCompletion(ctx context.Context, db *sql.DB, config Config, credentials secrets.Runtime) error {
	if db == nil || config.Validate() != nil {
		return ErrIncomplete
	}
	initial, err := password(config.PasswordFile)
	if err != nil {
		return ErrIncomplete
	}
	defer clear(initial)
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return ErrIncomplete
	}
	defer tx.Rollback()
	if secrets.VerifyBinding(ctx, tx, credentials) != nil {
		return ErrIncomplete
	}
	var hash string
	var valid bool
	err = tx.QueryRowContext(ctx, `SELECT u.hash,
	 u.passwd AND NOT u.openid AND u.register=$2
	 AND EXISTS(SELECT 1 FROM uem_access_migrations WHERE name='bootstrap')
	 AND EXISTS(SELECT 1 FROM uem_access_grants g WHERE g.user_id=u.uid AND g.role='administrator' AND g.tenant_id=0 AND g.site_id=0)
	 FROM uem_access_bootstrap_account b JOIN users u ON u.uid=b.user_id
	 WHERE b.singleton AND b.user_id=$1`, config.UserID, openuem.REGISTER_COMPLETE).Scan(&hash, &valid)
	if err != nil || !valid || !boundedPasswordHash(hash) {
		return ErrIncomplete
	}
	// Bound stored Argon2 parameters before comparison so a damaged database
	// value cannot make this short-lived readiness job allocate unbounded memory.
	same, err := argon2id.ComparePasswordAndHash(string(initial), hash)
	if err != nil || same || ctx.Err() != nil || tx.Commit() != nil {
		return ErrIncomplete
	}
	return nil
}

func boundedPasswordHash(hash string) bool {
	if len(hash) == 0 || len(hash) > 1024 {
		return false
	}
	params, salt, key, err := argon2id.DecodeHash(hash)
	return err == nil && params.Memory >= 8 && params.Memory <= 128*1024 && params.Iterations >= 1 && params.Iterations <= 5 &&
		params.Parallelism >= 1 && len(salt) >= 16 && len(salt) <= 64 && len(key) >= 32 && len(key) <= 64
}

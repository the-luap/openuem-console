package secrets

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"errors"

	"github.com/open-uem/openuem-console/internal/security/access"
)

var ErrBinding = errors.New("installation credentials do not match the database binding or the account registry is not fresh")

// CheckBinding runs before account initialization, field encryption or listener
// startup. An installation ID opts a fresh registry into permanent key binding.
// Once bound, omitting the ID cannot bypass verification. Existing unbound legacy
// accounts are never silently adopted. This operation does not rotate keys.
func CheckBinding(ctx context.Context, db *sql.DB, credentials Runtime) error {
	if db == nil || credentials.Installation != "" && (!validInstallation(credentials.Installation) || !validRuntime(credentials)) {
		return ErrBinding
	}
	permissions, err := access.NewStore(db)
	if err != nil || permissions.Migrate(ctx) != nil {
		return ErrBinding
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return ErrBinding
	}
	defer tx.Rollback()
	// Shares the account/grant bootstrap lock, including legacy administration.
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(684627902)`); err != nil {
		return ErrBinding
	}
	if _, err = tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS uem_installation_secrets (
	 singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK(singleton),
	 version INTEGER NOT NULL CHECK(version=1),
	 installation TEXT NOT NULL CHECK(installation ~ '^[0-9a-f]{32}$'),
	 jwt_proof BYTEA NOT NULL CHECK(octet_length(jwt_proof)=32),
	 master_proof BYTEA NOT NULL CHECK(octet_length(master_proof)=32),
	 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
	)`); err != nil {
		return ErrBinding
	}
	var installation string
	var recorded bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM uem_access_migrations WHERE name='installation-secrets')`).Scan(&recorded); err != nil {
		return ErrBinding
	}
	var version int
	var jwtProof, masterProof []byte
	err = tx.QueryRowContext(ctx, `SELECT version,installation,jwt_proof,master_proof FROM uem_installation_secrets WHERE singleton`).Scan(&version, &installation, &jwtProof, &masterProof)
	if err == nil {
		if !recorded || version != 1 || credentials.Installation != installation || !validRuntime(credentials) ||
			!hmac.Equal(jwtProof, bindingProof(credentials.JWT, "jwt", installation)) ||
			!hmac.Equal(masterProof, bindingProof(credentials.Master, "master", installation)) {
			return ErrBinding
		}
	} else if errors.Is(err, sql.ErrNoRows) {
		if recorded {
			return ErrBinding
		}
		if credentials.Installation != "" {
			// Also serialize ordinary account registration. A retained access marker
			// prevents re-binding after all accounts have been deleted.
			if _, err = tx.ExecContext(ctx, `LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE`); err != nil {
				return ErrBinding
			}
			var occupied bool
			if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM users)
			 OR EXISTS(SELECT 1 FROM uem_access_migrations WHERE name='bootstrap')
			 OR EXISTS(SELECT 1 FROM uem_access_grants)
			 OR EXISTS(SELECT 1 FROM uem_access_revisions)
			 OR EXISTS(SELECT 1 FROM uem_access_audit)`).Scan(&occupied); err != nil || occupied {
				return ErrBinding
			}
			if _, err = tx.ExecContext(ctx, `INSERT INTO uem_installation_secrets(singleton,version,installation,jwt_proof,master_proof) VALUES(true,1,$1,$2,$3)`, credentials.Installation, bindingProof(credentials.JWT, "jwt", credentials.Installation), bindingProof(credentials.Master, "master", credentials.Installation)); err != nil {
				return ErrBinding
			}
			if _, err = tx.ExecContext(ctx, `INSERT INTO uem_access_migrations(name) VALUES('installation-secrets')`); err != nil {
				return ErrBinding
			}
		}
	} else {
		return ErrBinding
	}
	if tx.Commit() != nil {
		return ErrBinding
	}
	return nil
}

func bindingProof(secret, role, installation string) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("OpenUEM installation secret binding v1\n" + role + "\n" + installation))
	return mac.Sum(nil)
}

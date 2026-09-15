package secrets

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
)

type databaseBootstrapRow struct {
	Installation, Operation, ConfigHash, VerifierHash, Role, Database, Stage string
	RoleOID, DatabaseOID                                                     int64
	Ready                                                                    bool
}

func (row databaseBootstrapRow) matches(binding databaseBootstrapBinding) bool {
	config, _ := json.Marshal(binding.Config)
	return row.Installation == binding.Config.Installation && row.Operation == binding.Operation && row.ConfigHash == databaseDigest(string(config)) && row.VerifierHash == databaseDigest(binding.Verifier) && row.Role == binding.Config.User && row.Database == binding.Config.Database && row.Stage == "openuem_stage_"+binding.Operation && row.Stage != row.Database && row.RoleOID > 0 && row.RoleOID <= 4294967295
}

func ensureDatabaseBootstrapCatalog(ctx context.Context, conn *sql.Conn, create bool) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return ErrDatabaseBootstrap
	}
	defer tx.Rollback()
	var owned bool
	err = tx.QueryRowContext(ctx, `SELECT nspowner='postgres'::regrole AND obj_description(oid,'pg_namespace')='OpenUEM database bootstrap v1' AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(nspacl,acldefault('n',nspowner))) WHERE grantee<>nspowner) FROM pg_namespace WHERE nspname='openuem_bootstrap'`).Scan(&owned)
	if err == nil {
		if !owned {
			return ErrDatabaseBootstrap
		}
		// Never repair a missing control table in an already marked namespace.
		if err = tx.QueryRowContext(ctx, `SELECT relowner='postgres'::regrole AND relkind='r' AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(relacl,acldefault('r',relowner))) WHERE grantee<>relowner) FROM pg_class WHERE oid=to_regclass('openuem_bootstrap.installations')`).Scan(&owned); err != nil || !owned {
			return ErrDatabaseBootstrap
		}
	} else if errors.Is(err, sql.ErrNoRows) {
		if !create {
			return ErrDatabaseBootstrap
		}
		if _, err = tx.ExecContext(ctx, `CREATE SCHEMA openuem_bootstrap AUTHORIZATION postgres;
		COMMENT ON SCHEMA openuem_bootstrap IS 'OpenUEM database bootstrap v1';
		REVOKE ALL ON SCHEMA openuem_bootstrap FROM PUBLIC;
		CREATE TABLE openuem_bootstrap.installations (
		 installation TEXT PRIMARY KEY,
		 operation TEXT NOT NULL UNIQUE,
		 config_hash TEXT NOT NULL,
		 verifier_hash TEXT NOT NULL,
		 role_name TEXT NOT NULL UNIQUE,
		 database_name TEXT NOT NULL UNIQUE,
		 stage_name TEXT NOT NULL UNIQUE,
		 role_oid BIGINT NOT NULL CHECK(role_oid BETWEEN 1 AND 4294967295),
		 database_oid BIGINT NOT NULL DEFAULT 0 CHECK(database_oid BETWEEN 0 AND 4294967295),
		 ready BOOLEAN NOT NULL DEFAULT false,
		 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
		 CHECK(NOT ready OR database_oid>0)
		);
		REVOKE ALL ON openuem_bootstrap.installations FROM PUBLIC`); err != nil {
			return ErrDatabaseBootstrap
		}
	} else {
		return ErrDatabaseBootstrap
	}
	// PostgreSQL default privileges may grant newly created control objects to
	// additional roles. Do not commit a catalog with unexpected readers/writers.
	if err = tx.QueryRowContext(ctx, `SELECT NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(nspacl,acldefault('n',nspowner))) WHERE grantee<>nspowner) FROM pg_namespace WHERE nspname='openuem_bootstrap'`).Scan(&owned); err != nil || !owned {
		return ErrDatabaseBootstrap
	}
	if err = tx.QueryRowContext(ctx, `SELECT NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(relacl,acldefault('r',relowner))) WHERE grantee<>relowner) FROM pg_class WHERE oid=to_regclass('openuem_bootstrap.installations')`).Scan(&owned); err != nil || !owned {
		return ErrDatabaseBootstrap
	}
	if tx.Commit() != nil {
		return ErrDatabaseBootstrap
	}
	return nil
}

func readDatabaseBootstrap(ctx context.Context, conn *sql.Conn, installation string) (databaseBootstrapRow, bool, error) {
	var row databaseBootstrapRow
	err := conn.QueryRowContext(ctx, `SELECT installation,operation,config_hash,verifier_hash,role_name,database_name,stage_name,role_oid,database_oid,ready FROM openuem_bootstrap.installations WHERE installation=$1`, installation).Scan(&row.Installation, &row.Operation, &row.ConfigHash, &row.VerifierHash, &row.Role, &row.Database, &row.Stage, &row.RoleOID, &row.DatabaseOID, &row.Ready)
	if errors.Is(err, sql.ErrNoRows) {
		return row, false, nil
	}
	if err != nil {
		return row, false, ErrDatabaseBootstrap
	}
	return row, true, nil
}

func databaseNamesOccupied(ctx context.Context, conn *sql.Conn, config DatabaseConfig) bool {
	var occupied bool
	err := conn.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1) OR EXISTS(SELECT 1 FROM pg_database WHERE datname=$2)`, config.User, config.Database).Scan(&occupied)
	return err != nil || occupied
}

func createDatabaseBootstrapRole(ctx context.Context, conn *sql.Conn, binding databaseBootstrapBinding) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return ErrDatabaseBootstrap
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `CREATE ROLE `+databaseIdentifierSQL(binding.Config.User)+` NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT PASSWORD `+databaseLiteralSQL(binding.Verifier)); err != nil {
		return ErrDatabaseBootstrap
	}
	var roleOID int64
	if err = tx.QueryRowContext(ctx, `SELECT oid::bigint FROM pg_authid WHERE rolname=$1`, binding.Config.User).Scan(&roleOID); err != nil {
		return ErrDatabaseBootstrap
	}
	config, _ := json.Marshal(binding.Config)
	inserted, err := tx.ExecContext(ctx, `INSERT INTO openuem_bootstrap.installations(installation,operation,config_hash,verifier_hash,role_name,database_name,stage_name,role_oid) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, binding.Config.Installation, binding.Operation, databaseDigest(string(config)), databaseDigest(binding.Verifier), binding.Config.User, binding.Config.Database, "openuem_stage_"+binding.Operation, roleOID)
	if err != nil || !databaseOneRow(inserted) {
		return ErrDatabaseBootstrap
	}
	if tx.Commit() != nil {
		return ErrDatabaseBootstrap
	}
	return nil
}

func checkDatabaseBootstrapRole(ctx context.Context, conn *sql.Conn, row databaseBootstrapRow, binding databaseBootstrapBinding) error {
	var oid int64
	var login, unprivileged bool
	var verifier string
	err := conn.QueryRowContext(ctx, `SELECT oid::bigint,rolcanlogin,rolpassword,
	 NOT (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)
	 AND rolinherit AND rolconnlimit=-1 AND rolvaliduntil IS NULL
	 AND NOT EXISTS(SELECT 1 FROM pg_db_role_setting WHERE setrole=pg_authid.oid)
	 AND NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE member=pg_authid.oid OR roleid=pg_authid.oid)
	 FROM pg_authid WHERE rolname=$1`, row.Role).Scan(&oid, &login, &verifier, &unprivileged)
	if err != nil || oid != row.RoleOID || login != row.Ready || !unprivileged || !hmac.Equal([]byte(verifier), []byte(binding.Verifier)) {
		return ErrDatabaseBootstrap
	}
	return nil
}

type bootstrapDatabaseObject struct {
	Name                          string
	OID, Owner                    int64
	Allowed, Template, DefaultACL bool
	Limit                         int
}

func (object bootstrapDatabaseObject) pending(owner int64) bool {
	return object.Owner == owner && !object.Allowed && !object.Template && object.DefaultACL && object.Limit == -1
}

func readBootstrapDatabaseObject(ctx context.Context, conn *sql.Conn, name string) (bootstrapDatabaseObject, bool, error) {
	var object bootstrapDatabaseObject
	err := conn.QueryRowContext(ctx, `SELECT datname,oid::bigint,datdba::bigint,datallowconn,datistemplate,datacl IS NULL,datconnlimit FROM pg_database WHERE datname=$1`, name).Scan(&object.Name, &object.OID, &object.Owner, &object.Allowed, &object.Template, &object.DefaultACL, &object.Limit)
	if errors.Is(err, sql.ErrNoRows) {
		return object, false, nil
	}
	if err != nil {
		return object, false, ErrDatabaseBootstrap
	}
	return object, true, nil
}

func checkDatabaseBootstrapObject(ctx context.Context, conn *sql.Conn, row databaseBootstrapRow) (bootstrapDatabaseObject, error) {
	name := row.Stage
	if row.Ready {
		name = row.Database
	}
	object, exists, err := readBootstrapDatabaseObject(ctx, conn, name)
	if err != nil || !exists || object.OID != row.DatabaseOID || object.Owner != row.RoleOID || object.Allowed != row.Ready || object.Template || object.Limit != -1 {
		return object, ErrDatabaseBootstrap
	}
	var conflict bool
	if err = conn.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname IN ($1,$2) AND oid::bigint<>$3)`, row.Stage, row.Database, row.DatabaseOID).Scan(&conflict); err != nil || conflict {
		return object, ErrDatabaseBootstrap
	}
	if row.Ready {
		var private bool
		// Only the application owner may hold database ACL entries. Superusers
		// retain their ordinary authority, without an explicit PUBLIC grant.
		if err = conn.QueryRowContext(ctx, `SELECT datacl IS NOT NULL AND NOT EXISTS(SELECT 1 FROM aclexplode(datacl) WHERE grantee::bigint<>$2) AND (SELECT count(*)=3 FROM aclexplode(datacl) WHERE grantee::bigint=$2 AND privilege_type IN ('CREATE','CONNECT','TEMPORARY')) FROM pg_database WHERE oid::bigint=$1`, row.DatabaseOID, row.RoleOID).Scan(&private); err != nil || !private {
			return object, ErrDatabaseBootstrap
		}
	}
	return object, nil
}

func finishDatabaseBootstrap(ctx context.Context, conn *sql.Conn, row databaseBootstrapRow, beforeCommit func() error) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return ErrDatabaseBootstrap
	}
	defer tx.Rollback()
	for _, statement := range []string{
		`ALTER DATABASE ` + databaseIdentifierSQL(row.Stage) + ` RENAME TO ` + databaseIdentifierSQL(row.Database),
		`REVOKE ALL ON DATABASE ` + databaseIdentifierSQL(row.Database) + ` FROM PUBLIC`,
		`GRANT ALL ON DATABASE ` + databaseIdentifierSQL(row.Database) + ` TO ` + databaseIdentifierSQL(row.Role),
		`ALTER DATABASE ` + databaseIdentifierSQL(row.Database) + ` ALLOW_CONNECTIONS true`,
		`ALTER ROLE ` + databaseIdentifierSQL(row.Role) + ` LOGIN`,
	} {
		if _, err = tx.ExecContext(ctx, statement); err != nil {
			return ErrDatabaseBootstrap
		}
	}
	updated, err := tx.ExecContext(ctx, `UPDATE openuem_bootstrap.installations SET ready=true WHERE installation=$1 AND operation=$2 AND role_oid=$3 AND database_oid=$4 AND NOT ready`, row.Installation, row.Operation, row.RoleOID, row.DatabaseOID)
	if err != nil || !databaseOneRow(updated) {
		return ErrDatabaseBootstrap
	}
	if beforeCommit != nil {
		if err := beforeCommit(); err != nil {
			return err
		}
	}
	if tx.Commit() != nil {
		return ErrDatabaseBootstrap
	}
	return nil
}

func databaseIdentifierSQL(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}
func databaseLiteralSQL(value string) string { return `'` + strings.ReplaceAll(value, `'`, `''`) + `'` }

func databaseOneRow(result sql.Result) bool {
	if result == nil {
		return false
	}
	count, err := result.RowsAffected()
	return err == nil && count == 1
}

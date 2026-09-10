package secrets

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-uem/nats/enrollment/keyfile"
)

var ErrDatabaseBootstrap = errors.New("database bootstrap could not verify or complete the bound installation; existing state was retained")
var ErrDatabaseBootstrapBusy = errors.New("another database bootstrap is active; retry after it finishes")

type databaseBootstrapBinding struct {
	Version   int            `json:"version"`
	Config    DatabaseConfig `json:"config"`
	Cluster   string         `json:"cluster"`
	Operation string         `json:"operation"`
	Verifier  string         `json:"verifier"`
}

type databaseObjectRecord struct {
	Operation   string `json:"operation"`
	RoleOID     int64  `json:"role_oid"`
	DatabaseOID int64  `json:"database_oid,omitempty"`
}

// BootstrapDatabase creates only its bound fresh application role/database.
// Completed credential files are read-only inputs. A separate protected journal
// binds the actual PostgreSQL cluster and immutable object identities. Dropped,
// replaced or externally changed objects are never reset or recreated.
func BootstrapDatabase(ctx context.Context, credentialsDirectory, stateDirectory string, config DatabaseConfig) (Result, error) {
	return bootstrapDatabase(ctx, credentialsDirectory, stateDirectory, config, nil)
}

func bootstrapDatabase(ctx context.Context, credentialsDirectory, stateDirectory string, config DatabaseConfig, afterStep func(string) error) (Result, error) {
	if config.Validate() != nil || keyfile.CheckDirectory(credentialsDirectory) != nil {
		return Result{}, ErrDatabaseBootstrap
	}
	source, err := openProvisioning(ctx, credentialsDirectory, append([]string{"credentials.json", "manifest.json"}, databaseArtifacts...), nil)
	if err != nil || !source.present["manifest.json"] {
		return Result{}, ErrDatabaseBootstrap
	}
	credentials, err := loadDatabaseJournal(source, config)
	if err != nil || completeDatabaseFiles(source, credentials, false) != nil {
		return Result{}, ErrDatabaseBootstrap
	}
	db, err := sql.Open("pgx", databaseConnection(config, "postgres", credentials.AdministratorPassword, "postgres"))
	if err != nil {
		return Result{}, ErrDatabaseBootstrap
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(ctx)
	if err != nil {
		return Result{}, ErrDatabaseBootstrap
	}
	defer conn.Close()
	var cluster string
	var valid bool
	if err = conn.QueryRowContext(ctx, `SELECT system_identifier::text FROM pg_control_system()`).Scan(&cluster); err != nil {
		return Result{}, ErrDatabaseBootstrap
	}
	if err = conn.QueryRowContext(ctx, `SELECT current_user='postgres' AND current_database()='postgres' AND NOT pg_is_in_recovery() AND current_setting('server_version_num')::integer BETWEEN 170000 AND 179999 AND (SELECT rolsuper FROM pg_roles WHERE rolname=current_user)`).Scan(&valid); err != nil || !valid {
		return Result{}, ErrDatabaseBootstrap
	}
	// This dedicated connection owns the session lock until both Conn and DB are
	// closed, including cancellation. It is never borrowed by application work.
	if err = conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock(684627911)`).Scan(&valid); err != nil {
		return Result{}, ErrDatabaseBootstrap
	}
	if !valid {
		return Result{}, ErrDatabaseBootstrapBusy
	}
	if _, err = conn.ExecContext(ctx, `SET log_statement='none'; SET log_duration=off; SET log_min_duration_statement=-1; SET log_min_duration_sample=-1; SET log_transaction_sample_rate=0; SET log_min_error_statement='panic'; SET log_parameter_max_length=0; SET log_parameter_max_length_on_error=0; SET search_path=pg_catalog`); err != nil {
		return Result{}, ErrDatabaseBootstrap
	}
	d, err := openProvisioning(ctx, stateDirectory, []string{"binding.json", "role.json", "database.json", "ready.json"}, afterStep)
	if err != nil {
		return Result{}, ErrDatabaseBootstrap
	}
	if d.present["binding.json"] {
		if _, err := readDatabaseBootstrapBinding(d, config, cluster, credentials.Password); err != nil {
			return Result{}, err
		}
	} else if len(d.present) != 0 {
		return Result{}, ErrDatabaseBootstrap
	}
	if !d.present["binding.json"] && databaseNamesOccupied(ctx, conn, config) {
		return Result{}, ErrDatabaseBootstrap
	}
	if err = ensureDatabaseBootstrapCatalog(ctx, conn, !d.present["binding.json"]); err != nil {
		return Result{}, err
	}
	row, exists, err := readDatabaseBootstrap(ctx, conn, config.Installation)
	if err != nil {
		return Result{}, err
	}
	if !d.present["binding.json"] {
		if len(d.present) != 0 || exists || databaseNamesOccupied(ctx, conn, config) {
			return Result{}, ErrDatabaseBootstrap
		}
		var random [32]byte
		if _, err := rand.Read(random[:]); err != nil {
			return Result{}, ErrDatabaseBootstrap
		}
		binding := databaseBootstrapBinding{Version: 1, Config: config, Cluster: cluster, Operation: hex.EncodeToString(random[:16]), Verifier: databaseSCRAM(credentials.Password, random[16:])}
		clear(random[:])
		data, _ := json.Marshal(binding)
		defer clear(data)
		if err := d.write("binding.json", data); err != nil {
			return Result{}, err
		}
	}
	binding, err := readDatabaseBootstrapBinding(d, config, cluster, credentials.Password)
	if err != nil {
		return Result{}, err
	}
	step := func(name string) error {
		if err := d.check(); err != nil {
			return err
		}
		if afterStep != nil {
			return afterStep(name)
		}
		return nil
	}
	if !exists {
		if d.present["role.json"] || d.present["database.json"] || d.present["ready.json"] || databaseNamesOccupied(ctx, conn, config) {
			return Result{}, ErrDatabaseBootstrap
		}
		if err := createDatabaseBootstrapRole(ctx, conn, binding); err != nil {
			return Result{}, err
		}
		if err := step("role-committed"); err != nil {
			return Result{}, err
		}
		row, exists, err = readDatabaseBootstrap(ctx, conn, config.Installation)
		if err != nil || !exists {
			return Result{}, ErrDatabaseBootstrap
		}
	}
	if !row.matches(binding) || checkDatabaseBootstrapRole(ctx, conn, row, binding) != nil {
		return Result{}, ErrDatabaseBootstrap
	}
	if d.present["ready.json"] && !row.Ready || d.present["database.json"] && row.DatabaseOID == 0 {
		return Result{}, ErrDatabaseBootstrap
	}
	if err := databasePhase(d, "role.json", databaseObjectRecord{Operation: binding.Operation, RoleOID: row.RoleOID}); err != nil {
		return Result{}, err
	}
	if row.DatabaseOID == 0 {
		if row.Ready {
			return Result{}, ErrDatabaseBootstrap
		}
		if _, occupied, err := readBootstrapDatabaseObject(ctx, conn, row.Database); err != nil || occupied {
			return Result{}, ErrDatabaseBootstrap
		}
		candidate, exists, err := readBootstrapDatabaseObject(ctx, conn, row.Stage)
		if err != nil {
			return Result{}, err
		}
		if !exists {
			if _, err = conn.ExecContext(ctx, `CREATE DATABASE `+databaseIdentifierSQL(row.Stage)+` WITH OWNER `+databaseIdentifierSQL(row.Role)+` TEMPLATE template0 ALLOW_CONNECTIONS false`); err != nil {
				return Result{}, ErrDatabaseBootstrap
			}
			if err := step("database-created"); err != nil {
				return Result{}, err
			}
			candidate, exists, err = readBootstrapDatabaseObject(ctx, conn, row.Stage)
		}
		if err != nil || !exists || !candidate.pending(row.RoleOID) || candidate.Name != row.Stage {
			return Result{}, ErrDatabaseBootstrap
		}
		updated, err := conn.ExecContext(ctx, `UPDATE openuem_bootstrap.installations SET database_oid=$2 WHERE installation=$1 AND operation=$3 AND role_oid=$4 AND database_oid=0 AND NOT ready`, config.Installation, candidate.OID, row.Operation, row.RoleOID)
		if err != nil || !databaseOneRow(updated) {
			return Result{}, ErrDatabaseBootstrap
		}
		row.DatabaseOID = candidate.OID
		if err := step("database-bound"); err != nil {
			return Result{}, err
		}
	}
	object, err := checkDatabaseBootstrapObject(ctx, conn, row)
	if err != nil {
		return Result{}, err
	}
	if err := databasePhase(d, "database.json", databaseObjectRecord{Operation: binding.Operation, RoleOID: row.RoleOID, DatabaseOID: row.DatabaseOID}); err != nil {
		return Result{}, err
	}
	if !row.Ready {
		if object.Name != row.Stage || !object.pending(row.RoleOID) {
			return Result{}, ErrDatabaseBootstrap
		}
		if err := finishDatabaseBootstrap(ctx, conn, row, func() error { return step("ready-precommit") }); err != nil {
			return Result{}, err
		}
		if err := step("ready-committed"); err != nil {
			return Result{}, err
		}
		row.Ready = true
	}
	if checkDatabaseBootstrapRole(ctx, conn, row, binding) != nil {
		return Result{}, ErrDatabaseBootstrap
	}
	if _, err := checkDatabaseBootstrapObject(ctx, conn, row); err != nil {
		return Result{}, err
	}
	if err := databasePhase(d, "ready.json", databaseObjectRecord{Operation: binding.Operation, RoleOID: row.RoleOID, DatabaseOID: row.DatabaseOID}); err != nil {
		return Result{}, err
	}
	return Result{Installation: config.Installation}, nil
}

func databasePhase(d *provisioningDirectory, name string, record databaseObjectRecord) error {
	data, _ := json.Marshal(record)
	if d.present[name] {
		actual, err := d.read(name, 1024)
		if err != nil || !bytes.Equal(actual, data) {
			return ErrDatabaseBootstrap
		}
		return nil
	}
	return d.write(name, data)
}

func databaseDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func readDatabaseBootstrapBinding(d *provisioningDirectory, config DatabaseConfig, cluster, password string) (databaseBootstrapBinding, error) {
	data, err := d.read("binding.json", 8192)
	if err != nil {
		return databaseBootstrapBinding{}, ErrDatabaseBootstrap
	}
	defer clear(data)
	var binding databaseBootstrapBinding
	if json.Unmarshal(data, &binding) != nil || binding.Version != 1 || binding.Config != config || binding.Cluster != cluster || !validInstallation(binding.Operation) || !validDatabaseSCRAM(password, binding.Verifier) {
		return databaseBootstrapBinding{}, ErrDatabaseBootstrap
	}
	if _, err := strconv.ParseUint(binding.Cluster, 10, 64); err != nil {
		return databaseBootstrapBinding{}, ErrDatabaseBootstrap
	}
	canonical, _ := json.Marshal(binding)
	defer clear(canonical)
	if !bytes.Equal(data, canonical) {
		return databaseBootstrapBinding{}, ErrDatabaseBootstrap
	}
	return binding, nil
}

# Resumable PostgreSQL application bootstrap

`openuem-database-bootstrap` creates and verifies one installation's application
role and database on PostgreSQL 17. It reads the completed outputs of
[database credential provisioning](database-credentials.md), authenticates as the
bootstrap administrator over TLS with hostname verification, and keeps a separate
private journal. It never changes a password, adopts an existing account or
recreates a missing database after its identity has been committed.

## Run after database server initialization

Build the command from `./cmd/openuem-database-bootstrap`. Run it on Linux/macOS
under the account that owns provisioning, after PostgreSQL is accepting TLS
connections and before starting the console:

```sh
openuem-database-bootstrap \
  --config /private/openuem/database.json \
  --credentials /private/openuem/database-credentials \
  --state /private/openuem/database-bootstrap
```

The separate [setup container image](setup-containers.md) provides the same command
without a shell or Go toolchain in the runtime.

Use the exact protected metadata used to create the credentials. The configured
host and CA file path must be accessible from this command's environment as well
as the console's environment. PostgreSQL's `postgres` account must already use
the generated `administrator-password`; the command connects to its `postgres`
maintenance database. The server must be a writable PostgreSQL 17 primary with
superuser administration available. Replicas and other major versions fail closed.

This command does not start or initialize PostgreSQL, provision its TLS identity,
install trust, or create missing credential files. The credential and journal
directories must be separate, private, and under trusted existing parents.
Only the bootstrap job receives the administrator password. The console receives
its protected `database.url` through `DATABASE_URL_FILE` and the public CA file.
Start the console only after the bootstrap job exits successfully.

For a fresh private PKI, the certificate manager at
[revision 938ea1a](https://github.com/the-luap/openuem-cert-manager/commit/938ea1a77eba4c9eb4517db629fc42ef2f8b96ad)
or later accepts `private-pki --database-dns database.internal`. Its separate
`database/server.pem` and `database/server.key` are the PostgreSQL TLS identity;
its public `trust/backend-ca.pem` is mounted at the configured client CA path.
Database DNS names are fixed when the PKI is first created; adding this option to
existing PKI state is rejected. See the
[private PKI instructions](https://github.com/the-luap/openuem-cert-manager/blob/938ea1a77eba4c9eb4517db629fc42ef2f8b96ad/docs/private-pki.md)
for the complete invocation and per-service mount boundaries.

Success prints one JSON object containing only `installation`. Failure exits
nonzero with a fixed diagnostic that excludes passwords, URLs and SQL text. The
command has a two-minute deadline and handles interruption and `SIGTERM`. A
competing bootstrap receives a retryable busy error. Retrying with the original
inputs is safe after the active invocation exits.

## Durable object binding

The command uses a dedicated administrator connection and a PostgreSQL session
advisory lock. A private control table,
`postgres.openuem_bootstrap.installations`, stores the installation, operation,
configuration/verifier digests, requested names, object identifiers and readiness.
Only its PostgreSQL owner may hold explicit schema/table grants. Existing objects
with conflicting names or an unrecognized control namespace are rejected.

The separate journal contains:

| File | Durable meaning |
| --- | --- |
| `binding.json` | Exact metadata, PostgreSQL system identifier, random operation and salted SCRAM verifier |
| `role.json` | Original role OID bound to the operation |
| `database.json` | Original role and database OIDs bound to the operation |
| `ready.json` | Verified committed readiness for those same objects |

Treat every journal file as sensitive. The password verifier in `binding.json`
must remain private even though it is not the original password. The command
supplies a precomputed SCRAM verifier when creating the role and disables normal
statement/error-parameter logging on its dedicated session before secret-bearing
SQL. It does not override independent extension auditing or external database
monitoring; keep those administrative systems and backups appropriately protected.
PostgreSQL documents the accepted encoded password in
[CREATE ROLE](https://www.postgresql.org/docs/17/sql-createrole.html) and its
[authentication catalog](https://www.postgresql.org/docs/17/catalog-pg-authid.html).

Role creation and its SQL binding commit together with login disabled. Database
creation uses a random staging name, the original application owner, `template0`
and disabled connections. PostgreSQL requires
[CREATE DATABASE](https://www.postgresql.org/docs/17/sql-createdatabase.html)
outside a transaction, so the random stage provides the recovery point if the
process stops before persisting the database OID. A retry accepts that pending
object only with the expected name, owner, disabled connections and default
properties. After recording its OID, a missing or replacement object is rejected.

Finalization commits the final database name, removal of PUBLIC database access,
application database grants, enabled connections, role login and SQL readiness
together. The application role has no superuser, role-creation, database-creation,
replication or row-security bypass authority. Restart also rejects changed role
membership, role settings, expiry, password, connection limits, database owner,
template status or database ACLs. Role defaults are inspected in PostgreSQL's
[role/database settings catalog](https://www.postgresql.org/docs/17/catalog-pg-db-role-setting.html).
Database ownership permits the ordinary console schema migrations.

## Recovery boundary

Keep the original credentials, protected journal and PostgreSQL cluster together
in recovery procedures. Never delete markers, replace the journal with an empty
directory or initialize another cluster as a repair step. The PostgreSQL system
identifier and object OIDs deliberately prevent adoption of a different cluster
or replacement role/database. Logical restores, major-version migration and
password rotation need a separate reviewed migration workflow; this command
does not implement those workflows.

After an interruption, complete existing writes are reused exactly. Missing
derived phase files can be reconstructed only from the original private binding
and consistent SQL object binding. Partial, changed, unrelated, symlinked or
overly accessible files stop the operation. Losing the binding file, SQL control
table or committed role/database is an error, not an instruction to reset state.
Application data and schema are never cleared by this command.

## Verification and remaining deployment work

The isolated PostgreSQL suite exercises all nine durable interruption points,
rollback of finalization, suppressed INSERT/UPDATE binding writes, competing
writers, context cancellation and lock release. It rejects changed roles,
memberships, databases, catalog permissions, bindings and credential files without
repairing their contents. Tests also cover private-catalog default grants,
reconstruction of derived phase files and rejection of a different cluster binding.

The actual compiled command creates the application database, repeats successfully,
emits only public metadata and exits promptly on `SIGTERM` while a real database
lock blocks it. Both process and console migration fixtures use the actual pinned
private PKI command to generate the PostgreSQL server certificate and PKCS#8 key.
The real console model migrates and initializes the resulting database over
verified TLS. CI runs the isolated PostgreSQL image on native Linux
amd64/arm64; argument handling, SCRAM validation and runtime configuration also
have native platform checks. These fixtures use synthetic clusters and no
external network, host port, host trust installation or existing database.

Reference deployment wiring, container mount ownership, full fresh-stack acceptance
and restore/migration acceptance remain open in the
[implementation ledger](implementation-status.md).

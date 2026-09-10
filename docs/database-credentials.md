# Persistent database credentials

`openuem-database-credentials` creates independent 256-bit random passwords for
PostgreSQL bootstrap administration and the console's application role. It also
creates a connection URL with `sslmode=verify-full` and explicit CA trust. The
command runs offline on Linux/macOS and prints only the installation identifier.
It does not create database accounts, start PostgreSQL or change an existing role.

Use the identifier from the [installation secret provisioner](installation-secrets.md)
in a protected metadata file. For example:

```json
{
  "version": 1,
  "installation": "0123456789abcdef0123456789abcdef",
  "host": "database.internal",
  "port": 5432,
  "database": "openuem",
  "user": "console",
  "trust_file": "/run/openuem/database-ca.pem"
}
```

Replace the example identifier with the actual installation identifier. The
metadata must be a protected regular file owned by the service or system
administrator, with no Unix group/other access or untrusted Windows ACL entries.
The parser rejects unknown or repeated properties, extra JSON documents and
invalid identifiers without repeating input values in errors. The application
role cannot be `postgres` or a `pg_` role. System database names are rejected.

Run under a trusted existing parent as the account which owns provisioning:

```sh
openuem-database-credentials \
  --config /private/openuem/database.json \
  --directory /private/openuem/database-credentials
```

The output directory is separate from the main installation secret directory.
It contains:

| File | Purpose | Intended access |
| --- | --- | --- |
| `administrator-password` | Bootstrap password for the PostgreSQL `postgres` role | Database initialization/recovery only |
| `database-password` | Independent password for the configured application role | Database role provisioning only |
| `database.url` | Application URL with the configured database, role and CA path | Console read-only mount via `DATABASE_URL_FILE` |
| `credentials.json` | Durable source of both credentials and the exact metadata | Provisioning/recovery only |
| `manifest.json` | Completion marker binding file digests and installation | Provisioning/recovery only |

The CA path is interpreted inside the application and bootstrap containers. Its CA must verify
the PostgreSQL server certificate, whose identity must match the configured host.
The generator never offers a verification-disabled connection mode. It does not
create the database server certificate or install a CA into host trust.

The application role should own its application database and support the console
schema migrations, with no superuser, role-creation, database-creation, replication
or row-security bypass privileges. Keep the bootstrap administrator credential
out of the console container. Service-specific database grants and credential
distribution remain part of the full reference deployment work.

## Restart and recovery

The protected source is written and synced before either password or the URL.
The completion marker is written only after all derived files match the source.
Each completed write survives an interrupted invocation without choosing new
credentials. Concurrent invocations can return an error while another writer is
active; retry after it finishes. Existing files are never overwritten.

Later invocations require the same installation, host, port, database, role and
CA path. Changed metadata, missing committed files, malformed source, broad
permissions, symlinks or unrelated directory entries stop provisioning. Restore
the original protected source and database rather than using a new empty
directory to repair an existing installation. This command is not a password
rotation or database-account reset mechanism.

## Evidence and remaining integration

Tests cover random role separation, runtime URL loading, immutable metadata,
concurrent writers, interruptions after every complete write, damaged state and
output privacy. The main installation provisioner uses the same checked directory
and exclusive-write implementation and retains its existing recovery tests.

An isolated native Linux PostgreSQL 17 fixture creates a new cluster with the
generated administrator password and TLS server identity. The production
[database bootstrap command](database-bootstrap.md) creates the application role
and database using those completed credential files. The
actual console model creates its schema and initial settings using the generated
URL as the application owner. The fixture proves encrypted transport, rejects
the administrator password for the application role, denies role creation and
rejects a mismatched TLS server name. It has no external network, host ports,
host trust installation or existing database access. CI runs it on amd64/arm64;
configuration parsing and protected file loading also run natively on Windows.

Automatic, resumable production role/database creation has its own protected
journal and PostgreSQL interruption, rollback, drift and process lifecycle tests.
Server certificate provisioning, service mount ownership and full
fresh-stack/restore acceptance remain open.

# Encrypted database backup and enrollment recovery

`cmd/openuem-recovery` creates an encrypted PostgreSQL database backup and a
separately encrypted bundle of application keys and selected configuration files.
Restore uses a new, empty database and a new recovery directory. It preserves
stored identities and encrypted state instead of issuing replacement enrollments.
It does not start services, activate a restored deployment or contact device providers.

This implements the database recovery portion of PKI-01. Synthetic Apple, Windows
and desktop continuity tests pass. Physical-device disaster recovery, CA/master-key
rotation and the rest of PKI-01 remain open.

## Requirements and scope

Build with `go build -o openuem-recovery ./cmd/openuem-recovery`. The executable
requires PostgreSQL 17 or later and trusted `pg_dump`/`pg_restore` executables whose
major version matches the connected server. Restore permits the same or a newer
server major, with application/database upgrade compatibility checked separately.
The local regression suite uses PostgreSQL 17.11 and real 17.11 clients.

The database URL comes only from `OPENUEM_RECOVERY_DATABASE_URL`, supplied by the
operator's protected environment or secret manager. Use an explicit
`postgres://user:password@host:port/database?sslmode=verify-full` URL, percent-encoding
credential characters as required. Remote connections require `verify-full`;
explicit `sslmode=disable` is accepted only for loopback hosts. Optional URL
parameters are `sslrootcert`, `sslcert`, `sslkey` (absolute file paths) and
`connect_timeout` (bounded by the tool). Other query parameters, multiple hosts and ambient nonempty `PG*`
environment variables are rejected so preflight and the PostgreSQL child process
use the same destination. Catalog preflight uses a fixed safe search path.
Passwords never appear in child arguments; a temporary protected password file
is removed after the child exits. Child diagnostics are withheld because they
can contain SQL, device data or credentials. A child warning also prevents a
successful result.

Use an administrative backup role able to read every required object and a
trusted restore owner able to inspect the destination catalogs and recreate the
source objects. Prepare the destination separately from `template0`; the tool
never creates or drops a production database. Restore rejects existing application
objects, extra schemas, extensions, large objects and other active connections.
Keep the destination isolated and applications stopped throughout the operation:
the repeated preflight checks are not a lock against an unrelated client connecting.

The custom dump includes all non-system schemas, table data, large objects,
sequences and post-data triggers/constraints. PostgreSQL provides the consistent
database snapshot. Configuration files and environment variables are collected
separately: coordinate schema changes, provider credential changes and key rotation
with the backup. `created_at` records backup creation time, not an exact database
snapshot timestamp. See the [PostgreSQL 17 pg_dump documentation](https://www.postgresql.org/docs/17/app-pgdump.html).

Cluster roles, ownership/ACL deployment, tablespace placement, WAL/PITR, installed
packages, NATS/JetStream volumes, external providers and unlisted filesystem data
need separate recovery procedures. Restore uses the destination owner and default
tablespace, without source ownership or ACL restoration. This is a database and
selected-configuration backup, not an automatic inventory of a whole installation.

## Separate encryption identities

Generate two identities on a trusted recovery workstation. Each `keygen` writes
a new private file and prints only its public recipient:

```sh
./openuem-recovery --action keygen --output /secure/offline/database.key
./openuem-recovery --action keygen --output /secure/offline/recovery.key
```

Create private parent directories beforehand. On Unix they must be owned by the
operator or system administrator and exclude group/other access; on Windows the
shared credential-file implementation verifies native owner/DACL protection.
Ancestors must remain trusted. Existing files are never overwritten and final
symlinks are rejected. Flat recovery filenames are case-insensitive, lowercase on
extraction, and exclude traversal, Windows device names and reserved receipt names.

Only the two public recipients belong on the backup host. Keep the private
identities separately protected, outside the backup repository, with independently
tested access procedures. Use different custodians/storage where required. The
application recovery bundle and database backup require different recipients.
The tool generates native hybrid age identities; the library also accepts one
native age identity/recipient per input, without plugin execution. See the
[age API](https://pkg.go.dev/filippo.io/age) and pinned
[age 1.3.2 release](https://github.com/FiloSottile/age/releases/tag/v1.3.2).

Encryption authenticates ciphertext integrity, not the sender: anyone knowing
the public recipients can create a new encrypted pair. Obtain backups from a
trusted source and keep the creation report/backup ID in an independent trusted
record. A backup ID is a pairing/selection check, not proof of origin; use a
trusted manifest of both ciphertext file hashes when transferring through
untrusted storage. PostgreSQL restores source-authored SQL; decrypting an unknown backup is
not permission to execute it against a trusted server.

## Create a backup

Store a protected JSON specification containing environment **names** and absolute
source-file paths. Include the actual running configuration; the example names
and paths must be adapted to the installation:

```json
{
  "environment": ["ENCRYPTION_MASTER_KEY", "WINDOWS_MDM_MASTER_KEY"],
  "files": [
    {"name": "console.ini", "path": "/secure/config/openuem.ini"},
    {"name": "gateway.key", "path": "/secure/tls/gateway.key"},
    {"name": "gateway.crt", "path": "/secure/tls/gateway.crt"}
  ]
}
```

Only list enabled settings that exist in the backup process environment. Apple
or individual desktop identity tables require `ENCRYPTION_MASTER_KEY`; native
Windows authority tables require the canonical base64 32-byte
`WINDOWS_MDM_MASTER_KEY`. Detection covers non-system schemas. These checks validate
presence/format, not decryption against every stored secret. The operator must
supply the matching live keys. Additional application secrets, provider tokens,
TLS keys and configuration files must be explicitly included when needed.

```sh
./openuem-recovery --action create \
  --specification /secure/config/recovery-spec.json \
  --output /secure/backups/database-2026-09-10.age \
  --recovery-output /secure/backups/recovery-2026-09-10.age \
  --recipient "$DATABASE_RECIPIENT" \
  --recovery-recipient "$RECOVERY_RECIPIENT" \
  --pg-dump /usr/lib/postgresql/17/bin/pg_dump
```

A successful command prints metadata including `backup_id`, source database,
server major, creation time, environment/file names and the encrypted recovery-file digest.
No secret values or source connection URL appear in the report. Save that report
outside the backup storage. Both final artifacts must exist and verify before a
backup is considered usable; copying them to separate repositories is operational.
Creation streams the database directly into encryption. Completed files are
synced and published without replacement; normal failure removes partial files.
Pair publication cannot be atomic across two paths. A crash or power loss can
leave one artifact or a private partial file. File contents are flushed; Unix
publication also syncs the parent directory. Windows namespace durability depends
on the filesystem. Verify both artifacts after recovery from interruption.

## Verify and restore

Use a private work directory on **encrypted storage**. Verify and restore create
a protected temporary plaintext custom dump to authenticate the entire database
archive before connecting to any destination. Normal completion, failure and
cancellation remove it; process crashes can leave `restore-*.dump` files and
`.pgpass-*` credentials for controlled cleanup. Removal is not secure erasure.
Treat extracted configuration and `environment.json` as secrets as well.

```sh
./openuem-recovery --action verify \
  --input /secure/backups/database-2026-09-10.age \
  --recovery-input /secure/backups/recovery-2026-09-10.age \
  --identity /secure/offline/database.key \
  --recovery-identity /secure/offline/recovery.key \
  --work-directory /encrypted/recovery-work
```

Verification checks complete age authentication, the pair's UUID/digest binding,
strict bounded metadata and the custom-dump prefix. The reported SHA-256 binds
the encrypted recovery file, avoiding a public hash of low-entropy secrets. It does not prove that SQL can
be restored. Perform an actual isolated restore drill and application continuity
checks. After verifying the expected independently recorded ID, set the protected
database URL to the precreated, empty destination and run:

```sh
./openuem-recovery --action restore \
  --input /secure/backups/database-2026-09-10.age \
  --recovery-input /secure/backups/recovery-2026-09-10.age \
  --identity /secure/offline/database.key \
  --recovery-identity /secure/offline/recovery.key \
  --work-directory /encrypted/recovery-work \
  --recovery-directory /encrypted/recovery-work/restored \
  --confirm-backup-id "$VERIFIED_BACKUP_ID" \
  --confirm-database openuem_recovered \
  --pg-restore /usr/lib/postgresql/17/bin/pg_restore
```

The new directory receives `environment.json`, selected files under their logical
names and `recovery.json` before database changes start. Import JSON through the
service's configuration mechanism; do not source it as a shell script. Map each
logical filename back to its reviewed deployment location. The CLI does not copy
files into live service paths or change services automatically.

Restore runs with `--single-transaction --exit-on-error --no-owner --no-acl
--no-tablespaces`, retaining source constraints and immutable audit guards. On
acknowledged success, the tool atomically publishes `completed.json`, identifying
the backup and destination, and prints the report. See the
[PostgreSQL restore options](https://www.postgresql.org/docs/17/app-pgrestore.html).

Once the child may have started, any failure is reported as **unconfirmed** and
prepared recovery keys remain available. A database commit followed by lost
acknowledgement cannot safely be called a rollback. Inspect the destination and
receipt before deciding on a new isolated attempt. Never delete prepared keys
merely because the command failed. Earlier preflight failures remove the new
prepared directory; existing directories and databases are never replaced.
Timeout defaults to 30 minutes, configurable from one second to 24 hours.

Before activation, verify matching application keys, tenant/site permissions,
original CA/certificates, endpoint DNS/TLS/provider configuration and retained
command state. Keep the original installation and restored copy from managing
devices concurrently. Devices renewed, revoked or changed after the snapshot may
need a later recovery point and reconciliation; this tool supplies no WAL replay.

## Format limits and automated evidence

Format 1 contains an age-encrypted envelope followed by a PostgreSQL custom dump,
plus an independently encrypted JSON recovery bundle. Limits are 1 TiB per database
ciphertext, 64 KiB metadata, 64 MiB encoded recovery JSON, 32 MiB collected raw
configuration, 16 MiB per source file, and 128 environment variables/files each.
Environment values must be nonempty UTF-8 without NUL, at most 1 MiB each. Binary
and empty configuration files are preserved. Duplicate/unknown JSON fields,
excessive nesting, unsafe names, modified/truncated/trailing ciphertext, swapped
pairs and wrong identities fail before destination access.

The opted-in integration suite creates only uniquely named disposable databases
under the reserved local PostgreSQL 17 fixture. It runs real dump/encryption/
verification/restore cycles, including the CLI entry point. Coverage includes
multiple schemas, large objects, sequences, immutable triggers, empty files,
occupied/active/unconfirmed destinations, malformed envelopes, cancellation,
private child-process handling, failed-copy transaction rollback and preservation
of recovery keys without a completion receipt.

Platform drills restore the same synthetic Apple SCEP identity/CA/push key and
finish an existing profile's install/remove lifecycle; the same Windows CA,
certificate, exact provisioning retry and pending authenticated CSP session, with
protected audit export/immutability; and the desktop CA/claim result and original
certificate authorization, followed by revocation. They do not contact APNs,
real Windows devices or a production broker. The CI workflow executes those
PostgreSQL drills on Linux and private-file/CLI/process boundaries natively on
Windows. Hardware, production provider and power-loss acceptance remain separate.

Local final recovery and CLI race suites pass in **6.049** and **1.748 seconds**.
The platform drills pass in **2.854** (Apple), **2.318** (Windows) and **2.098 seconds**
(desktop). The complete Apple, Windows and desktop regression suites pass in
**247.525**, **162.006** and **19.527 seconds**, respectively; the Windows protocol
suite passes in **1.422 seconds**. Bundle fuzzing passes **861,386 executions** in
**31.449 seconds**. Vet, module consistency and complete Linux/Windows builds pass.
Native Windows recovery-file/CLI/process checks pass in CI for `18fd1a8`.
The initial Linux job stopped before tests because the hosted image lacked the
PostgreSQL 17 client package source. CI now explicitly configures the official
signed [PostgreSQL Apt repository](https://www.postgresql.org/download/linux/ubuntu/)
and installs client-only packages on the disposable runner. Both corrected workflows
for `c5336c3` pass: [push CI](https://github.com/the-luap/openuem-console/actions/runs/34463014418)
and [pull-request CI](https://github.com/the-luap/openuem-console/actions/runs/34463018453),
including Linux database/platform drills, native Windows checks and builds.

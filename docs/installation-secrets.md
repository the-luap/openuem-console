# Persistent installation secrets

`openuem-installation-secrets` provisions JWT signing material, the database
encryption master key and the initial administrator password without writing any
of their values to standard output, errors or command arguments. It is an offline
Linux/macOS provisioning command; runtime file loading also supports Windows.
It does not connect to a database, install a service or modify host credentials.

Run the command as the provisioning/service account under an existing trusted
parent directory:

```sh
openuem-installation-secrets --directory /private/openuem/installation
```

The command creates one private directory, without creating its parents or
changing existing permissions. Standard output contains only the randomly
generated installation identifier. A successful invocation has these files:

| File | Purpose | Runtime mount |
| --- | --- | --- |
| `jwt.key` | Independent 256-bit random JWT signing secret, encoded as 43 ASCII characters | Console, read-only |
| `encryption.key` | 32 ASCII characters carrying 192 random bits; passed directly to the existing AES API | Console, read-only |
| `initial-password` | Independent 256-bit random password with a fixed complexity prefix | First administrator setup, read-only |
| `secrets.json` | Protected durable source of the installation identifier and all three secrets | Provisioning/recovery only |
| `manifest.json` | Completion marker binding file digests to the installation | Provisioning/recovery only |

The encryption key is already the actual 32-byte input required by existing
OpenUEM encryption. Do not decode it, convert it to a 64-character hex string or
replace it with the JWT secret. The generated credentials use independent random
bytes. Read the initial password through an authorized local secret-management
workflow; the command deliberately does not print it.

## Runtime configuration

The foreground console accepts `--jwt-key-file` / `JWT_KEY_FILE` and
`--encryption-master-key-file` / `ENCRYPTION_MASTER_KEY_FILE`. Installed services
accept the same environment variables. Selecting a JWT file bypasses the legacy
INI/Windows credential lookup. For example, mount only the selected input files
and configure their paths:

```sh
JWT_KEY_FILE=/run/openuem-secrets/jwt.key
ENCRYPTION_MASTER_KEY_FILE=/run/openuem-secrets/encryption.key
OPENUEM_BOOTSTRAP_PASSWORD_FILE=/run/openuem-secrets/initial-password
OPENUEM_BOOTSTRAP_ADMIN=openuem
```

For a fresh installation, also set `OPENUEM_INSTALLATION_ID` to the exact
32-character lowercase hexadecimal identifier printed by provisioning. This
enables permanent database binding before the first account is created. The
identifier is public metadata; preserve it with the provisioning source.

These settings complement the remaining database, TLS, broker and console
configuration. Do not set raw `JWT_KEY` / `ENCRYPTION_MASTER_KEY` values alongside
their file alternatives: conflicting inputs are rejected. A missing or invalid
file never falls back to a legacy value. Individual mode requires both runtime
keys, a JWT of at least 32 bytes and an encryption key of exactly 32 bytes.
Legacy raw-input behavior remains available outside that mode.

The console also accepts `--dburl-file` / `DATABASE_URL_FILE` for a separately
provisioned database connection URL. Installed services use the same environment
setting and skip their legacy database credential lookup when a file is selected.
The URL must use `postgres://` or `postgresql://`, specify a network host and a
database, and contain at most 8192 printable non-space ASCII characters, with an
optional LF/CRLF terminator. Percent-encode reserved characters in credentials.
Configure the intended TLS mode and trust parameters in that URL. Parser errors
never echo the URL or its password. Raw `DATABASE_URL` / `--dburl` and a URL file
are mutually exclusive; missing files cannot trigger a legacy fallback. The
main installation generator does not create database accounts. The separate
[database credential provisioner](database-credentials.md) now creates independent
bootstrap/application passwords and the protected URL file.

The installation, database credential and database bootstrap commands also have
[separate setup container images](setup-containers.md).

Files must be protected regular files owned by the service or system
administrator; Unix group/other access and untrusted Windows ACLs are rejected.
The loader rejects final symbolic links, replacement during open, excessive
length, spaces, control characters and non-ASCII content. It accepts a single LF
or CRLF terminator. JWT files contain 32–128 characters and encryption files
exactly 32. Keep all parent directories trusted against replacement.

The [first-administrator workflow](first-administrator-bootstrap.md) consumes the
initial password only while creating a fresh account. After completing the first
login, remove that runtime mount. Keep the protected provisioning source intact;
unmounting a file is different from deleting its durable original.

## Restart, interruption and recovery

Provisioning writes and syncs `secrets.json` before writing any runtime file. It
syncs completed files and directory entries before returning success. Complete
interrupted writes can be resumed using exactly the same source secrets. A
concurrent initializer may return an error while another process is writing;
retry the command after that process finishes. No process overwrites an existing
file, and consumers must wait for a successful invocation before starting.

Later invocations validate the canonical source, all credentials and the
completion marker. A missing source, a missing committed runtime file, extra
directory entries, changed material, invalid permissions or a partially written
file causes an error. Existing state is retained for investigation or restore;
the command does not silently regenerate or repair it. Losing a completion
marker can only republish the exact credentials retained in a valid source.

Back up the provisioning source with the installation's protected recovery
material. Do not run this initializer against a new empty directory as a recovery
procedure for an existing database: it would create a different installation.
Restore the original secrets, installation identifier and database together.
Rotation, service-specific volume
ownership and complete reference composition remain separate work. This command
does not claim a completed fresh-stack or disaster-recovery acceptance test.

## Database binding

With `OPENUEM_INSTALLATION_ID` selected, startup records independent HMAC proofs
for the JWT and encryption keys in a fresh account registry. The database stores
the public identifier and proofs, without storing either key. A separate permanent
completion marker commits in the same transaction. Account/grant bootstrap and
competing secret bindings share a transaction-level advisory lock; ordinary
registrations are also serialized while checking that the registry is empty.

Every subsequent worker startup checks the retained binding before initializing
accounts, encrypting database fields or starting listeners. A different/missing
identifier, changed key or missing binding/marker stops startup. Clearing the
environment setting or selecting legacy mode cannot bypass an existing binding.
Account deletion and a missing initial-password mount cannot reset it.

Existing unbound installations retain their startup behavior while the identifier
is unset. They cannot silently opt in after accounts or access history exist; an
explicit migration that verifies their existing credentials remains separate
work. The check does not overwrite old keys or authorize rotation. Losing both
the database and its retained records still requires restoring the original
installation, rather than initializing a new empty directory.

## Validation

Tests cover private file loading, conflicting sources, redacted failures,
idempotent initialization, concurrent creation, interruptions after every complete
write, malformed/changed/missing state and legacy AES compatibility. Command tests
check output privacy and recovery after an output failure. Installed-service
tests prove that mounted credentials work with an unavailable legacy credential
store. The real PostgreSQL/router administrator test uses generated secrets for
first login, password replacement, session encryption and signed invitations.
Database tests cover exact restarts, conflicting initializers, changed/missing
keys, marker rollback and loss, occupied registries and retained account history.
An actual worker test verifies that switching to legacy mode and requesting an
account reset cannot bypass a bound database.

The [protocol key provisioner](protocol-keys.md) reads this completed directory
without modifying it and creates separate retained Windows authority encryption
and desktop bootstrap signing keys. The existing three-secret format stays
unchanged. Keep the additional journal separate from runtime mounts.

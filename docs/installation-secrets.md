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

These settings complement the remaining database, TLS, broker and console
configuration. Do not set raw `JWT_KEY` / `ENCRYPTION_MASTER_KEY` values alongside
their file alternatives: conflicting inputs are rejected. A missing or invalid
file never falls back to a legacy value. Individual mode requires both runtime
keys, a JWT of at least 32 bytes and an encryption key of exactly 32 bytes.
Legacy raw-input behavior remains available outside that mode.

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
Restore the original secrets and database together. Automatic database/secret
binding, rotation, database credential provisioning, service-specific volume
ownership and complete reference composition remain separate work. This command
does not claim a completed fresh-stack or disaster-recovery acceptance test.

## Validation

Tests cover private file loading, conflicting sources, redacted failures,
idempotent initialization, concurrent creation, interruptions after every complete
write, malformed/changed/missing state and legacy AES compatibility. Command tests
check output privacy and recovery after an output failure. Installed-service
tests prove that mounted credentials work with an unavailable legacy credential
store. The real PostgreSQL/router administrator test uses generated secrets for
first login, password replacement, session encryption and signed invitations.

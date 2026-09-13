# Task secret encryption and migration

Local account passwords and SSH key passphrases are encrypted before authorized
creation or replacement. Empty values remain empty. Explicit editor keep leaves
the original column untouched; clear requires an empty input. Reviews expose only
whether each secret is set. The console and worker use the same immutable shared
`github.com/open-uem/nats/tasksecrets` package. No secret is added to audit events,
review responses or migration errors.

SSH storage uses a versioned AES-256-GCM envelope with a random nonce and a
purpose-specific HKDF-SHA256 key derived from the 32-byte raw master key. The field
and version prefix are authenticated. Authorized task/profile clones can copy the
ciphertext because the binding does not include database IDs. This format does
not prevent a database writer from substituting another task's SSH ciphertext.
The shared package documents the exact format and its compatibility contract.
Passwords retain their historical unmarked AES-GCM hex format.

Plaintext is bounded to 16 KiB, valid UTF-8 and without NUL. Stored-size limits in
manual dispatch include encryption overhead. Manual task execution and scheduled
worker configuration generation decrypt into temporary values. Wrong keys,
corrupt envelopes and unsupported SSH versions return no executable partial
configuration. The worker no longer returns early after successful password
decryption or mutates the stored password; Unix user-removal tasks also use their
correct task type. Agents receive the existing configuration fields and need no
new secret-storage protocol.

## Coordinated upgrade

The compatible worker implementation is [a975e61](https://github.com/the-luap/openuem-worker/commit/a975e61),
using shared module [36652c9](https://github.com/the-luap/openuem-nats/commit/36652c9).

1. Back up the database and its matching encryption master key using the existing
   protected operational process. A database backup alone cannot recover secrets.
2. Upgrade every worker to the shared version-one reader while the older console
   still writes legacy SSH plaintext. The new worker reads both formats. Check
   the configured raw 32-byte key agrees across services.
3. Stop all old worker and console instances before starting the upgraded console.
   Old workers treat encrypted SSH storage as a literal passphrase. There is no
   automatic worker-version handshake or mixed-version safety gate.
4. Start the new console. After audit migrations and before inventory dispatch
   and console HTTP serving, task secrets migrate in batches of at most 64 rows.
   Each batch holds row locks and commits its changes and audit entries together.
   Rows are scanned by ID up to the initial maximum; normal new writes are sealed.
   Migration covers nonempty secret fields on all task types, including disabled
   tasks and rows without a current profile. It preserves NULL versus empty,
   task versions, ordering, assignment and every other configuration field.
5. Confirm console startup succeeds and inspect global inventory audit entries
   with action `inventory.tasks.secrets_migrate` and actor
   `system:task-secret-migration`. Each changed task records its numeric ID and
   Boolean field-change indicators. Organization/site audit readers do not see
   these global maintenance events. Normal inventory audit retention applies.

An authentication failure, invalid value, missing key for a nonempty plaintext
secret, database error, audit failure or startup deadline stops console startup.
Completed batches remain committed. Fix the cause and restart: existing envelopes
are authenticated and preserved, and only remaining plaintext is encrypted.
The active batch rolls back, including its audit events. The startup context has
a finite deadline; a very large dataset may require repeated starts to complete.
The authentication service has its own lifecycle; migration does not claim to
stop every other service. No device command is issued by migration.

Do not downgrade workers against the migrated database. A rollback requires a
matching pre-upgrade database/key backup and coordinated service rollback. This
change does not implement key rotation, old-key fallback or key recovery.

## Legacy ambiguities and recovery

The entire `openuem:task-secret:` prefix is reserved. A preexisting literal SSH
passphrase beginning with that prefix must be explicitly replaced and sealed
before migration; unknown versions must never silently execute as plaintext.
Historical passwords have no marker. A hex value of at least 28 decoded bytes
must authenticate; shorter hex passwords are valid legacy plaintext. A long hex
plaintext password is indistinguishable from damaged historical ciphertext.

If startup identifies an affected task ID, first verify the correct existing
master key and restore damaged data from a matching backup when possible. For
ambiguous legacy values, use the previous console's explicit password/passphrase
replacement before the upgrade; choose a new unambiguous SSH value without the
reserved prefix. If some batches already migrated, restore the matching
pre-upgrade backup before using an old console. Never print stored values, put
secrets in command-line arguments, or change the key simply to bypass failure.
The new editor always seals literal replacement input, including prefix-like
text, so newly created values have no prefix ambiguity.

## Verification

Shared codec race tests cover independent format construction, fresh nonces,
legacy migration, repeated migration, malformed encodings, tampering, missing or
wrong keys, Unicode, empty values and storage bounds. A decoder fuzz run completed
744,587 inputs. Owned PostgreSQL tests cover batch rollback/restart, audit failure,
NULL preservation, unchanged metadata, global audit visibility, encrypted
creation/replacement, task/profile cloning and maximum-size manual dispatch.
Worker tests cover complete Windows, Linux and macOS configurations after
password/SSH decryption, subsequent account removal, repeatability and rejection
without partial output. These are protocol/configuration tests, not physical
endpoint acceptance or a production migration benchmark.

The complete inventory PostgreSQL/race suite passes in 122.049 seconds and the
audit suite in 10.762 seconds. Registered Apple/OIDC routes, affected Linux race
checks and the full console Linux build pass. The worker's complete model/common
PostgreSQL/race suites and command tests pass, with full Linux and Windows builds.
No UI markup changed in this milestone; the existing registered form routes were
checked without rerunning the unchanged complete browser matrix.

Broader settings/provider secret migration and a complete rotation/recovery
lifecycle remain separate roadmap work.

# Session token storage

The PostgreSQL session store preserves the existing table and token format.
With a configured master key, database token IDs use the existing randomized
AES-GCM/hex encryption. Session payload encoding is unchanged. All active console
writers must use the same encryption configuration and key.

Encrypted commits resolve their existing token representation and write it in
one transaction. A table write lock also coordinates ordinary SQL token
migration and deletion. This prevents concurrent first commits from creating
multiple randomized ciphertext rows for the same browser token. Token migration
updates the primary key in one statement, retaining data, expiry, ownership and
other columns; it no longer creates a copy followed by a separate delete.

Deletion removes every matching physical representation, including expired
duplicates. If lookup discovers multiple active representations from an older
version, it retires that credential and lets the browser start a fresh session.
Ambiguous direct writes or enumeration fail instead of silently choosing one
record. Database errors and cancellation propagate to the session middleware.
Lookup never treats an encrypted database value as its corresponding browser
credential. Plaintext rows await the existing startup migration when encrypted
mode is enabled.

Shared decoding checks the nonce/tag length before opening legacy ciphertext.
Short hexadecimal and unrelated plaintext records cannot panic the store or
prevent another session's owner association. Owner association reads only token
IDs, requires one matching encrypted record and respects the request context.
Database cursors close before subsequent operations, including when the pool has
only one connection. Transaction rollback uses a bounded cleanup context.

Disposable PostgreSQL race tests reproduce the previous twelve-row concurrent
commit and incomplete deletion, hidden cancellation, and mixed-record owner
failure. Regressions cover one-record concurrent commits, deletion, automatic
retirement of legacy duplicates, expired duplicates, single-connection operation,
atomic concurrent token migration, preserved ownership and ciphertext rejection.
The legacy decoder also has compatibility tests and a bounded fuzz target.
The owned TLS/console sign-in matrix runs with both plaintext and encrypted token
storage, including failed admission, account switching, policy revocation and
temporary database contention.

Encrypted lookup still scans legacy token IDs, and encrypted writes serialize
at the table level. Indexed token lookup and production-scale acceptance remain
separate work. This change does not introduce durable revocation tombstones for
requests that loaded a session before deletion; the middleware's later-write
behavior remains a separate lifecycle requirement. See [OpenID sign-in](oidc-sign-in.md)
for the current identity-revision checks on protected console requests.

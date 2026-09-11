# Session token storage

The PostgreSQL session store retains the existing `sessions` table, payload
encoding and randomized AES-GCM/hex token encryption. With no master key, token
IDs remain plaintext. A required `token_lookup` column contains the SHA-256 digest
of a domain prefix and the browser token. A unique index selects one record;
lookup verifies its actual token representation before returning data. Neither
the digest nor an encrypted database token is accepted as the browser token.
SCS payload encoding is unchanged; this is not payload encryption.

## Durable deletion

Deleting a session also inserts its digest and deletion time into
`sessions_revocations` in the same database transaction. Row-deletion triggers
cover SCS logout, administrator deletion, bulk Ent deletion, credential resets
and expiry cleanup. A statement trigger covers truncation. Trigger relation names
are bound to their actual schema, independently of the deleting client's search
path. Receipt failures roll back deletion and propagate an error.

A commit explicitly uses Read Committed isolation, takes a transaction-scoped
advisory lock for its token, locks any existing
record and then checks revocation in a new statement. This ordering observes a
deletion which finished while the writer was waiting for the row, even when the
connection defaults to Repeatable Read. This follows PostgreSQL
[statement snapshot and row-lock behavior](https://www.postgresql.org/docs/current/transaction-iso.html#XACT-READ-COMMITTED). A completed
deletion rejects later writes, including requests which loaded their data earlier
and writes from a restarted console. A rolled-back deletion leaves the session
usable. Different tokens can write concurrently. Reads also exclude revoked
records. SCS can create a fresh session with a new random token after deletion.

Store deletion records even a nonempty token whose first write is still pending;
destroying an empty, never-committed session creates no receipt. Revocation receipts
are permanent and contain no account ID or session payload. Do not prune them:
there is currently no proven maximum duration for every outstanding writer. A
bounded retention policy and production storage-growth acceptance remain open.
Expiry cleanup removes session data but retains its receipt. Already admitted
application operations may finish; this store does not cancel in-flight handlers
or undo their other database changes.

## Upgrade and operation

Stop all console/authentication writers before upgrading this schema. The old
store does not supply the mandatory lookup column or honor revocation receipts;
a rolling deployment with older writers is unsupported. Retain a consistent
database backup and the original master key. Downgrading the executable against
the migrated schema is unsupported.

Before either HTTP server starts, the session manager runs one atomic migration
with a two-minute deadline. It adds the index, receipt table, triggers and a
configuration binding. Existing tokens are decoded and indexed in batches of
at most 500 IDs. Plaintext records are encrypted when a master key is configured.
Primary-key updates retain expiry, payload, ownership and other columns. Every
representation of a duplicated logical token, including expired copies and
copies in later batches, is removed and its digest permanently retired. Those
browsers must sign in again. Unique existing sessions retain their tokens.

The migration rejects legacy ciphertext which cannot be opened with its original
key. Once initialized, a different key or encryption mode fails startup. Key
rotation and switching encryption mode require a separate migration; changing the
environment variable alone is unsupported. Failed or canceled migrations roll
back and can be retried with the correct configuration. Concurrent starts serialize
migration and reuse the same completed schema. Startup errors are returned to the
caller, and the store refuses requests until initialization succeeds. The old
best-effort token-encryption loop has been removed.

Shared decoding checks nonce/tag lengths before opening legacy ciphertext.
Short hexadecimal records cannot panic startup. Owner association uses the same
unique lookup index, verifies the token, respects request cancellation and updates
only an existing record. Database errors reach the middleware. The active-session
list remains an administrative database view; session enumeration necessarily
visits the returned records. Normal lookup and writes no longer scan all token IDs
or take a table-wide write lock. Schema migration alone takes an exclusive table
lock. Normal writes require PostgreSQL advisory-lock and table permissions; the
upgrade also requires schema/table/function/trigger creation privileges.

Expiry cleanup uses cancellable database attempts with a thirty-second deadline.
Stopping the worker cancels an active query and joins its goroutine before the
pool closes; concurrent and repeated stop calls are safe. Transactions roll back
with a separate bounded cleanup context.

## Verification

Owned PostgreSQL fixtures first reproduced six cases of usable sessions returning
after deletion: logout, administrator deletion and bulk credential-reset deletion,
with both plaintext and encrypted storage. The real SCS manager/codec regression
now covers those paths, truncation, restart, fresh login and idle-timeout cleanup.
Controlled row locks prove commit/delete ordering, rollback behavior and concurrent
progress for an unrelated token. Injected receipt failures cannot partially delete
a session.

Additional tests cover eight concurrent migrations, mismatched keys/modes,
canceled migration and retry, legacy migration preserving ownership/data/expiry,
1,002 duplicate ciphertext records across batches, one-connection operation,
quoted and long table names, deletion with a changed search path and ordinary Ent
schema restart. A 2,000-row fixture verifies the PostgreSQL lookup index is used;
this is not production-scale load acceptance. Tests reject digest/ciphertext bearer
values and inconsistent indexed records. The decoder also has race and fuzz tests.

The actual Linux ARM64 console/OIDC matrix runs with both encryption modes,
including failed admission, account switching, live identity revocation and
transient database contention. Startup migration and protected administrator
password lifecycle tests use the production session-manager initialization. See
[OpenID sign-in](oidc-sign-in.md) for identity-revision checks on protected requests.

# Session token storage

The PostgreSQL session store retains the existing `sessions` table, payload
encoding and randomized AES-GCM/hex token encryption. With no master key, token
IDs remain plaintext. A required `token_lookup` column contains the SHA-256 digest
of a domain prefix and the browser token. A unique index selects one record;
lookup verifies its actual token representation before returning data. Neither
the digest nor an encrypted database token is accepted as the browser token.
SCS payload encoding is unchanged; this is not payload encryption.

## Sign-in admission

Password, certificate, OpenID, local MFA completion and password-replacement
flows use one session-establishment operation. It clears all old values, renews
the token even for the same account, stores the new flow, associates its owner
and completes any required login confirmation before publishing the cookie.
Completed password login without MFA no longer issues an intermediate cookie.
Pending second-factor sessions also have an owner for administrative deletion.
An unused recovery helper which removed the recovery restriction has been removed.

Failure clears in-memory identity before attempting bounded storage deletion.
This prevents outer SCS error rendering from saving an authenticated session again,
including when deletion itself fails. Cleanup uses a separate two-second context
so cancellation of the initiating request does not prevent cleanup. Recovery and
second-factor state from a previous account or flow is never inherited.

OpenID MFA completion carries forward only an identity which still passes current
account/binding/policy validation. Its local confirmation remains conditional;
missing identity requires sign-in again. This shared operation addresses session
state and cookie publication. Local credential/method validation is described below; remaining MFA persistence
and concurrency guarantees remain separate security work.

Owned regressions reproduced inherited authority and usable cookies after failed
owner association or login confirmation. Tests cover same-account reauthentication,
account changes, cleanup failure and canceled requests. Certificate tests perform
real mutual TLS using a disposable CA and local signed OCSP responses. The complete
OpenID route matrix covers actual TOTP completion, retained valid identity and
rejection of missing identity, with both token-encryption modes. The protected
administrator password/recovery lifecycle also passes with the shared operation.

## Local account admission

Password and certificate admission now lock the current authentication settings
and account in a Read Committed transaction with a five-second deadline. The
configured method and account mode must agree. Password admission also matches
the exact password hash that was verified; both methods reject a changed MFA
requirement. Revoked, review and incomplete accounts cannot be promoted by login.
Approved/completed accounts may sign in; issued-certificate accounts can finish
certificate sign-in. Forced initial-password accounts can enter only the separate
password-replacement flow, without prematurely completing registration.

The checks run before a password flow starts and again after session ownership is
associated. Completed admission updates registration and clears the temporary
certificate password inside that same transaction. Certificate MFA remains pending
until its second factor completes. The old unconditional `ConfirmLogIn` update has
been removed. An explicit `authentication-pending` session flag prevents a pending
first factor from becoming a full session if MFA is disabled while the browser
is answering its challenge. Public MFA actions require that pending phase too.

Owned regressions reproduced denied account reactivation, password use on a
certificate account, disabled-method admission and confirmation overwriting an
intervening revocation. Tests now reject those cases, password changes and newly
enabled MFA during owner association, plus incompatible certificate account modes.
A canceled row-lock wait cannot partially confirm an account; a later valid first
login clears its temporary certificate password. The forced-password lifecycle
remains restricted and the protected administrator startup/password tests pass.

These checks govern new local sign-in admission. They do not yet provide complete
request-time local credential revalidation ; the separate recovery/invitation checks below also apply to credential changes.

## Password replacement policy

Initial-password, email-recovery and invitation proofs must still match the
current account when the new password is committed. Their five-second Read
Committed transaction locks authentication configuration before the user, using
the same lock order as local sign-in. Password authentication must remain enabled;
the account must remain in password mode, outside OpenID mode, and in an approved,
completed, password-link-sent or forced-password state. Initial-password proofs
still require the forced-password state specifically. Revoked/review accounts and
incompatible modes cannot be reactivated by an earlier recovery or invitation.

The existing exact password/source digests, expiry and single-winner checks remain.
Successful replacement consumes the recovery/invitation records and deletes all
owned sessions in the same transaction, generating durable revocation receipts.
A previously loaded session cannot recreate itself afterward. Existing MFA
configuration is preserved. Denied replacement leaves credentials, registration,
source grants and session rows unchanged. A committed revocation observed after a
row-lock wait denies replacement; a rolled-back revocation permits valid work.

Fifteen owned policy cases cover all three proof kinds; the baseline reproduced
thirteen invalid replacements, including reactivation and unintended session
removal. Positive recovery/invitation cases cover both storage modes, retained MFA,
source consumption, grant replay and preloaded-session retirement. The production
administrator password/recovery/invitation routes and concurrent initial-password
replacement test also pass. Fixture invitations use the same password-link-sent
registration state as administrator invitation issuance.

## MFA and recovery boundaries

A password-replacement session identifies its target account but cannot authorize
MFA enrollment, enrollment confirmation, TOTP validation or backup-code use. Every
public MFA action requires a `login-primary` proof retained only in the server-side
session after a verified password, certificate or OpenID sign-in. The proof binds
the account, method, credential digest and a fifteen-minute deadline. Password
proofs match the current password hash; certificate proofs record the verified
certificate digest; OpenID proofs match and revalidate the admitted identity.

MFA admission also checks current account registration, authentication mode,
enabled method and MFA configuration. Missing/expired proofs, password changes,
mode changes, revoked/review accounts and disabled methods or MFA deny the step.
An existing confirmed TOTP enrollment cannot be overwritten through the public
login enrollment endpoints. TOTP/backup-code login requires confirmed enrollment.
Successful MFA creates a fresh session and removes the pending primary proof.
An older pending session without a proof must restart primary sign-in after this
upgrade. Account-settings enrollment remains a separate protected workflow.

The owned baseline demonstrated recovery sessions crossing all four MFA mutation
or admission paths, with both storage modes. Regressions now deny those transitions
and preserve account MFA state. Positive tests cover password/TOTP, password/backup
code and first enrollment, plus actual certificate and OpenID MFA completion.
Proof identity, method, lifetime, size and malformed-state tests run in CI; database
checks cover changed credentials and disabled/revoked state.

These checks do not make the existing enrollment/recovery-code mutations atomic.
Durable one-use MFA consumption, TOTP replay counters, concurrent enrollment
completion and request-time local credential revalidation remain open. A request which
already loaded its primary proof may still race another completion; removing the
proof from the completed session alone is not a durable consumption receipt.

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

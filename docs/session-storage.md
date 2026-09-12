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
account/binding/policy validation. Its final transaction also locks the current
configuration, identity binding and account before confirming registration. It
compares the policy, binding revision, active state, account mode and exact MFA
state, including the stored TOTP secret. Missing identity or changed authorization
requires sign-in again. Initial callbacks use the same transaction with an explicit
pending/complete MFA distinction. Configured initial auto-approval is retained
only for an account whose pending-review state has not changed since validation.
Confirmation cannot undo review imposed on an already approved account.

The owned OpenID baseline reproduced 22 callback/MFA admissions despite review,
disabled method, inactive/revised binding or changed MFA requirements/secrets.
The actual TLS-provider/router fixtures now reject those changes before issuing
a cookie. Store tests cover initial auto-approval, pending and completed enrollment,
plus canceled and committed/rolled-back binding-lock waits. These checks govern
admission; the shared one-use evidence described below also covers MFA completion.

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

New sign-in admission and request-time policy checks have distinct stages. The
recovery/invitation checks below also apply to credential changes.

## User certificate admission

TLS chain/possession and signed OCSP verification are followed by a current
registry check in the final local admission transaction. The certificate serial
must identify a `user` certificate owned by the exact account, with the same
expiry as the presented certificate and no local revocation entry. Missing,
reassigned, non-user, deleted, expired or revoked records deny admission. The
serial must be positive and fit the legacy signed 64-bit registry; native user
issuers already generate within that range. Certificate records must exist before
sign-in; trusted TLS credentials alone do not authorize creation of a registry
entry or adoption of another user's record.

Configuration and account locks precede the certificate checks. A short shared
lock on the legacy revocation table serializes even an absent-record check against
existing insert/delete writers, which have no common parent-row or advisory-lock
protocol. A shared certificate-row lock protects owner, purpose and expiry.
The five-second transaction deadline also bounds those waits. Confirmation and
MFA evidence consumption follow only valid current state, and certificate expiry
is checked again before commit. Invalid state cannot leave partial confirmation
or consumed primary evidence. Revocation-table writers may wait for active
admission checks; contention and production scale remain operational acceptance.

Pending certificate MFA retains the already verified public DER certificate in
the server-side session, bounded to 16 KiB. Its exact digest must match the
primary proof; user identity, client-auth usage, serial and lifetime must remain
valid. Public MFA authorization, the pending console challenge and final TOTP or
backup-code admission recheck the registry. The final transaction also binds MFA
evidence to the certificate digest. No private key is retained. The public
certificate is discarded with pending state after successful completion.
Older pending certificate sessions without this evidence must restart sign-in.
All older console/authentication writers must stop before upgrade.

Eight owned mutual-TLS/OCSP baseline cases admitted invalid registry state,
including changes during session association. Regressions now deny all eight.
Further tests replace ownership or add revocation after TOTP/backup verification
in both storage modes, check committed/rolled-back/canceled registry waits and
valid retries, and distinguish retired pending state from transient registry
failure. Certificate parsing tests cover proof mismatch, malformed/oversized
data, invalid serials and lifetime boundaries. Existing successful mutual-TLS,
MFA and failure-cleanup fixtures now register their owned user certificates.

These checks govern initial and pending/final MFA admission. Completed sessions
still need original-certificate lifetime/revocation/rotation binding; the current
local policy checks below do not retain the original certificate. The legacy
registry also lacks issuer/key and account-generation identifiers. Certificate
reissue, CA rotation and account deletion/recreation need those additional
bindings before the full credential-lifecycle roadmap can be closed.

## Current local session policy

Protected console requests now recheck the method recorded in the server session
against current password/certificate configuration and account mode. The account
must still be approved or completed. Revoked/review, forced-password, invitation
and newly issued-certificate states cannot retain a completed session. A local
session cannot become an OpenID session when the account mode changes. Missing
or malformed stored method flags require a new sign-in. A previously completed
second factor cannot authorize removed or unconfirmed MFA.

The account lookup and local policy transaction share a five-second request
deadline. Configuration and account are read under shared locks in Read Committed
isolation; concurrent valid requests may coexist, and a policy writer is observed
after its lock is released. Verification does not confirm registration or modify
credentials. The exact snapshot read for this request is checked again under the
lock. The endpoint runs after these locks are released; its domain transaction
must still enforce current permissions and mutation-specific authorization.

An invalid local session loses in-memory authority before its stored token is
deleted, with a separate two-second cleanup deadline. Successful deletion creates
a permanent receipt, so a preloaded writer or a replayed cookie cannot return,
even if account policy is later restored. A transient account/configuration read
failure instead returns generic HTTP 503 and retains the session for retry.
Deleted accounts are retired. An OpenID account without its bound identity cannot
fall back to local authentication.

A pending certificate login can still present its MFA challenge, including the
issued-certificate state, but only with a fresh matching primary proof. It cannot
reach the protected endpoint. Recovery sessions remain excluded. The existing
password/certificate/OpenID MFA completion checks still apply separately.

The owned baseline admitted all eighteen invalid policy cases. The expanded
regressions cover both methods, valid single-factor/MFA sessions, missing method
state, OpenID mode changes, pending proof checks, transient lookup/configuration
failure, retry and committed/rolled-back account waits. Registered HTTP routes
with production CSRF/session middleware verify cookie deletion and durable
retirement in both storage modes. Synthetic role/browser fixtures now declare
completed certificate accounts and the same method flag written by real sign-in.

The generation checks below also bind completed sessions to the account and
method state at admission. Original certificate expiry/revocation/rotation remains
separate. Request-time checks cannot recall a domain action already admitted
before a later policy change; domain transactions must still enforce their own
authorization boundaries.

## Completed local session generations

Completed password and certificate sessions now carry random generation UUIDs
for their account and authentication method. Database triggers rotate the account
generation when its password hash, account mode, creation identity, MFA requirement,
confirmation or active secret changes, or its registration crosses a restricted
state. Method enable/disable changes rotate the corresponding method generation.
Restoring a previous field value does not restore its earlier UUID, so a brief
suspension or policy cycle still invalidates existing sessions. Generation changes
commit or roll back with the credential/policy write.

Ordinary name/email/profile edits, preparation of an unconfirmed MFA secret while
MFA is disabled, and normal approved/issued-certificate sign-in confirmation do
not rotate the account generation. Changing certificate policy does not rotate
the password-method UUID. Account deletion removes its generation; recreation
gets a new one even if the UID, creation time and credentials are copied exactly.
Account-settings MFA confirmation requires a new sign-in for subsequent protected
requests, after the response has shown the newly generated recovery codes.

Final local admission reads these identifiers while holding configuration and
account locks. Only a successful commit returns the new session stamp. The shared
session publisher saves the stamp after final admission and before sending its
cookie. Failure of that second save clears authority and retires the token; a
valid retry can sign in. Confirmation and MFA receipts already committed by final
admission remain committed if later session persistence or delivery fails.

Protected requests compare the stored generation with current UUIDs under the
same source locks as policy verification. They cannot adopt a new generation by
loading the latest password hash or MFA secret. Rejected sessions are retired;
transient verification failures still permit retry. The generation is server-side
metadata, not a client-supplied credential or replacement for session-token proof.

Migration seeds existing accounts and method identifiers, installs schema-bound
triggers and preserves UUIDs on repeated startup. It rejects missing/disabled
triggers or incomplete generation rows. New trigger writes require the application's
database writers to retain access to the generation tables. All older console/auth
writers must stop before upgrade. Completed local sessions without a stamp must
sign in again. Existing database-backed credential writers participate through
the triggers without constructing session metadata themselves.

Twelve owned baseline cases retained old password sessions after credential,
MFA, account-generation and restored-policy changes. The corrected baseline and
regressions use actual password/TOTP completion in both storage modes. Additional
checks cover harmless edits and staging, method isolation, rollback and injected
trigger failure, a caller with a different search path, repeated startup, disabled
trigger rejection, exact account recreation, canceled credential waits, fresh
processes and failed final session persistence with a valid retry.

This stamps completed local sessions. Pending primary proofs still use their
existing credential, lifetime and certificate-registry checks; they do not yet
carry independent account/method generation stamps. OpenID uses its separate
live policy and binding-revision checks. Original certificate lifetime, registry
changes after completed sign-in, issuer/key identity and rotation remain open.

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

The protected account-settings password change now uses the same transaction.
Its handler verifies the current password, requires completed MFA when configured,
and passes the full account snapshot to the model. The transaction checks the
current password hash, password method, enabled configuration, approved/completed
registration and exact MFA requirement, confirmation and stored secret. It cannot
override a newer password, revocation, review or MFA change. Forced-password and
invitation states must use their respective restricted workflows. An account
proof cannot enter this path through the serialized recovery-proof API.

A successful account change clears outstanding email-recovery/invitation grants
and retires every owned session atomically, preserving MFA configuration. Failure
at session deletion rolls back the password and all other writes, including the
revocation receipts. A valid retry remains possible. Cancellation during an
account-row wait cannot commit after the lock is released; a rolled-back policy
change permits the original request. Concurrent changes based on one verified
password have one winner. The same password is rejected, and empty new-password
and confirmation fields now use their correct validation messages.

Owned tests exercise the registered HTTP route with its CSRF and session
middleware in both storage modes, including cookie deletion and replay of the old
cookie. Separate tests cover invalid inputs, current policy, intervening changes,
transaction failure, cancellation and concurrent replacement. Storage errors are
returned as generic HTTP 503 responses. This transaction binds the current password
verification to its write; broader completed-session credential revalidation and
account-settings step-up policies remain separate work.

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
Password/certificate completion rechecks the exact stored TOTP secret while
holding the account lock. A secret replaced after TOTP or backup-code verification
cannot authorize the final session. The owned eight-case baseline reproduced
this gap for both methods and storage modes; regressions inject replacement
during owner association and require cleared authority with no new cookie.
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

Enrollment persistence and one-use sign-in evidence use the transactions described
below. A preloaded pending session cannot bypass primary-flow or TOTP consumption.
Complete request-time local credential revalidation remains separate work.

## Atomic MFA enrollment

Secret staging, enrollment confirmation and MFA removal require the full account
snapshot whose authorization was checked. Configuration is locked before the
account, using read-committed transactions and a five-second request deadline.
The transaction rechecks current registration, enabled method, account mode,
password hash, MFA requirement, confirmation state and exact stored secret.
An older request cannot replace a changed or already confirmed secret. Existing
enrollment must be disabled before a new enrollment starts.

Confirmation hashes ten distinct recovery codes before acquiring database locks,
then replaces the complete code set and marks the exact staged secret confirmed
in one transaction. A competing completion loses its stale snapshot. Failure
during insertion or the account update retains the previous codes and MFA state.
Removal clears the secret and codes and deletes the account's sessions together;
session-deletion failure rolls back all three changes. Permanent session receipts
prevent a preloaded session from returning after successful removal.

Public MFA handlers retain the account snapshot returned by primary-authentication
validation. Account settings read full snapshots rather than selected hash/secret
fields. TOTP verification decrypts into a separate value using the safe legacy
decoder; it preserves the stored ciphertext used by the transaction comparison.
New recovery codes use unbiased random character selection and reject duplicates.
Conflicting state returns HTTP 409; storage failure returns a generic HTTP 503.

The owned baseline reproduced partial code replacement, code loss on failed
removal and overwrite of confirmed enrollment. Tests cover failure at insertion,
confirmation and session deletion; concurrent confirmation for password,
certificate and OpenID account modes with both storage formats; canceled and
committed/rolled-back row waits; stale authorization; exact ciphertext retention;
and the actual account-settings and public password/MFA handlers.

Database confirmation and delivery of the response or a new session are separate
operations. If response delivery or later session admission fails after commit,
MFA remains configured; the codes cannot be redisplayed because only their hashes
are stored. The configured authenticator remains usable. These enrollment transactions do not
confirm the later sign-in or deliver its response. Completed sign-in consumes its
primary proof and TOTP counter in the separate confirmation transaction below.
Protected account-settings code verification is not a new sign-in and does not
claim a login counter.

## Single-use recovery codes

Backup-code verification compares only unused hashes, then conditionally changes
the exact record from unused to used. The update rechecks its owner and stored
hash. Only one affected row followed by a successful transaction commit grants
admission. A competing consumer, changed hash, reassigned owner or deleted code
invalidates the earlier comparison. Hash verification holds no database locks;
unrelated accounts can consume their codes while another record is locked.

The request context and a five-second deadline cover the database work. An
explicit transaction prevents a canceled, blocked update from later committing
when its lock is released. Database failures return a generic HTTP 503 without
an authenticated cookie; neither the submitted code nor database diagnostics are
logged or returned by this operation. Empty and oversized inputs are rejected.
Hash comparison itself is not interruptible; cancellation is checked between
comparisons and before the write. An uncertain commit response denies admission
and may leave the code consumed. A committed code also stays consumed if a later
account-policy or session-admission check fails.

The owned baseline admitted four simultaneous requests with one code. Controlled
PostgreSQL row-lock tests now establish one winner, reject stale records, preserve
unused state on canceled waits and rejected writes, and permit valid retries.
Actual backup-code handlers repeat the four-request test and storage-failure
checks with plaintext and encrypted session stores. These guarantees concern a
stored recovery-code record. Enrollment/code-set replacement is covered above;
one-use primary proofs and TOTP counters are covered below.

## One-use MFA sign-in evidence

Every new `login-primary` proof has a random UUID in addition to its account,
method, credential digest and fifteen-minute lifetime. Two primary authentications
within the same second have different identities. Pending sessions created before
this change lack the UUID and must restart primary sign-in after the upgrade.

Final password, certificate and OpenID MFA confirmation consumes that UUID in
`uem_mfa_primary_consumptions` inside the same transaction as account confirmation.
Only one request can insert its receipt. This also rejects simultaneous use of
one primary flow with distinct valid backup codes. The earlier recovery-code
transaction remains separate: a code already consumed stays used if later primary
admission loses or fails.

TOTP sign-in records the actual accepted counter in `uem_mfa_totp_counters`, keyed
by account and a digest of the decoded authenticator key. Validation retains the
existing six-digit SHA-1, thirty-second period and one-step clock-skew policy.
The conditional update accepts only a counter greater than the last committed
counter for that key. Different base32 spelling, ciphertext changes, session
renewal or process restart cannot create a fresh counter for the same key. A
newer valid counter, another account or a new authenticator key remains usable.
Neither the passcode nor plaintext authenticator key is stored in these tables.

Primary receipt, counter advancement and final account confirmation commit or
roll back together. A storage error or cancellation after evidence insertion
cannot burn the flow or counter; a later retry can succeed. Once committed, the
evidence remains consumed even if HTTP delivery fails. Replay or expiration
returns HTTP 401, clears the failed session, and requires a new sign-in attempt
with a new code. This does not retire an independently completed valid session.

Session and identity-store startup migrations create the shared tables under a
common migration lock. Stop all older console and certificate-authentication
writers before upgrading: older versions do not consume these receipts and a
mixed deployment cannot provide the guarantee. Migration and session cleanup
preserve both tables. Receipts and per-key counters are retained permanently for
now; their growth and any future retention scheme require operational acceptance.

The owned baseline admitted four sessions for one primary flow with distinct
backup codes, and four for one TOTP counter with distinct primary flows, in both
session storage modes. Controlled admission barriers now produce exactly one
winner. Tests cover transaction failures, cancellation after receipt insertion,
valid retry, a newer counter, independent accounts/keys, equivalent and encrypted
key representations, repeated migration and a fresh process using the same owned
database. OpenID store concurrency and the actual TLS-provider/console routes
also reject consumed evidence while preserving the valid completed session.

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

# Durable NetBird removal recovery delivery

`NewNetbirdRemovalRecoveryDeliveryStore` adds native delivery and read-only receipt
observation to the [reviewed recovery request store](netbird-removal-recovery-requests.md).
Migration 034 adds immutable attempt, result and observation records, guarded
completion, cancellation exclusion and the updated five-family device barrier.
The original uninstall, its unconfirmed outcome and its owned release proof remain
unchanged. No route or automatic dispatcher is enabled by this store.

## Admission before native execution

`Recover` requires current `AssignSoftware` authority in the exact request site,
the immutable requesting actor and the exact console review revision. A device
lock serializes admission with cancellation and other NetBird request families.
A retained attempt is returned before any current native inspection or execution,
even when its result is missing, its request has expired or its recipient changed.
Current permission and exact historical scope are still required for that read.

A new attempt repeats the complete original-release proof and current individual
identity, membership, consumer, certificate, platform, architecture and inventory
checks. Version-four inspection must return the exact reviewed recovery descriptor,
recovery digest, console revision and explicit journal revision. Changed, absent,
missing, conflicting or unavailable evidence prevents admission.

The command is version five, operation `recover-removal`, with the new recovery
request UUID. `Command.Revision` is the console review; the descriptor retains its
separate `RemovalRecovery.JournalRevision`. Its issue time uses the database clock;
its lifetime is at most ten minutes, bounded by the reviewed current certificate.
The immutable database attempt retains only wire version, certificate hash,
command hash and times. Its audit commits in the same transaction before the one
direct transport call. No database transaction spans native execution.

Both Go and database guards reject cancellation after admission. Exact replay
never sends another command. A missing result is therefore `pending`, not retry
authority. The delivery constructor accepts a dedicated version-five executor;
fresh-removal source inspection and version-four uninstall execution are not used.

## Independent results and current receipt observation

A completely matching receipt can be retained with the first delivery result.
Only status `completed` confirms completion. Unconfirmed, busy, rejected and
withdrawn receipts remain unconfirmed delivery outcomes. An error, absent reply,
wrong correlation or caller cancellation retains no trusted receipt. Recording
uses a bounded context independent of caller cancellation after the executor
returns. If result recording or its audit fails, the committed attempt remains;
replay reads it without executing again.

`ObserveRecovery` requires current exact-site `AssignSoftware` authority. It sends
only a version-two `receipt` query for the retained recovery UUID, command hash,
console revision and operation. It authenticates the current individual recipient
and certificate, without requiring the old certificate or native staged files to
remain present. The query uses the database clock, a two-second response budget
and the current certificate/caller deadline. The exact source-free query and its
correlated response, or unavailable result, are retained with the audit.

Only an exact completed receipt without release metadata can mark the request
complete and remove the device barrier. Native absence, missing receipts,
unconfirmed evidence and release/withdrawal evidence cannot do this. Receipt
observation does not send a native command or release/withdraw the request.
A terminal completion is read without another query.

Public delivery history distinguishes `Outcome` from `OriginalOutcome`: the latter
is the first **recovery delivery** result, not the original uninstall result.
A later observation can confirm completion while that first result remains
unconfirmed or pending. If observation commits before the initial executor
returns, a late unconfirmed result cannot undo completion. The completion receipt
and its timestamp remain tied to the retained observation.

[Reviewed resolution](netbird-removal-recovery-resolutions.md) can separately
confirm release or withdrawal using exact owned control proof. Delivery history
then reports `released` with its resolution UUID, actor and timestamp, retaining
the first delivery outcome. Released requests return history without native work
or receipt observation; a late native result cannot replace terminal release.

Reads reconstruct the complete historical version-five command from immutable
request and attempt metadata and verify its canonical hash before trusting its
receipt. Public records contain neither the historical certificate nor an
executable envelope. Scoped history requires `ReadSoftware` and an audit.

## Database protections and verification

Attempts, first results and observations cannot be updated or deleted. Guards
reject stale or unavailable delivery admission, mismatched current recipients,
wrong operations/revisions/hashes, foreign original-uninstall receipts, unknown
source fields, malformed controls/responses and fabricated completion. Completion
requires an exact retained result or observation timestamp and becomes immutable.
All seven new guards are required at startup. Request UUIDs remain permanently
reserved after cancellation or completion; expiry alone does not free a device.

Owned PostgreSQL integration fixtures exercise exact admission and committed audit
before execution, cancellation exclusion, changed reviews/authority, lost and
mismatched responses, concurrent delivery, expiry without replay, renewed
certificate observation, audit rollback, malformed SQL evidence, startup guards
and corrupted retained command metadata. A held executor also verifies that late
uncertainty cannot undo an observed completion. Tests preserve the original
uninstall outcome and use no vendor remover or host NetBird state. The complete
NetBird inventory suite, with 177 top-level tests plus subcases, passes with race
detection against the owned PostgreSQL database. The Linux console build passes.

Joined automatic dispatch, coherent public history and UI remain separate
integration work. Missing, empty or incomplete
manifest policy and physical package/reboot acceptance also remain open.

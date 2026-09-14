# Reviewed resolution of NetBird removal recovery

`NetbirdRemovalRecoveryStore` now provides explicit resolution for an admitted
[recovery delivery](netbird-removal-recovery-delivery.md). An uncertain recovery
has its own request, command, journal state and resolution. The original uninstall
and its previously confirmed release remain unchanged.

## Current evidence and a retained review

`ReviewRecoveryResolution` requires current `AssignSoftware` authority in the exact
request site and its console review revision. It locks the device and request,
reconstructs the exact historical version-five command and verifies its hash,
then authenticates the current individual recipient. Certificate renewal does not
require the old certificate or the original native staged files to remain present.

A version-two receipt query binds the recovery UUID, command hash, console revision
and `recover-removal` operation. The query and correlated reply are retained.
An exact completed receipt can confirm native completion through ordinary receipt
observation. Otherwise, a current version-one journal query determines whether a
control can be offered:

- A missing receipt can offer `withdraw` only when the journal is ready and has
  capacity. Withdrawal permanently records that this exact command must not run.
- An unconfirmed receipt can offer `release` only when the journal permits release
  of this exact recovery UUID and command hash. Release acknowledges uncertainty
  and clears its journal barrier; it does not confirm successful native removal,
  roll back files or terminate an independent process.
- Unavailable, conflicting, orphaned or ineligible evidence offers no control.
  A foreign release UUID cannot clear the device barrier. An already-owned release
  observed after a lost reply requires explicit reconciliation.

Each eligible review retains the current identity and inventory binding hash,
receipt evidence, journal revision, kind, sequence, actor and a new review revision.
It lasts at most two minutes, bounded by the current certificate. The resolution
UUID is independent of the recovery, original uninstall and original release.
After an attempt exists, later reviews keep the same resolution UUID and advance
its sequence. A release attempt cannot later be changed into withdrawal.

## One reviewed control at a time

`ResolveRecovery` consumes an exact retained review under current software
permissions. It repeats the current receipt/journal inspection and compares the
complete snapshot. Changed authority, receipt, journal, revision, scope or expiry
prevents delivery. The resolution intent, exact control and audit commit before
transport. No database transaction spans the mutating control request.

Withdrawal uses version two and includes the recovery console revision and
operation. Release uses version one and binds the exact recovery UUID and command
hash; its response also must match the recovery revision and operation. An
original-uninstall receipt cannot be substituted for recovery evidence.

A consumed review only reads retained history, even while its first control is
pending or after a lost reply. It never sends a second control. Another attempt
requires another explicit current review. A new review may change an undelivered
withdrawal into release if the command was received in the meantime, while keeping
the same resolution UUID and advancing the sequence.

Only an exact owned control result can create a release proof and mark the recovery
released. Cancellation remains unavailable after native admission. First native
results and control results remain immutable. A late native result can be retained
without changing an already confirmed release into completion.

## Reconciliation and independent history

`ReconcileRecoveryResolution` sends only a current-identity version-two receipt
query. Exact withdrawal or release evidence must name the owned resolution and
have an earlier retained control of the corresponding kind. Missing receipts,
foreign release IDs, evidence predating the control and proof with no matching
owned attempt leave the barrier intact. An exact completed receipt still follows
the separate completion path when the request is unresolved.

Reconciliation can confirm a lost release or withdrawal response without another
mutating control. A terminal resolution is read without another query. History
retains the original recovery delivery outcome, each reviewed control and its
result, the confirming actor and timestamp. `ReadRecoveryResolution` requires
`ReadSoftware` in the exact historical site. Public records contain no current
certificate, broker binding, executable envelope or private native paths.

After a recovery is explicitly released, another independently reviewed recovery
may still refer to the same **original uninstall**. It has a new request UUID and
fresh current journal/native review. The previous recovery is not reinterpreted
as an original uninstall, and no existing native command is redelivered.

## Database protections and tests

Migration 035 adds immutable recovery reviews, resolution intents, controls,
control results and release proofs. Eleven additional startup guards protect their
shape, identity, scope, sequence, actor, time and correlation, and require exact
retained proof for release. Terminal cancellation, completion and release are
disjoint and immutable. The common five-family barrier frees the device only on
one of those terminal decisions, while every request UUID remains reserved.

Owned PostgreSQL fixtures cover committed intent/audit before transport, exact
review replay, lost replies, certificate renewal, new reviewed attempts, changed
or expired authority/evidence, unavailable/foreign/orphaned proofs, independent
SQL payload and startup guards, original-uninstall substitution, concurrent review
consumption and late native results. They also verify a new recovery against a
fresh journal review after release, preserving the original uninstall's outcome
and release. Tests execute no vendor remover or host NetBird mutation. The full
NetBird inventory suite, with 188 top-level tests plus subcases, passes with race
detection against the owned PostgreSQL database. The Linux console build passes.

Joined dispatch, coherent public history/UI, missing or empty manifest policies
and physical installation/removal acceptance remain separate work. No recovery
route or automatic processing is enabled by these stores.

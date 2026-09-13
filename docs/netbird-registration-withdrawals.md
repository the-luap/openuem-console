# Permanent withdrawal of an unattempted NetBird registration

An agent's missing receipt does not prove that a delayed command cannot still
arrive. Registration resolution now offers an explicit withdrawal when the
current agent confirms support for control version two and reports a ready
journal with capacity. Review remains read-only. The confirmation describes the
permanent denial and preserves the original console outcome as `unconfirmed`.

## Ordering and proof

The initial receipt query uses the existing version-one protocol. A missing
result triggers a separately correlated version-two receipt query carrying the
original revision and operation as well as the original command UUID/digest.
An older response, timeout or unsupported control does not establish capability.
A live registration-state query checks current readiness and binds the review
to the journal generation. Current scope, certificate and consumer checks apply.

After explicit confirmation, the console independently stores resolution intent.
It confirms removal of the exact retained provider key using the original
encrypted provider origin/token. Only then does it independently commit the
withdrawal control and audit before sending one bounded request. The control
uses the retained resolution UUID and expires within ten seconds and the current
certificate lifetime. A fresh review is required to continue an unattempted step.

The agent serializes withdrawal with execution admission. It refuses withdrawal
if the original UUID has any execution attempt, if other execution is pending,
or if storage, clock or current identity cannot authorize the action. Otherwise
it publishes and syncs a permanent withdrawal in the same contiguous sequence
as execution attempts before returning proof. Subsequent delivery of the same
UUID is denied even after restart; conflicting command data also remains denied.
The record contains only bounded receipt metadata, resolution UUID, time, boot
evidence and sequence index. It contains no setup key or provider token.

The console accepts only correlated `withdrawn` evidence with the original
device, revision, operation, complete command digest and exact resolution UUID.
Migration `017_netbird_registration_withdrawals.sql` extends the existing guarded
intent/control/proof storage for that version-two envelope. Final proof, release
metadata and release audit commit together. Original outcomes and original request
identities stay immutable; the existing registration and connection barriers open
only after that commit.

## Lost replies and execution races

Replaying the initial form returns its retained intent without resending a
mutation. **Check retained evidence** queries version-two evidence under current
identity, including after certificate renewal. It can recover a lost withdrawal
reply or a final audit rollback without sending another withdrawal. A missing
receipt remains insufficient to confirm resolution.

If execution starts before withdrawal obtains the journal mutex, withdrawal
conflicts and cannot rewrite that execution. A matching later completed receipt
can be acknowledged with key absence, retaining the original uncertain outcome.
An uncertain attempt that wins the race can now receive an explicitly reviewed
[release recovery attempt](netbird-resolution-retries.md) after execution ends.
The same recovery flow covers an undelivered release or withdrawal, preserving
the original resolution UUID. Nothing is retried automatically. Unknown provider
key identity, unavailable storage, unsupported agents and lost removal requests
still need separate recovery work.

## Validation and scope

Shared codec tests preserve version-one encoding/digests and reject ambiguous
versions, missing metadata and foreign proof. Fuzz checks exercise both control
decoding and withdrawal responses. Agent race/filesystem tests cover concurrent
admission, permanent replay, expiry, cancellation, full storage, clock rollback,
publication failure, certificate renewal and missing/corrupt sequence records.
Owned broker tests discard a withdrawal response, deliver the registration late,
reopen the executor and verify zero execution callbacks.

Owned PostgreSQL/TLS tests cover provider absence before withdrawal, current
individual identity, loss of either request or reply, immutable audit ordering,
late completed/unconfirmed execution and read-only proof recovery. Actual console
routes test the reviewed form and separate outcome metadata. Twelve additional
responsive browser cases cover permanent-withdrawal wording, confirmation,
pending proof and unsupported agents; all 117 registration cases and all 2,313
cases in the full browser matrix pass. The complete inventory PostgreSQL race
suite passes in 200.398 seconds. Agent race suites pass on Linux and macOS,
worker models/common pass with owned PostgreSQL on Linux, and agent builds for
Linux/macOS/Windows plus console/worker Linux and worker Windows builds pass.

The agent protocol can represent connection-command withdrawals, but the console
connection-resolution flow has not adopted this recovery path yet. Provider peer
ownership, trusted installers and physical endpoint/provider acceptance remain
separate work. These tests use owned fixtures and never invoke an installed
NetBird executable or a live provider.

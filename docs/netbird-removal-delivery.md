# Native NetBird removal delivery and receipt recovery

The console inventory layer now connects an exact [reviewed removal request](netbird-removal-requests.md)
to one durable native attempt, direct delivery and retained result. The dedicated
publisher accepts only the version-four removal grammar. Existing connection and
installation publishers continue to reject it. [Reviewed resolution](netbird-removal-resolutions.md)
now provides explicit withdrawal/release and read-only lost-control reconciliation.
Public routes, a joined dispatcher and the resolution UI remain separate work.

## Fresh native admission

`NewNetbirdRemovalDeliveryStore` configures a distinct removal executor.
`Uninstall` requires current exact-site software-assignment authority, the original
request actor and review revision. It acquires the shared device lock and request
row, returning a previously admitted delivery before any new native inspection.
An expired, cancelled or completed request cannot start new work.

A fresh attempt repeats native inspection and requires the original complete
descriptor, descriptor digest, review fingerprint and journal revision. Current
recipient, certificate, consumer and software rights remain locked through the
attempt and audit commit. Positive absence, a new package/process state, changed
identity or journal does not authorize removal of a different state.

The command contains the exact retained native descriptor and original UUID and
review revision, with a fresh ten-minute command lifetime bounded by the current
certificate. Request admission lifetime and native execution lifetime are distinct.
An immutable attempt records wire version, certificate hash, complete command hash
and command times. No download, preparation RPC or provider credential is involved.
Database validation requires an eligible original request, fresh times and the
current matching individual recipient.

Attempt and audit commit before the direct broker call. No database transaction
spans native execution. The publisher uses one ordinary NATS request with the
original command deadline; it uses no stream queue or retry. The result must match
the entire command. Replaying a delivery while its result is missing returns
`pending` and never sends another native command.

## Original result and exclusion

The first result is immutable. A matching completed receipt records completion;
error, cancellation, no reply, mismatched receipt or any other valid agent status
retains `unconfirmed`. Invalid replies are not retained as evidence. A bounded
recording context survives caller cancellation. Failed result persistence leaves
the durable attempt pending rather than granting redelivery.

Native attempt admission permanently excludes queued cancellation, in both Go
and database guards. The common connection/registration/installation/removal
barrier remains closed for pending or uncertain attempts. Only retained completed
evidence or separately reviewed exact journal resolution opens it. A direct timestamp update cannot manufacture
completion; it must match a validated result or original-receipt observation.
Original UUIDs remain permanently reserved after completion.

## Read-only original-receipt recovery

`ObserveRemoval` authenticates the current individual recipient and scoped
software authority, then sends a version-two original-receipt query. It binds
original UUID, revision, command hash and `uninstall` operation. Certificate renewal
is allowed; the original installed state need not still exist. This path does not
perform another native package inspection, deinstallation, withdrawal or release.

The exact control and validated response, or unavailable response, are retained
as append-only observations. Only a matching original completed receipt confirms
the request. Current package absence by itself cannot rewrite an uncertain
execution result or open its barrier. Missing, unconfirmed, foreign and inaccessible
receipts remain unresolved.

Delivery reads preserve `OriginalOutcome` independently of later completion,
alongside the correlated receipt and latest observation metadata. A successful
observation can recover a lost completed reply even when first-result persistence
failed. The original missing/uncertain result remains visible. Reads use original
scope and software-read rights and do not query an agent.

## Verification and remaining integration

Owned PostgreSQL tests cover immutable attempt/audit-before-send ordering, exact
state and command bytes, fresh command lifetime, cancellation exclusion, successful
barrier opening, changed native state/journal/recipient/authority, audit rollback,
all uncertain receipt statuses, lost replies, cancellation and failed result
persistence. Concurrent delivery returns pending while the first caller owns the
single RPC. Original-receipt recovery uses a renewed certificate, preserves first
outcomes, rejects mismatched operations/hashes and refuses absence-only evidence.

Owned NATS tests verify one direct version-four delivery, preserved correlated
statuses, deadlines, cancellation, rejected cross-version/expired commands and no
stream messages. They retain separation from connection/installation publishers
and strict native-inspection transport tests. The complete NetBird inventory race
suite and Linux ARM64 console build cover the integrated change. No real vendor
package, provider or enrolled endpoint is mutated by these fixtures.

Explicit reviewed withdrawal/release and lost-control reconciliation are now
implemented. Bounded joined dispatch, coherent history/status UI and retained
local staging recovery remain required. The [native agent owner](https://github.com/the-luap/openuem-agent/blob/aa1262dd95fa086649d7bc3bdee8beb08b0e13ad/docs/netbird-removal-execution.md)
already handles protected removal and repeated native absence verification.
Physical package, interruption, reboot and desktop acceptance remains separate.

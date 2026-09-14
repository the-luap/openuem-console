# Reviewed native NetBird removal requests

The inventory layer now retains source-free removal intent independently of
connection commands, provider-peer deletion and approved installation packages.
`NetbirdRemovalStore` provides exact-site review, immutable request admission,
historical reads and explicit queued cancellation. A [joined dispatcher](netbird-removal-dispatch.md)
now processes committed requests asynchronously; the [scoped UI](netbird-removal-ui.md)
provides exact review, confirmation and retained status/history.
The separate [delivery owner](netbird-removal-delivery.md) now rechecks this intent,
commits one native attempt and retains original results and receipt observations.

## Current native review

Review and submission require current `software.assign` authority for an explicit
tenant and site. The target must have one matching site, a supported reported
platform, a current individual identity and an active, synchronized command
consumer. Periodic NetBird inventory can be missing; it cannot prove installed
package ownership or absence.

The store issues one fresh version-three `removal-state` control bound to the
individual certificate, exact device and scope. Native inspection gets its own
30-second protocol window bounded by the parent and certificate expiry. A response
must match the complete request and supply a ready journal with either the exact
native descriptor or positive absence. Unsupported, stale, malformed, inaccessible
or mismatched evidence prevents admission. Positive absence is displayed as
read-only evidence and cannot create a removal request.

The review fingerprint binds descriptor digest, native platform/architecture,
device binding generation, broker identity, consumer revision, certificate and
expiry, scope and journal revision. Submission repeats native inspection and
requires that fingerprint and descriptor unchanged. Transaction locks retain
current permissions, recipient and report binding through audit and commit.

## Permanent requests and common exclusion

Requests retain the original UUID, actor and exact site, the shared native
descriptor and its digest, the reviewed revision and journal revision, and a
ten-minute lifetime bounded by certificate expiry. Descriptors contain no package
URL, arbitrary executable/path, installer arguments or provider credentials.
The schema accepts only the strict source-free descriptor shape, and reads
revalidate its canonical shared digest.

Exact request replay checks current permissions but returns the original record
without contacting the agent. It does not require the current installation,
certificate or device inventory still to match historical state. Changed actor,
scope, device, descriptor digest or review revision under the same UUID conflicts.

All six request families, including [manifest recovery](netbird-removal-recovery-requests.md)
and [current absence verification](netbird-removal-absence.md),
share UUID and device advisory locks and a common conflict query. A database admission trigger also enforces exclusion for direct
inserts. Pending removal excludes connection, registration, installation and
manifest recovery and absence verification; their unresolved requests exclude removal. Cancellation releases the device slot
but never makes its original UUID reusable in another family. Expiry alone does
not release a pending request.

Request metadata and cancellation are immutable, deletion is prohibited and
history has no device foreign key that would erase original evidence. Read-only
history requires `software.read` in the original exact scope. Cancellation needs
`software.assign`, the original review revision and its own permanent UUID.
Once a native attempt exists, cancellation is permanently excluded. Only verified
completion or a separately reviewed exact journal resolution can open that
attempt's barrier.
Exact cancellation replay preserves the first actor and timestamp. Audit failure
rolls back request or cancellation atomically.

## Verification and remaining work

Owned PostgreSQL tests cover scoped software roles, native present/absent/error
responses, certificate and request correlation, changed version/state/journal,
recipient revocation/expiry, native architecture, reported platform, moved site,
device binding and revoked permission. They verify source-free history, exact
replay after identity changes, malformed/source-bearing SQL descriptors, immutable
records, cross-family exclusion and UUID retention, concurrent same/different-ID
admission, joined permission/identity locks and audit rollback.

The complete NetBird inventory race suite and Linux ARM64 console build cover
the shared admission change. Fixtures do not contact a vendor, deliver native
commands or mutate an enrolled endpoint.

Separate native attempts/results, direct delivery and original-receipt observation
and [reviewed uncertain-operation recovery](netbird-removal-resolutions.md) are
implemented. [Joined dispatch](netbird-removal-dispatch.md) now consumes committed
requests once. [Bounded history pages and public UI](netbird-removal-ui.md) now
connect these lifecycles. Retained local staging recovery now has separate
[reviewed request storage](netbird-removal-recovery-requests.md); its native delivery
and public lifecycle remain to be connected.
The already implemented
[agent owner](https://github.com/the-luap/openuem-agent/blob/aa1262dd95fa086649d7bc3bdee8beb08b0e13ad/docs/netbird-removal-execution.md)
provides exact native execution and repeated absence checks. Physical package,
interruption, reboot and desktop acceptance remains separate from owned fixtures.

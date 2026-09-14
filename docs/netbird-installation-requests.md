# Durable NetBird installation requests

`inventory.NetbirdInstallationStore` now provides reviewed, immutable installation
requests, scoped history reads and explicit cancellation before delivery. It
connects organization package approval storage to a particular individually
enrolled Unix device. This is a backend component; construction enables no route,
dispatcher or native installer. The optional [preparation constructor](netbird-console-preparation.md)
now admits one separately requested, authenticated download/inspection RPC.

## Current authority and exact source

Review, request and cancellation require current `software.assign` for the exact
organization/site. Organization and site operators can assign an approved package,
matching the existing software model. Creating or revoking the approval still
requires organization `software.manage`. History requires `software.read`.
Each transaction retains authorization locks through its atomic audit.

The source requires individual mode to be enabled, one active individual identity
in the exact scope, a current
certificate and an active command consumer whose completed revision matches its
desired revision. Enrollment platform/architecture, reported platform and approved
package target must agree. Device membership, identity, consumer and generation
locks remain held until the transaction ends. The NetBird inventory row is optional:
an absent client can be a target. No provider URL, token or peer registration is
needed. A fresh bounded journal query must return `ready`; this is exclusion
evidence and does not establish native installer capability.

An internal loader locks the approval before reading revocation in a separate
statement. It decrypts the source envelope, applies the strict descriptor codec,
requires canonical bytes and verifies the complete digest and every public
metadata field against the authenticated descriptor. A wrong key, corrupt or
swapped envelope, changed metadata, foreign approval or permanent revocation
prevents admission. Public review/history objects contain no source URL or
encrypted descriptor. Approval replays also read revocation after acquiring their
row lock, so a waiting replay cannot return stale revocation metadata.
Site-level reviews expose only the artifact identity, target/version, size and
digests; they do not expose the organization's approval actor or verification
reference. Organization-wide approval history keeps its existing separate rights.

The review fingerprint binds approval/digest, exact device/scope, generation,
certificate and expiry, broker key, command-consumer revision, native target and
live journal revision. Request creation recomputes it under current authority.
The request deadline is at most ten minutes and cannot exceed certificate expiry.

## Permanent requests and shared exclusion

Migration `024_netbird_installations.sql` adds permanent request records with
approval references and public fingerprints. It stores no executable command or
new plaintext source copy. Exact UUID replay requires the original actor,
device/scope, approval/digest and review revision and returns the original record
without another journal query or action. Current assignment permission is still
required. Replaying a cancelled request cannot reactivate it after revocation.

Installation, connection and registration share the existing advisory device
lock and permanent request UUID namespace. Go admission and database triggers
enforce exclusion across all three families. Outstanding installations block the
other families; completed/cancelled historical UUIDs remain reserved. A unique
index also prevents two active installations for one device. The revocation insert
guard locks the approval for update, including direct SQL insertions, to serialize
against admission's shared lock. Startup verifies the added protections.

Cancellation retains its own UUID, actor and timestamp and releases the
pre-delivery barrier. Exact replay succeeds; a changed cancellation identity or
actor conflicts. Request identity and cancellation evidence cannot be rewritten
or deleted. Request/read/cancellation events use the existing NetBird audit source
without private package data. Audit failure rolls back the request or cancellation.
Historical reads and pre-delivery cancellation remain possible after device
deletion or disabling individual mode; old registry rows cannot admit new requests
while the server uses shared credentials.

## Integration boundary

A queued request is retained intent. The optional
[preparation component](netbird-console-preparation.md) verifies both native
capabilities and retains one exact attempt before its direct RPC. The
[native delivery component](netbird-installation-delivery.md) now rechecks current
approval and target authority, reconstructs the complete live preparation, then
commits one exact command attempt before installation delivery. Neither download
nor native execution holds a database transaction.

Cancellation remains available before native delivery, including while preparation
is in flight. Any native command attempt excludes cancellation, even if a direct
SQL cancellation was already waiting. Only retained completed receipt evidence
opens the shared device barrier; completed UUIDs remain reserved. Read-only
observations can recover completion after lost replies and certificate renewal
without redelivery or rewriting the original result. Uncertain/missing receipts
use [explicit reviewed withdrawal/release](netbird-installation-resolutions.md);
expiry never silently erases
the barrier. Automatic dispatch, lifecycle UI and local removal remain open.

The current individual enrollment validator and registry accept Windows/macOS,
not Linux. Tests enroll macOS through the real owned registry fixture. Linux also
needs individual enrollment and independent publisher provenance. Shared legacy
credentials cannot substitute. Windows retains its existing software workflow.

## Verification

Owned PostgreSQL fixtures cover an absent client, scoped operators/viewers,
encrypted source and public metadata integrity, changed identities/consumers,
revocation, replay/cancellation, shared barriers, audit rollback, concurrent
requests, deadline bounds and history retention. Concurrent tests prove that both
installation requests and approval replays observe revocation committed while
waiting for the approval lock. Permission, recipient and revocation changes wait
for admission's transaction. No provider, package download, agent command or
native installer is executed by these tests.

The complete inventory race suite passes in 295.726 seconds and the complete audit
race suite in 9.821 seconds. Final focused installation/package tests pass in
18.031 seconds, including disabled individual mode and scoped metadata privacy.
The registered console route fixture with PostgreSQL and the full Linux ARM64
console build also pass. No views or browser assets change in this component.

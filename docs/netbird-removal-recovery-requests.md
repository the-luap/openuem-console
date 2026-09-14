# Reviewed NetBird removal recovery requests

`NetbirdRemovalRecoveryStore` persists a separate continuation request for an
interrupted macOS uninstall with a valid original manifest. Migration 033 adds
its immutable request and cancellation records, original-release foreign key,
history index and common admission guards. The store provides review, request,
scoped read and explicit cancellation. The delivery-enabled constructor adds
[one durable native attempt and retained receipt observation](netbird-removal-recovery-delivery.md).
[Reviewed release/withdrawal resolution](netbird-removal-recovery-resolutions.md)
also retains separate proof. Joined dispatch and public UI integration remain open.

## Original owned evidence

Every review starts with the exact original uninstall in the requested device,
organization and site. It must have a confirmed release and cannot be cancelled
or completed. Release status alone is insufficient: an undelivered command may
have been permanently withdrawn instead.

The store reconstructs the original version-four command from its immutable
request descriptor and minimal attempt metadata: historical certificate hash,
wire version, issue time and expiry. Its canonical command digest must equal the
retained hash. This does not require the old certificate to remain current.

The exact release-proof record must agree with the original request's resolution
UUID, releasing actor and timestamp. The store decodes and correlates the retained
control and response, including its request hash, original uninstall receipt and
release UUID. Only an unconfirmed receipt with an earlier owned `release` attempt
is eligible. Both a directly confirmed release response and a later read-only
receipt reconciliation are supported. Withdrawn, completed, missing, unreleased
and corrupted original evidence cannot reach the native inspector.

## Current authority and native review

Review and request require `AssignSoftware` in an exact organization/site scope.
Current device membership, active individual consumer, current certificate and
expiry, broker binding, platform, architecture and inventory generation are held
under the existing permission and inventory locks. Recovery currently requires
macOS and the same architecture as the original descriptor.

A version-four `removal-recovery-state` control requests current evidence for the
exact original reference. Its deadline is bounded by 45 seconds, the current
certificate and its caller. Only an exact correlated `ok` response with a ready
journal and valid `manifest` recovery descriptor is accepted. Private identity
and broker values contribute to the console review hash without entering public
records. The recovery digest separately binds the complete source-free recovery
descriptor, including the original release and current journal/native hashes.

The current console review revision differs from the recovery descriptor's
explicit journal revision. A request repeats native inspection and all current
authority checks before comparing the reviewed digest and revision.

## Permanent admission and cancellation

Requests use a new UUID distinct from the original uninstall and release. They
retain exact device/site/actor, original request, reviewed recovery descriptor,
both digests, current journal revision and an expiry of at most ten minutes,
bounded by the current certificate. Exact request replay reads the retained row
under current software authority without probing or executing the agent. Changed
actor, original reference, scope or reviewed values cannot reuse the UUID.

The existing UUID and device advisory locks now include recovery as a fifth
family alongside connection, registration, installation and fresh removal. The
database admission trigger protects direct inserts in every family as well.
An unresolved recovery blocks other work; its UUID remains reserved after
cancellation, verified completion or confirmed owned resolution. Expiry alone
does not release the device barrier.

Database guards require an exact original released unconfirmed receipt and an
exact source-free `manifest` descriptor. Unknown fields, replacement descriptors,
alternate modes, mismatched references/revisions, pre-cancelled rows and reuse of
an original UUID are rejected. Request intent and terminal cancellation are
immutable, and startup refuses missing or disabled guards.

Scoped reads require `ReadSoftware`. Cancellation requires `AssignSoftware` and
an exact request revision, and retains a separate cancellation UUID and actor.
Repeated cancellation is idempotent only with that same identity. It sends no
native control, never changes the original uninstall and cannot erase request
history. Once a delivery attempt is committed, cancellation is refused by both
the store and database guard, including when no delivery result was saved.
Request/read/cancellation audits commit with their corresponding state; an audit
failure rolls back the operation.

## Verification

Owned PostgreSQL fixtures create original uninstall, control and release evidence
through the existing stores. Tests cover direct and reconciled release proof,
certificate renewal, exact replay and scope, rejected withdrawn originals,
corrupted retained commands/controls/responses, current authority/native changes,
all five request barriers, permanent UUIDs, SQL descriptor/immutability guards,
concurrent requests and audit rollback. A held native inspection verifies that
certificate, membership and permission changes cannot cross request commit.
Tests do not execute a vendor remover or read/change host NetBird state.

The full NetBird inventory suite passes with race detection against an owned
PostgreSQL database, including the existing four families and the new recovery
requests. The Linux console build also passes. Public routes and automatic
delivery are not configured by the request or delivery stores.

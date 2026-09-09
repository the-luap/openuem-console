# Retained Apple profile revisions

Every newly saved System or User profile now has a separately encrypted,
immutable revision record. The current catalog entry references the exact
organization, profile, revision number, root payload UUID and snapshot identifier.
Revision history provides the durable profile identity needed for subsequent ADE
profile prerequisites and makes earlier configurations reviewable and restorable.

## Storage and migration

Migration 029 captures the currently available payload of each existing profile.
It records that origin explicitly and leaves its author unknown. It does not
invent versions that were overwritten before revision history existed. The
original profile-bound encryption envelope is retained for those migrated rows.
New snapshots use a separate encryption purpose bound to the organization and
revision UUID, so another revision's ciphertext cannot be substituted.

Stored root UUID, profile identifier and scope must match the decoded payload.
An omitted scope in a legacy payload retains the System default. Database
constraints reject updates and deletion of snapshots, duplicate revision/root
identities, mismatched current-version references and restoration references to
another profile family or organization.

Deleting an unused catalog entry preserves its revision history and protected
payloads. The console explains this retention before deletion. Historical
credentials embedded in a profile therefore remain accessible to authorized
profile managers. A deleted entry cannot be silently recreated by restoration.
General retention and encryption-key rotation remain separate operational work.

## Review, download and restore

**Apple profiles → All profile revision history** includes active and deleted
catalog entries. Each current profile also links to its own history. Pages show
at most 100 revisions, ordered by recording time and identifier. A cursor is
bound to the selected organization and optional profile family.

Ordinary profile readers see metadata, origin and restoration reasons. Payloads
and embedded credentials are absent from the history model and HTML. Complete
historical downloads require organization profile-management permission and an
audited request. History and download responses use `no-store`.

Restoration requires organization-wide profile management and assignment
authority checked inside the transaction. The operator selects an earlier
revision, supplies a 1–1000-character reason and confirms redeployment to all
current assignments in the organization. CSRF protection and strict form parsing
reject missing confirmation, duplicate fields and query-supplied mutation input.
The expected current revision prevents an older browser page from overwriting a
concurrent edit or restoration.

Restoring creates the next revision with a fresh root payload UUID; it never
changes the source snapshot. The new record retains its source revision, actor,
reason and recording time. Current validation rules are reapplied. Snapshot,
catalog change, active device/user assignment commands and audit commit together.
If an assignment is no longer supported or the audit fails, the entire change
rolls back. Paused users keep their prior state and receive the current revision
through the normal resume workflow.

A restored profile remains pending until its new UUID is reported installed.
Reporting the earlier revision's UUID does not verify restoration. For Platform
SSO, successful profile verification still does not establish provider
registration, credential synchronization or successful sign-in. Review old
provider tokens and other credentials before restoring them.

## Validation and remaining integration

Local PostgreSQL checks apply all 29 actual migrations in an isolated transaction
and prepare 190 production application, ADE and profile SQL statements. An
additional execution fixture covers migration of an existing profile, immutable
history, the current-version foreign key and retention after catalog deletion.
The isolated schemas are rolled back after those checks.

Native tests cover encryption binding, metadata privacy, exact historical
downloads, deletion retention, restoration provenance, stale/concurrent writes,
audit rollback, current SSO compatibility, fresh UUID observations, legacy
migration, 102-revision pagination and active/paused Mac user channels. Console
tests exercise organization/scoped roles, protected downloads, strict forms,
CSRF, source-family binding, stale requests and retained deleted history.

Eighteen browser scenarios use the actual rendered history pages at widths 390,
768 and 1440 pixels. Earlier/current, deleted, migrated, reader and empty states
pass keyboard interaction, required confirmation, current-revision/CSRF form
values, unavailable-action checks and horizontal-overflow checks. These use the
rendered history fixtures from `28f29d2`. Three additional catalog scenarios at
the same widths use `bee0145` and verify the retention notice, deletion label,
history link and absence of horizontal overflow; those commits share the same
history templates and assets.

At [`bee0145`](https://github.com/the-luap/openuem-console/commit/bee0145bd16bce6c071c15ef12d8b85cb7bf4315),
both complete workflows passed all four jobs in
[push CI](https://github.com/the-luap/openuem-console/actions/runs/34333437834) and
[PR CI](https://github.com/the-luap/openuem-console/actions/runs/34333442616).
This covers Linux/Windows builds, native Windows checks, console rendering and
authorization, the native Apple race suite, gateway/security regressions,
existing model tests and desktop agent regression. The native Apple suites
completed in 488.507 and 534.643 seconds, respectively.

No profile is deployed to a real device by these tests. Immutable ADE SSO profile
requirements, ownership of pinned assignments and reviewed corrections are now
implemented; their validation is recorded in
[Platform SSO profiles](apple-platform-sso.md). Cross-profile routing reservations
now retain potentially installed revisions until fresh replacement or removal
verification; both complete integration workflows pass at `ccbde13`.
Provider-specific registration acceptance remains open. Verification against
an assigned historical snapshot is recorded separately below. This revision
foundation does not complete the full roadmap.

## Assigned revision observations

Device and user profile verification now resolves the assignment's retained
revision instead of the latest catalog row. A missing legacy snapshot cannot be
replaced by the current catalog identity. Device queries created before the most
recent assignment acknowledgement cannot verify installation or removal, even
if their delayed response happens to match the desired state. Assignment changes,
acknowledgements and new command creation use the database wall clock after locks
are acquired, preserving that ordering across transactions that waited for a lock.

Migration 030 also retains the creation time of the query behind each accepted
device/user profile inventory. An older or equally timed query cannot replace
that inventory, change its displayed receipt time or reverse a newer verification.
Its authenticated command response still completes normally. Existing inventory
has no reliable historical query provenance; the next accepted query establishes
this boundary without inventing an earlier timestamp.

UUID comparisons accept case differences. Mac user responses do not need an
`IsManaged` value: Apple's
[ProfileList schema](https://github.com/apple/device-management/blob/release/mdm/commands/profile.list.yaml)
marks that response key as unavailable on macOS. The acknowledged assignment and
subsequent exact UUID observation remain required.

The local SQL check now prepares 250 production statements, including device and
user command paths, against all 30 actual migrations. An execution fixture uses
the actual System/User verification queries to check older retained assignments,
pre-acknowledgement reports, foreign organizations and missing history. New
native protocol tests
exercise retained System/User versions, stale installation/removal observations,
missing snapshots, database timestamp ordering and omitted Mac `IsManaged`.
The execution fixture also runs both actual inventory updates with initial,
newer, equal and older query times. Protocol tests complete a delayed query after
a newer accepted report and check that inventory, receipt time and assignment
verification remain unchanged.
Nine browser scenarios use the actual `913fbaa` renderings at 390, 768 and 1440
pixels: managed, reader and paused user pages preserve inventory identity,
appropriate actions and the updated verification explanation without an
unsupported management warning or horizontal overflow.

Assigned-revision verification at `9d17f4b` passes all four jobs in both
[push CI](https://github.com/the-luap/openuem-console/actions/runs/34334705967) and
[PR CI](https://github.com/the-luap/openuem-console/actions/runs/34334711904).
The Mac console follow-up at `913fbaa` also passes the complete
[push workflow](https://github.com/the-luap/openuem-console/actions/runs/34335156853),
including the 443.070-second native Apple race suite.

The additional inventory-ordering change at `08029fd` passes the local migration,
preparation and actual SQL execution checks above. Both complete workflows pass
all four jobs in
[push CI](https://github.com/the-luap/openuem-console/actions/runs/34336312494) and
[PR CI](https://github.com/the-luap/openuem-console/actions/runs/34336316609),
including the extended native protocol tests for late query completion.

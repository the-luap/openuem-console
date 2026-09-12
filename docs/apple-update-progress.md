# Current progress for an original Apple update cohort

Open an [original group update assignment](apple-update-groups.md) and select
**Current cohort progress**. An activated [schedule](apple-update-schedules.md)
links to that same original receipt. The assessment retains the receipt's exact
native enrollment IDs and original plan definition. Current group membership,
plan edits and archival cannot change the assessed cohort.

Independent sets of counts distinguish reported OS results, configured policy
and [estimated deadline timing](apple-update-deadlines.md). A device can report
the target OS while its policy has since been replaced or removed. An acknowledged declarative-management notification does
not establish installation, and the report does not attribute an OS change to
this particular assignment.

An original assignment also offers [reviewed removal of matching policies](apple-update-group-removals.md).
Its immutable removal receipts are separate from this current assessment. Later
policy removal or replacement leaves the original OS target and cohort intact.

## OS observations and result criteria

Migration 047 adds a bounded current OS-observation row per native enrollment.
Authenticated Device Information and declarative-status ingestion update it in
their existing exclusive device transactions. This separate projection does not
borrow a build from merged inventory or refresh an OS timestamp from unrelated
incremental status. Legacy merged inventory is not backfilled as a new observation.

- A valid version report records its numeric version, source and database time.
  Its build is retained only when a valid build accompanies that version in the
  same packet. A version-only report therefore has no verified accompanying build.
- A build-only delta clears the previous build evidence without changing the old
  version or its timestamp. It cannot establish a new version/build association.
- An explicitly invalidated or malformed version, missing OS version in a full
  declarative report, removed OS status parent or any declarative status error
  clears the current observation. A later valid error-free OS report restores it.
- Device Information or status processing failures roll back this projection
  together with the original protocol transaction.

The current cohort assessment counts **Target or newer OS reported** only when
the original enrollment is active with an unexpired identity, the observation was
recorded after admission and within the last 24 hours, and its numeric OS version
exceeds the target or matches the exact target version and build. A lower version
or a different reported build at the target version remains **Update still
required**. Missing, pre-admission, stale, future-dated, malformed or incomplete
evidence is **Result unverified**, with a fixed explanation.

The [individual device assessment](apple-update-assessment.md) shares these
freshness and version/build association rules. This cohort view additionally
requires post-admission packet evidence for the original assignment's target.
It is an assessment of current device-reported evidence, not independent hardware
acceptance or a causal proof that this assignment installed the update.

## Current policy and original delivery evidence

Each available original enrollment is compared with the original plan's configured
version, build, device-local deadline and information URL. The result distinguishes
matching values, a different policy and no policy. Matching values do not prove
continuous ownership by this assignment; a policy may have been changed away and
back. Current failure/unavailability flags are shown separately from OS outcomes.
Bounded, escaped protocol error details remain on the scoped device page.

The original declarative notification's current queue status is read through its
saved command ID, exact device/organization and request type. Missing notification
history is unavailable evidence, not an installation success. The view never
queues a retry, changes policy or sends a device refresh. **Refresh this
assessment** performs another audited server-side read.

## Scope, consistency and bounds

`GET /ios/update-plans/:plan/group-assignments/:assignment/progress` requires
current `ManageUpdates` and `ReadDevices` authority in the exact original site.
The transaction authenticates the immutable encrypted receipt, locks current
authority/site, and acquires shared device and policy locks in the receipt's
canonical native-ID order. It assesses every original target, up to the existing
100-device admission bound, under a ten-second context. A database or audit failure
withholds the entire response.

A device that moved out of the original site remains an unavailable original ID;
its current name, OS observation, policy and device navigation are withheld.
Inactive enrollments and expired identities cannot contribute a verified OS result.
Large names are omitted, configured policy text is bounded before decoding, and
raw inventory/status/error documents are not loaded. Public JSON/XML/YAML
serialization and ordinary formatting omit protected progress contents. Responses
prohibit caching. Unknown query fields are rejected.

The assessment timestamp and counts describe current state under the held locks.
They are not persisted historical outcome snapshots. OS and policy counters are
independent; attention and availability counters can overlap configuration counts.
Deadline estimates require a valid, fresh reported device time zone. Unknown
zones remain unverified. The original target still required after the estimated
deadline count also requires an OS report at or after the latest possible
deadline instant; pre-deadline evidence cannot establish that result.

## Validation and remaining work

Owned PostgreSQL 17/race tests exercise authenticated Device Information and
declarative status, partial/full/invalid/error reports, protocol rollback, an
acknowledged notification without OS proof, pre-admission and stale/future
observations, higher versions and exact builds, replaced/removed policies,
archived/changed sources, later group members, moved/revoked/expired identities,
bounded policy decoding, current authority and late read-audit failure. The
targeted regression passes in 17.624 seconds; the complete Apple PostgreSQL/race
suite passes in 543.717 seconds. Registered Linux console routes exercise the
actual scoped read and rejection paths with owned observations. macOS/Linux
package race tests, the full Linux build and 111 relevant Chrome cases pass.

Browser coverage includes reported, update-required, incomplete-build,
different/removed policy, unavailable, attention, mixed-cohort and long-metadata
states at 390, 768 and 1440 pixels. The view offers no assignment or scheduling
form. Broader package/build/browser and full Apple regression evidence is recorded
in [implementation status](implementation-status.md).

Persisted historical cohort snapshots, automatic promotion gates, exceptions,
deadline-aware escalation and physical-device acceptance remain separate work.

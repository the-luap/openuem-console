# Native Windows update rings and explicit cohorts

The native Windows backend now stores reusable, versioned update rings and
atomically assigns a reviewed device list to an exact ring revision. Each device
receives the existing [typed update run](native-windows-updates.md), including
platform preflight, Atomic configuration and effective-value read-back. Changing
a ring does not rewrite an admitted run or its evidence.

These APIs do not yet have production console forms or registered HTTP routes.
The [scheduled activation backend](native-windows-update-schedules.md) now handles
reviewed future cohorts. Dynamic groups, production worker registration,
pilot-to-broad promotion gates, automatic reconciliation and end-user restart
communication remain implementation work.
An explicit cohort supports manual pilot selection; it is not an automatic ring
promotion system or proof that Windows patches were installed.

## Revision and assignment behavior

| API | Behavior |
| --- | --- |
| `SaveUpdateRing` | Creates a ring or appends a revision after checking the caller's expected revision |
| `UpdateRings` | Audited site-scoped current revisions, including disabled rings; at most 100 per page |
| `UpdateRingRevisions` | Audited immutable history, newest first; a revision cursor and at most 100 entries |
| `AssignUpdateRing` | Captures 1–100 distinct device UUIDs and creates their update runs in one transaction |
| `UpdateRolloutDetails` | Audited original cohort, exact source revision and per-device run identifiers |
| `UpdateRunDetails` / `UpdateRuns` | Existing protected policy outcomes and command states, with ring/rollout provenance |

A caller supplies a stable ring UUID and a separate request UUID for each edit.
Creation expects revision zero. Subsequent edits must name the revision that was
reviewed; concurrent editors cannot overwrite one another. The name is limited
to 128 UTF-8 bytes, and the existing typed policy ranges/dependencies apply.
Disabling a ring is a new revision with `Enabled=false`; historical revisions
remain available. Revisions are bounded at 1,000,000.

An assignment supplies the ring UUID, exact revision, stable assignment request
UUID, selected device UUIDs, apply/removal mode and a lifetime from one minute
through seven days. Device order is normalized without modifying the caller's
list. Duplicate, malformed or empty targets are rejected. Every target must
still belong to the authorized organization/site and have a non-revoked native
Windows enrollment. Queue capacity and all ordinary typed-run checks apply to
every device. A failure at any target or audit rolls back the entire cohort,
including earlier inserted commands; there is no partially admitted rollout.

A new apply assignment requires the current enabled revision. Removing policy
may refer to a historical revision, including after a ring is disabled. Removal
uses exactly that revision's selected Config nodes and the existing separate
removal verification. Disabling or editing a ring neither cancels existing work
nor removes settings. The existing per-device `CancelUpdateRun` remains available
for undelivered steps and preserves sent/unknown outcome boundaries.

Retries are scoped and exact. An edit retry must match the original expected
revision, name, policy, enabled flag and creator permission revision. An
assignment retry must match its original ring/revision, normalized target set,
mode, lifetime and creator permission revision. It returns the original cohort
even after a later ring edit, disable or completed device exchange. Adding or
removing targets under the same request UUID is a conflict, not new work.

## Authorization and protected provenance

All methods require the existing `updates.manage` capability for the selected
site. Console session authentication remains the caller's responsibility. Reads
commit their audit before returning protected names, policies or cohort details.
Generic JSON/XML serialization and formatters do not expose ring/rollout payloads.
A future UI must escape names and device data and display the reviewed revision.

Ring authorship and assignment authority are distinct. A currently authorized
operator can explicitly select an existing ring revision; that assignment records
its own creator and current permission revision. Device delivery and replay use
the assignment creator's live permission checks. Later permission replacement
cannot revive that creator's old queued authority. A ring edit does not silently
transfer authority to its author or to a background scheduler.

Migration 008 adds a current-revision pointer, immutable encrypted revisions,
immutable encrypted cohort targets and append-only ring/rollout audit. Deferred
foreign keys prevent a committed head without its revision. Foreign keys bind
run provenance to the exact rollout, ring revision, organization/site, creator,
permission revision and mode. Device request UUIDs are derived from the immutable
rollout ID and device ID; each rollout has at most one run per device.

Ring intent encryption binds revision, scope, creator, permission revision,
request UUID, enabled state and creation time. Cohort encryption additionally
binds source revision, mode and lifetime. Each new ring run's encryption purpose
includes its source ring/revision and rollout. Existing direct runs retain their
original encryption purpose and command trees across migration.

Before a ring command is delivered, replayed or read through typed run details,
the server verifies the encrypted source cohort, device membership, derived
request UUID, creator/revision, mode, lifetime and exact original ring policy.
A valid typed policy for another ring or an unreviewed device cannot borrow that
source. The check uses the immutable historical revision, so admitted work can
finish after the ring head changes. Atomic assignment uses scoped request locks
and sorted device locks to handle duplicate and overlapping requests.

## Verification

Synthetic PostgreSQL tests cover concurrent creation and edit conflicts, exact
retries, protected history and current listing, scope/capability checks, immutable
SQL history, source ciphertext reassignment, changed policies and target sets,
audit rollback, missing devices and queue-capacity rollback across multiple
targets. Additional exchanges verify restart/replay and all 13 original policy
settings after the source ring is edited and disabled. The real loopback TLS
suite also delivers the complete ring-bound policy on resumed connections.
Migration tests preserve existing direct-run and custom CSP delivery evidence.

The full PostgreSQL 17/race suite, including concurrent edits and overlapping
cohorts, passes in **73.283 seconds** at **84.4%** package statement coverage. Vet
and formatting checks pass. `FuzzUpdateRingTargets` passes **213,552 executions**
in a 30-second local run; it checks bounded parsing, stable target normalization, protected round-trip
representation and distinct per-device request identities. CI includes that fuzz
target, the Windows persistence/race suite and native Windows portable tests.
Full CI for this ring extension is pending.

Use the [reserved PostgreSQL fixture](native-windows-mdm.md#scoped-enrollment-credentials).
The tests enroll only synthetic identities in isolated schemas, exchange data
with owned loopback servers and never install a policy or certificate on the
host or contact a real managed device.

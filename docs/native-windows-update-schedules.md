# Scheduled native Windows update ring activation

The backend can now schedule an exact [ring revision and device cohort](native-windows-update-rings.md)
for later activation. It stores the reviewed source, targets, creator permission
revision and timing before creating any device commands. A bounded worker
activates due plans through the same atomic cohort assignment used for immediate
rollouts. Concurrent workers and process restarts cannot activate one plan twice.

The [optional Windows listener](native-windows-operations.md) now starts the
worker at server startup and cancels it during shutdown. Console forms, dynamic
group selection and pilot promotion gates remain implementation work. This is scheduled policy
assignment, not evidence of patch installation or an automatic patch rollout gate.

## Timing and operator controls

`ScheduleUpdateRing` takes the site, exact ring revision, stable request UUID,
1–100 distinct native device UUIDs, apply/removal mode, `NotBefore`, an activation
window and a per-device run lifetime. It checks current scope, permissions, ring
eligibility and device enrollment at creation, then repeats the required checks
at activation. It does not reserve device queue slots in advance.

`NotBefore` is an absolute instant, normalized to UTC. Its precision must fit
PostgreSQL microseconds. Creation accepts at most one minute of request delay and
up to 90 days of lead time. The activation window and run lifetime each range
from one minute to seven days in whole seconds. The window must still be open
when schedule creation commits. A site has at most 256 active scheduled/waiting
plans; creation serializes the count so concurrent requests cannot overfill it.

The activation window governs when the server may create the cohort. **It is not
a Windows installation/restart maintenance window or a cutoff for subsequent
device delivery.** Once activated, each device run has its own original lifetime
and existing delivery checks. Offline devices can receive an admitted policy
later within that lifetime. Windows update deadlines, grace periods and restart
behavior remain explicit fields in the selected policy, with actual installation
and restart acceptance still required.

| API | Behavior |
| --- | --- |
| `ScheduleUpdateRing` | Saves immutable source/target/timing intent; exact request retries return the same plan |
| `UpdateScheduleDetails` | Audited original targets, timing, state, reason and activated rollout link |
| `UpdateSchedules` | Audited site history; at most 100 plans per page, offset at most 100,000 |
| `CancelUpdateSchedule` | Requires the reviewed state revision; cancels only scheduled/waiting plans |
| `ProcessDueUpdateSchedules` | Trusted maintenance entry point; processes at most 25 selected due plans per call |

Console methods require `updates.manage` and authenticated session identity from
the caller. Changing the creator's grants, including an identical regrant with a
new permission revision, invalidates old scheduling authority. A new apply
activation also requires the exact current enabled ring revision. Historical
removal remains possible under the same explicit-removal rules as immediate
ring assignments.

A changed window, target set, ring revision, mode, lifetime or creator permission
revision cannot reuse an existing request UUID. Equivalent timezone representations
of the same instant are idempotent. Plans are never silently edited or rearmed;
new intent requires a new request. Canceling an already activated plan cannot
recall device work. Its per-device runs retain their existing cancellation and
sent/unknown outcome boundaries.

## Durable worker outcomes

| State | Meaning |
| --- | --- |
| Scheduled | Reviewed intent exists; no cohort has been activated |
| Waiting | Admission could not complete before a queue/deadline boundary; retry is no earlier than one minute later |
| Activated | Cohort, device runs, schedule state and audits committed together |
| Blocked | Source authority, ring assignment or a target no longer permits activation; a new review is required |
| Canceled | An authorized operator canceled the pending plan |
| Expired | The activation window closed before admission could commit |

Queue capacity failure records `device_queue_full`. Admission lifetime expiry
records `admission_deadline_expired`; neither preserves partially inserted runs.
Blocked reasons distinguish authority changes, scope changes, ring assignment
conflicts and unavailable devices. A terminal state cannot be rewritten into an
active plan. Attempt and state revision counters remain visible in protected
reads, with append-only audit events.

The worker uses database time and acquires permission/scope locks before the
schedule row lock, matching console cancellation. Locked or no-longer-due rows
are skipped. It rechecks the exact creator permission revision and ring/device
prerequisites. A savepoint encloses cohort creation, activation state and their
audits. Queue failures roll back that whole section and persist a waiting state.
Expired windows roll it back and persist expiry, including when the window closes
while either the cohort or schedule audit waits. Unknown storage/crypto failures
return an error and preserve the unactivated plan; other valid records selected
in the same bounded batch can still proceed.

The final admission check uses one database timestamp against the cohort's
latest creation and earliest expiry bounds. No device payload is returned by the
worker. Authenticated device exchanges retain their independent creator,
configuration, source proof, deadline and replay checks.

## Persistence and source proof

Migration 009 adds immutable timing/target intent, authenticated mutable schedule
state and append-only schedule audit. Intent encryption binds scope, source ring
revision, creator/revision, request, mode, run lifetime and all timing fields.
State encryption also binds phase, revision, attempts, backoff, update/completion
times and rollout link. SQL triggers preserve immutable intent and terminal
history; foreign keys bind one activated rollout to its original schedule.

A scheduled rollout gets a deterministic activation request UUID and a separate
schedule binding in its encrypted purpose. Before its device commands can be
delivered, replayed or read, source proof checks the authenticated activated plan,
exact target set and source metadata, and activation within the original window.
Direct assignment retries cannot borrow a scheduled rollout identity. Existing
immediate ring cohorts and direct update runs retain their original encryption
purposes and exact protocol replay across migration.

## Verification

Synthetic PostgreSQL tests cover future/due timing, parallel workers, restart,
exactly-once activation, ring/permission/device changes, cancellation locking,
queue backoff/recovery, late audit expiry, audit rollback, malformed authenticated
state isolation, request/timezone boundaries, the active-plan cap and migration.
The real loopback TLS test now activates a schedule and verifies all 13 settings
through the existing seven-step ring update exchange.

The full PostgreSQL 17/race suite passes in **80.271 seconds**, at **83.6%**
package statement coverage. Vet and formatting checks pass. Both complete workflows
pass for scheduling commit `8bb65fb`
([push](https://github.com/the-luap/openuem-console/actions/runs/34419443928),
[pull request](https://github.com/the-luap/openuem-console/actions/runs/34419447259)).
The tests use only the [reserved PostgreSQL fixture](native-windows-mdm.md#scoped-enrollment-credentials)
and synthetic loopback device identities. Test-only time adjustment reseals owned
fixture data to exercise deadlines without waiting through production windows;
no host policy, certificate or actual managed device is changed.

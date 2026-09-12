# Scheduled native Windows update ring activation

The console and backend can schedule an exact [ring revision and device cohort](native-windows-update-rings.md)
for later activation. It stores the reviewed source, targets, creator permission
revision and timing before creating any device commands. A bounded worker
activates due plans through the same atomic cohort assignment used for immediate
rollouts. Concurrent workers and process restarts cannot activate one plan twice.

The [optional Windows listener](native-windows-operations.md) now starts the
worker at server startup and cancels it during shutdown. Reviewed console forms,
protected history and pending-plan cancellation are available. Reviewed
[dynamic group selection](native-windows-update-groups.md) rechecks the original
revision and native Windows membership at activation. Pilot promotion gates
remain implementation work. This is scheduled policy
assignment, not evidence of patch installation or an automatic patch rollout gate.

## Schedule from the console

Open ring history in a concrete site and choose **Schedule this revision** on the
current enabled revision, or **Schedule source removal** on a historical revision.
Enter 1–100 distinct native Windows UUIDs, one per line, and choose an activation
date/time in **UTC**, a window of 1–10,080 whole minutes and a per-device admission
lifetime of 1–168 whole hours. The browser's localized date display does not
convert the entered time from its local timezone. The preview displays both UTC
window boundaries, including date rollover, and every selected device.

Alternatively, choose devices from a dynamic site group. The form shows its
revision, rules, native Windows targets and excluded management identities.
Targets are read-only; choosing the group again starts a fresh draft. Creation
and activation both recheck the reviewed native membership. A changed group or
enabled inventory source configuration blocks the plan and requires new review.

The preview uses the same scoped, audited source/device checks as immediate
assignment. It preserves invalid drafts and shows each current certificate's
expiry, with an advisory when it expires before activation. This describes the
current identity record; it does not reserve future enrollment or queue capacity.
The worker and device transport retain their independent checks.

**Edit selected devices** preserves the selected source, targets, timing and
request UUID. **Confirm and save schedule** requires explicit confirmation and
saves only the plan. No device run or command is created by preview, editing or
future-plan creation. Final admission calls the existing transactional store
directly, preserving exact-request replay even after a ring change or the original
activation window. Static form parsing therefore checks timing syntax independently
of the current clock; new-work timing checks remain in preview and store admission.
Changing an already committed request's intent produces a conflict.

**Update schedules** displays 25 plans per page, including terminal history, with
bounded offsets. Details show the original source revision and target UUIDs,
UTC timestamps, admission lifetime, creator, state revision, attempts and reason.
Current names and identity metadata are read only in the original site; an
unavailable current device does not erase the original target or expose another
site's records. Activated plans link to their original cohort and device runs.
Backend timestamps retain subsecond precision in history.

**Cancel future activation** appears only for scheduled or waiting plans. It
requires explicit confirmation of the displayed state revision. A concurrent
state change or activation returns a conflict; cancellation cannot recall an
activated cohort. Successful cancellation preserves the immutable intent and
terminal history, removes the cancellation form and cannot be undone by replaying
the original create request.

These routes require `ManageUpdates` in the selected site without a prefix,
or under `/tenant/:tenant` and `/tenant/:tenant/site/:site`:

| Method and path | Behavior |
| --- | --- |
| `GET /windows/update-rings/:ring/schedule?revision=N&mode=apply` | Draft a reviewed schedule; mode may also be `remove` |
| `GET /windows/update-rings/:ring/schedule/groups?revision=N&mode=apply` | Choose a dynamic group revision in the selected site |
| `POST /windows/update-rings/:ring/schedule/preview` | Validate/review timing and all devices, or return to editing |
| `POST /windows/update-rings/:ring/schedule/create` | Confirm and save immutable future intent |
| `GET /windows/update-schedules` | Audited site history |
| `GET /windows/update-schedules/:schedule` | Protected original intent and current plan state |
| `POST /windows/update-schedules/:schedule/cancel` | Cancel pending activation with the reviewed state revision |

The existing 8 KiB body / 24-field ceiling, unique field allowlists, body-only
CSRF and no-query POST boundary apply. Reads fail closed if required auditing
fails, and creation/cancellation audit failures roll back the entire operation.
Names are escaped and storage errors do not reveal protected intent.

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
| `ScheduleUpdateRingFromGroup` | Additionally captures the reviewed group revision and enabled inventory sources; activation rechecks exact native membership |
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
conflicts, unavailable devices, changed groups (`group_changed`) and changed
inventory source configuration (`group_sources_changed`). A terminal state cannot be rewritten into an
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

Version-2 encrypted target intent adds the exact group source and enabled stores.
Legacy explicit-target intent remains version 1. Group/source fields in a legacy
plan, missing group/source fields in a version-2 plan and invalid group metadata
are rejected. No additional schema migration is required; older readers cannot
process version-2 group plans. Server startup supplies the same inventory source
configuration to console admission and the maintenance worker.

A scheduled rollout gets a deterministic activation request UUID and a separate
schedule binding in its encrypted purpose. Before its device commands can be
delivered, replayed or read, source proof checks the authenticated activated plan,
exact target set and source metadata, and activation within the original window.
Direct assignment retries cannot borrow a scheduled rollout identity. Existing
immediate ring cohorts and direct update runs retain their original encryption
purposes and exact protocol replay across migration.

Group source proof also requires the cohort's original ID, revision, name and
rules to match its protected activated plan. Later group edits do not affect an
already admitted cohort. Exact creation replay preserves the original plan even
after a source configuration change; it cannot create new work or rearm history.

## Verification

The group extension passes the complete actual Linux PostgreSQL 17/race suite
(190.222 seconds), registered console routes, Linux handler/view/catalog race
checks and the full Linux build. Thirty-six group browser cases include scheduled
source selection, UTC timing, confirmation, history and both blocked causes at
390/768/1440 pixels; 42 existing group/list/navigation cases also pass. Additional
database tests cover group changes, source configuration changes, original
provenance during delivery, protected intent rejection and late audit rollback.
The following timing and workflow evidence describes earlier scheduling changes.

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

Console parser and PostgreSQL route tests cover canonical UTC/minute syntax,
date rollover and time bounds, retained invalid drafts, complete target review,
future creation without queue writes, exact replay, changed intent, historical
removal, stale source conflicts, live permission replacement, sibling-site
isolation, confirmation/CSRF, cancellation revision races and full audit rollback.
An actual worker pass produces an activated plan and linked cohort; a separate
authority change produces protected blocked history. Pagination retains canceled
plans. View tests cover all six states, original targets with unavailable current
records, escaped names, subsecond UTC times and non-whole-hour backend lifetimes.

The full handler/race suite passes in **9.028 seconds**; Windows/shared view suites
pass in **2.543/1.987 seconds**. Vet and Linux/Windows builds pass. The final live
browser-fixture run, including the certificate-expiry advisory and manual browser
wait, passes in **303.907 seconds**, with views passing in **2.652/2.122 seconds**.
Set `OPENUEM_WINDOWS_SCHEDULE_BROWSER_FIXTURE` to a private URL-file path and
`OPENUEM_DESKTOP_BROWSER_HTTP=1` for the owned synthetic loopback fixture. Creating
the URL file's `.stop` sibling releases the fixture and cleans its schema.

Browser acceptance covers duplicate-target correction, edit preservation,
confirmed two-device historical removal scheduled across UTC midnight, saved
history and actual pending cancellation through cookie/Origin CSRF. The canceled
history remains readable without another cancellation form. History remains
contained at 390/768/1440 pixels; the 768-pixel form was visually inspected.
The browser reported no warnings or errors. These tests do not contact managed
devices or install host policy. Both complete workflows pass for schedule-console
commit `3a0b0fa`
([push](https://github.com/the-luap/openuem-console/actions/runs/34431557669),
[pull request](https://github.com/the-luap/openuem-console/actions/runs/34431559785)).

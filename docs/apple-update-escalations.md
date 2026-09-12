# Apple update monitoring and console alerts

From an original group assignment's **Current cohort progress**, open **Review
console update monitoring**. Review the original plan and fresh preview, then
confirm **Enable console monitoring**. **Apple update alerts** in management
navigation lists this site's monitors and saved incidents. Both update-management
and device-read permission are required, including for history.

Monitoring is opt-in for each immutable original assignment. Later changes to
the group or plan do not change its original enrollments, target or deadline.
The channel implemented here is the console: it does not send email, call
webhooks, change device policy or queue device commands.

## Decision evidence

A device requires attention only when all of the following hold at assessment:

- The original enrollment is active, has a valid identity and remains in the
  original site. Its current configured policy matches the original plan values.
- No temporary update exception is active.
- A usable OS version/build packet recorded after the original assignment and
  within the last 24 hours still requires the original target.
- A valid device-reported time zone recorded within the last 24 hours resolves
  the original device-local deadline, and the latest possible occurrence has
  elapsed. The OS packet was recorded at or after that occurrence.
- If an exception has expired or was explicitly ended, the OS packet was also
  recorded at or after that exception's end.

The [OS assessment](apple-update-assessment.md), [deadline
estimates](apple-update-deadlines.md) and [temporary
exceptions](apple-update-exceptions.md) retain their independent meanings.
Repeated local times use the latest possible instant; skipped or unverified
local times cannot establish overdue evidence. Matching configured values do
not establish continuous policy ownership by the original assignment.

A newly unverified device does not open an incident. If a previously open device
becomes unverified, it remains open and is counted as **Awaiting verified
evidence**. Missing or stale data cannot establish recovery. Active exceptions,
absent/different policies, a pending deadline or verified target OS evidence
exclude the device from escalation. These reasons remain visible separately;
removal from an incident does not itself prove installation.

## Incidents and acknowledgments

An incident retains its identity while its already-open devices continue to
require attention or await evidence. Repeated checks do not create repeated
alarms. Returning from unverified data to fresh attention for the same open
device preserves the existing acknowledgment.

A newly affected device starts a new incident identity and requires a new
acknowledgment. When no open devices remain, the incident and its current
acknowledgment clear. A later recurrence starts a new incident.

**Record acknowledgment** requires an action note and explicit confirmation of
the saved incident. It records who is handling that incident; it does not resolve
it, confirm installation or change any policy. A stale incident or configuration
cannot acknowledge a later incident. Retrying the same request returns its
original immutable receipt and leaves later state intact. A reused request key
with changed intent, actor or permission revision is rejected.

**Pause monitoring** stops future checks and preserves the last saved incident,
evidence and acknowledgment. Enabling monitoring again assigns it to the
confirming operator's current permission revision and makes a check due.
Configuration revisions change only on explicit configuration actions, so a
background check does not invalidate a configuration form.

## Worker and authority

The console starts the monitoring worker independently of the public Apple
listener, push-certificate reminders and scheduled update activation. Shutdown
cancels and joins all three workers. It checks immediately at startup and sweeps
every minute, with a five-minute interval between successful checks of a watch.
The due timestamp is not a delivery guarantee; downtime and workload can delay
checks. A sweep selects at most 25 watches and has a 30-second limit. Each watch
has a ten-second transaction limit. At most 256 monitors can be enabled in a site.

Every check uses the recorded owner's current update/device-read permissions and
requires the same permission revision. A grant change, including replacing it
with equivalent grants, stops monitoring with **Monitoring needs review**.
Permission restoration alone does not resume it. An authorized operator must
review and enable it again. Unverifiable source material also stops the watch;
a valid saved watch with an unavailable fresh preview can still be paused.

Current authority and scope locks precede the watch and device/policy locks.
Concurrent sweeps use a row lock with `SKIP LOCKED`. Assessment evidence, watch
state, any history event and audit write commit together. A failed final audit
rolls back the entire check or operator action. These operations never expand the
original group or send provider messages.

## Stored evidence and history

Migration 051 adds one durable watch per scoped original assignment and
append-only event receipts. Configuration and assessment state use separately
authenticated encrypted payloads. Scope, original source IDs, owner/grant
revision, state/configuration revisions, phase, incident/acknowledgment IDs,
counts and timestamps are bound to the relevant payload. Reads are bounded,
validate the immutable original cohort and authenticate referenced configuration
and acknowledgment events before returning a watch.

Saved assessments retain the original enrollment IDs, decision/reason, bounded
OS packet values/source/time, reported zone/source/time, derived UTC deadline
range and any relevant exception end time. They do not retain raw device status
documents or copy a moved device's new name. Historical deadline estimates
remain the recorded estimates; they are not recalculated with later time-zone
rules. An active-exception decision records the decision reason; the separate
exception history retains the original exception intent.

Configuration, newly required attention, meaningful decision changes, clearing,
acknowledgments and blocked monitoring append immutable encrypted events.
Unchanged checks refresh the current saved assessment and audit without creating
another history event. Monitor and event lists use 25-entry keyset pages with
an authenticated, scoped record as the cursor anchor. Historical event details
remain independent of later mutable watch state. A cryptographic or read-audit
failure withholds the affected result.

## Validation and remaining work

Owned PostgreSQL 17/race tests cover concurrent admission and checking, exact
retries, incident recurrence, stale acknowledgments, unknown evidence, pauses,
permission replacement, archived plans, moved devices, unavailable policy data,
immutable/corrupted events, keyset pages, bounded requests and final-audit
rollback. The targeted escalation/progress/exception/deadline regression passes
in 47.616 seconds. An additional PostgreSQL/race concurrency test passes in
3.227 seconds: valid policy changes and permission revocation cannot overtake
the final monitoring audit. The PostgreSQL maintenance lifecycle checks pass in
2.327 seconds. Actual registered Linux routes exercise the review,
configuration, acknowledgment, history, strict scope/permission failures and
corrupt-state handling. All 56 strict form-boundary cases pass.

The macOS and Linux view, locale, handler, lifecycle and middleware race checks
pass, as does the full Linux build. All 318 relevant Chrome cases pass, including
54 new monitoring cases at 390, 768 and 1440 pixels. Mobile attention and
source-blocked pages were inspected visually. Full-suite evidence is recorded in
[implementation status](implementation-status.md).

Automatic pilot promotion, continuous group membership reconciliation, email or
webhook escalation channels and physical-device acceptance remain separate work.
These saved snapshots belong to enabled original-assignment monitors; they are
not a general device compliance or historical reporting service.

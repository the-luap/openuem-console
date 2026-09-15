# Temporary Apple update exceptions

On an Apple device, select **Manage update exceptions**. The review shows the
current configured policy, current exception, notification availability and the
time of the assessment. Operators with current update-management and device-read
authority in the device's exact site can create, replace or end an exception.
Viewers can see the current exception in the device assessment but cannot manage
it or read the action history.

## Pause, replace, expire and end

A confirmed pause requires a reason and a future expiry within 30 days. The
console takes the expiry in **UTC**, distinct from an update policy's device-local
installation deadline. Confirmation binds the current configured values, latest
exception revision, native enrollment, site-placement revision and current
declarative-notification capability. Changed review inputs require a new review.

Admission removes the reviewed server policy, cancels its outstanding declarative
notifications and queues a replacement notification when supported. An active
exception blocks new policy assignments through individual, trusted in-process,
immediate group and scheduled activation paths. Group previews explain the
exclusion; a schedule whose original reviewed selection changed becomes blocked
for review. Replacing an active exception records another immutable pause event.

When the exception expires or an operator confirms **End update exception**, new
assignments are permitted. Neither action restores a previous policy or queues
an installation. Ending the exception queues no device work. Applying an update
afterward requires the ordinary current policy/catalog review. Exact retries of
an earlier request return its original receipt without repeating removal,
notification or restoration, including after a newer exception or policy exists.

The server cannot stop an installation already in progress. Notification queuing
or acknowledgment does not prove that the device removed its policy. Original
cohort OS results and [deadline estimates](apple-update-deadlines.md) remain
independent, with a separate active-exception count and per-device explanation.
The exception is not physical evidence of device-side behavior.

## Enrollment and site placement

Exceptions apply to one native enrollment in one organization/site placement.
A different enrollment ID does not inherit an exception. Moving an enrollment
out of its site permanently ends that exception's applicability, including if
the device later returns. This does not restore an old policy. An operator in
the new placement must review current state before creating another exception.

Migration 050 adds a database-maintained placement revision to native devices.
Changes to organization or site increment it under the device row lock; ordinary
updates cannot reset it. Exception events and review hashes bind that revision.
The original site's immutable history survives a move but does not load the
device's new name, policy or exception details from another site. A returned
device can receive a new exception with the next historical revision; its old
pause cannot silently become active again.

## Consistency, history and bounds

Creation, replacement and ending retain current authority and exact site locks,
acquire an exclusive device lock and compare the reviewed values. Policy removal,
notification replacement, encrypted receipt and audits commit together under a
ten-second context. Device identity and exception expiry are checked again after
the final audit. Failure rolls back the entire action. Permissions are rechecked
for every read and retry; a changed grant revision prevents reuse of an old
request even if the new grants have equivalent authority.

Each event is immutable, with an increasing revision within its original
site/enrollment, a scoped request key and a parent event. Authenticated encryption
binds its ID, scope, placement and event revisions, request, actor/grant revision,
kind and timestamps. The reason, reviewed comparison value, original configured
policy and optional notification ID are encrypted in a bounded 32 KiB payload.
The public models suppress ordinary formatting and JSON/XML/YAML output. Audit
metadata contains identifiers and revisions, not the reason or policy contents.

Reasons are limited to 1 KiB of valid UTF-8 with bounded control characters;
the console allows a brief 256-character reason and normalizes form line endings.
Policy fields are bounded before decoding. History reads authenticate 25 events
per page plus one look-ahead item, and validate the scoped cursor's ciphertext
before seeking by immutable revision. Corrupted required evidence fails closed
with a fixed availability response.

The registered routes are:

- `GET /ios/:id/update-exceptions/review`: current audited review.
- `POST /ios/:id/update-exceptions`: confirmed pause or end action.
- `GET /ios/:id/update-exceptions`: original scoped history.
- `GET /ios/:id/update-exceptions/:exception`: original event receipt.

These routes use the existing tenant/site prefix. Management routes require both
`ManageUpdates` and `ReadDevices`. The POST body is limited to 8 KiB, accepts only
unique allowlisted fields, uses the existing global and handler CSRF boundary,
and requires explicit confirmation. Resume rejects an expiry field, including an
empty one. Request/review values come from the audited preview; unknown query
fields and duplicate query values are rejected. Responses prohibit caching.

## Verification and remaining work

Owned PostgreSQL 17/race checks cover duplicate concurrent retries, competing
reviews, ordinary and group admission guards, blocked scheduled activation,
expiry without restoration, grant replacement, immutable/corrupted receipts,
26-event pagination, notification-capability changes, failed final audits and
identity/exception expiry during the final audit. Site round trips preserve
history while invalidating old applicability and old reviews. The expanded
regression passes in 36.499 seconds.

Console checks exercise actual scoped routes and strict form parsing. Browser
fixtures cover review, active/expired/ended exceptions, unavailable enrollments,
missing notification capability, original receipts, history, long reasons and
keyboard confirmation at 390, 768 and 1440 pixels. Device and cohort fixtures
also distinguish active exceptions from OS evidence and policy state. Broader
validation is recorded in [implementation status](implementation-status.md).

[Console update monitoring](apple-update-escalations.md) excludes active
exceptions and requires fresh OS evidence after an exception ends before opening
an overdue incident. Continuous group reconciliation, automatic pilot promotion,
external escalation delivery and physical-device acceptance remain separate work.
Exception expiry permits new assignments; it does not itself schedule one.

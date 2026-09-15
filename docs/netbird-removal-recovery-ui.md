# NetBird removal continuation: dispatch, history and console

The console now connects reviewed manifest-backed removal recovery to automatic
processing, retained history and explicit user actions. The original uninstall
and its owned release remain independent of every new continuation request.

## Background processing

Inventory startup constructs `NetbirdRemovalRecoveryStore` with the dedicated
version-five publisher and starts its joined dispatcher alongside the other
inventory workers. Four workers select the oldest active request without an
attempt or dispatch stop. Selection holds no database connection during native
execution. Each delivery has a twelve-minute parent budget covering current
inspection, native command lifetime and bounded result recording.

`Recover` rechecks the original requesting actor's current exact-site software
permission, original release proof, current individual recipient and reviewed
native/journal state before committing its one immutable attempt. An existing
attempt is never selected again, including after restart, lost responses or failed
result recording. Shutdown cancels processing and joins all callbacks and result
recording before the inventory service returns.

Migration 036 adds immutable dispatch stops for expired requests, lost software
permission and changed/unavailable source evidence. A stop retains the device
barrier and cannot replace an attempted or terminal request. Both Go admission
and a database trigger refuse delivery after a stop. An operator can explicitly
cancel a stopped request before native admission and obtain a new review. Startup
requires all three dispatch guards.

## Coherent retained reads

`Status` reads the request, native delivery, dispatch stop and resolution under a
shared request lock. Writers hold the corresponding exclusive lock, so a status
cannot combine incompatible transition states. `History` returns twenty records
per page with a cursor tied to the immutable device/site request and timestamp.

These reads require `ReadSoftware` in the historical site and an audit. They do
not contact the agent or require its present enrollment, certificate or native
files. Queued, stopped, cancelled, delivery pending, unconfirmed, completed and
released states remain distinct. A completed or released continuation retains its
first delivery result and links to the original uninstall receipt.

The original uninstall status exposes continuation-review eligibility only after
reconstructing its exact owned released **unconfirmed** proof. Withdrawn,
completed, unreleased and corrupted evidence cannot advertise a native
continuation. Reading eligibility does not inspect native files; the separate
review still requires fresh current authority and a supported original manifest.

## Routes and user actions

The route family is
`/tenant/:tenant/site/:site/computers/:uuid/netbird/removal-recoveries`:

| Method | Suffix | Action |
| --- | --- | --- |
| GET | empty | Scoped continuation history |
| GET | `/review?original_id=...` | Inspect the selected original uninstall for a fresh continuation review |
| POST | empty | Queue the exact reviewed original reference, recovery digest, console revision and new UUID |
| GET | `/:request` | Coherent retained request and result |
| POST | `/:request/cancel` | Cancel before native admission |
| POST | `/:request/observe` | Read the retained agent receipt |
| GET | `/:request/resolution` | Review withdrawal or release of this continuation |
| POST | `/:request/resolution` | Consume one exact retained resolution review |
| POST | `/:request/resolution/reconcile` | Reconcile an owned control after a lost response |

History and receipts require `ReadSoftware`; reviews and actions require
`AssignSoftware` in the exact organization/site. All five POST paths enforce the
raw eight-KiB body limit before CSRF extraction, including unknown-length requests.
Forms reject duplicate, unknown, malformed and conflicting query/body fields.
Native forms use 303 redirects; HTMX forms use 204 with the scoped redirect header.

An eligible original uninstall receipt offers **Review continuation of interrupted
removal** to software operators. The NetBird overview links to continuation
history. The review identifies the original package/request/release and the current
recovery and journal fingerprints, explains the connectivity impact and requires
an unchecked confirmation before queuing. Missing native recovery evidence offers
no continuation form.

Receipts distinguish the first continuation outcome from later observation and
resolution evidence. A received native attempt has no cancel or repeat action.
Eligible release/withdrawal requires a separate expiring review and confirmation;
read-only observation and reconciliation remain separate actions. Pending HTMX
forms disable their controls, show progress and suppress duplicate submission.
There is no automatic polling or automatic repetition of a native command.

## Verification and remaining work

Owned PostgreSQL tests cover restart exclusion, lost results, changed preflight,
retained stops, shutdown joining, coherent scope-bound status/history, pagination
and original-proof eligibility after certificate changes. Registered production
routes exercise exact original-reference forms, software authorization, CSRF,
unknown-length limits on all POST paths, native and HTMX submissions, completion,
receipt observation, withdrawal/release and lost-response reconciliation. Original
native outcomes remain unchanged throughout the continuation lifecycle.

Rendered template and middleware race tests pass. The complete Chrome matrix
covers 2,715 cases, including 75 continuation cases across 390, 768 and 1440 pixels:
long metadata, keyboard confirmation, scoped fields, reader access, lifecycle
states, pagination, pending indicators and duplicate suppression. Narrow review
and released-receipt screenshots were inspected. Browser fixtures use isolated
synthetic pages and perform no native endpoint operation.

The full NetBird inventory race suite passed against owned PostgreSQL in 605.970
seconds. Registered HTTP lifecycle tests, shutdown cancellation/join race tests,
and the Linux console and handler-test builds also passed.

Manifest-backed macOS continuation is integrated. The [independent native
current-absence layer](https://github.com/the-luap/openuem-agent/blob/febbc3d1b9e5b7ee39b80e8d0d04a27044952e0a/docs/netbird-removal-current-absence.md)
now supplies a separate read-only observer. The [remote protocol, agent admission
and complete console verification lifecycle](netbird-removal-absence.md) are
integrated. [Independent scaffold cleanup](netbird-removal-stage-cleanup.md) now
has native and agent admission plus its complete independent console lifecycle.
Linux individual enrollment,
publisher trust and physical installation/removal/reboot acceptance also remain
open, alongside the rest of the expanded roadmap. Native absence alone never
rewrites an uncertain outcome.

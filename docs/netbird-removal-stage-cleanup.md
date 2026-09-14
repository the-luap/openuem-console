# Independently reviewed NetBird removal staging cleanup

The [version-seven cleanup protocol](https://github.com/the-luap/openuem-nats/blob/8685f28fa959d05a0c9bd300dc2c79c5195bbd4b/docs/netbird-removal-stage-cleanup.md)
and [native owner with journal/service admission](https://github.com/the-luap/openuem-agent/blob/66404dc8faf209ef091c2fc696e710e2ffb8692a/docs/netbird-removal-stage-cleanup.md)
support a distinct current cleanup of a released uncertain uninstall's selected
private scaffold. Complete native proof permits only known empty directories and
bounded incomplete manifest metadata. The original uncertain receipt and its
release remain unchanged. Complete usable manifests, unknown objects, other
stages, replacement payloads, receipts and runtime conflicts prevent cleanup.

`PublishNetbirdRemovalStageCleanup` accepts only `cleanup-removal-stage` version
seven under current individual identity. It sends one direct request outside the
retrying agent command stream, bounds waiting by the reviewed command's deadline
and requires an exact correlated receipt. Pending or uncertain execution cannot
be automatically resent. Its caller must first commit the scoped reviewed intent,
exact independent attempt and audit; this transport alone grants no authority.

Version-six `removal-stage-cleanup-state` uses the existing strict control
publisher. The original reference contains only uninstall UUID, command hash,
review revision and owned release UUID. Current inspection returns the fixed
`macos-official-pkg-stage-v1` profile, ready-journal revision, native state digest,
exact directory count, manifest presence and byte count. All summary fields and
the fingerprint must match native preparation. Commands expire within five
minutes; native inspections within 45 seconds.

Existing connection, installation, removal, continuation and read-only absence
publishers reject the cleanup command. Cleanup does not silently use those
runners, infer an original manifest or change an old outcome. A missing stage
uses the separate current-absence workflow; it is not implied cleanup success.

## Console admission and durable evidence

`NetbirdRemovalStageCleanupStore` implements separate review, request, dispatch,
receipt observation, resolution and history. It reconstructs the exact original
version-four uninstall and its owned retained unconfirmed release proof. Missing,
withdrawn, completed, corrupted or foreign original evidence cannot authorize
cleanup. It then asks the currently enrolled macOS agent for a fresh native review.

The immutable intent binds the original reference, fixed profile, native digest,
ready-journal revision, directory count, manifest presence and byte count. The
console revision also binds the current certificate and expiry, broker, reconciled
consumer, report binding, platform, architecture and scope. Current
`software.assign` authority and recipient locks survive admission. The agent's
journal revision remains distinct from the console revision.

Requests expire within two minutes, bounded by the current certificate. Exact
request replay reads the existing intent without another native inspection.
Changed intent conflicts. Before delivery the store rechecks current authority,
original proof, recipient and every reviewed scope field. It commits a permanent
version-seven attempt and audit before sending one direct request. The command
expires within five minutes. A committed attempt prevents cancellation and
redelivery, including after restart or a lost reply. Its first result is immutable;
a later exact receipt can establish separate completion.

Migration `038_netbird_removal_stage_cleanups.sql` enforces exact typed metadata:
one to seven directories, a required boolean manifest flag and zero to 2 MiB of
metadata, with zero bytes when the manifest is absent. Unknown, missing, null and
incorrectly typed fields are refused. Request, attempt, result, observation,
review, resolution, proof and dispatch guards are checked at startup. All seven
NetBird request families share the unresolved-device barrier and permanent UUID
namespace in Go and SQL. Expiry and preflight stops retain the reservation until
explicit cancellation. Terminal requests retain their UUID.

Four bounded dispatch workers are cancelled and joined on shutdown. Historical
reads reconstruct retained evidence without native calls. Explicit receipt checks
require current authority but do not repeat cleanup. Missing receipts may offer a
reviewed permanent withdrawal; an exact unconfirmed journal entry may permit
release after execution has ended. Every control needs a fresh two-minute review.
Lost control replies reconcile through owned receipt evidence. Resolution never
claims cleanup completion or changes the original uninstall result.

## Scoped console workflow

Eligible original uninstall receipts offer **Review retained staging cleanup**.
The review displays the exact empty-directory count and incomplete metadata size,
or **None** when absent. It describes the destructive scope and requires an
unchecked confirmation. The form carries only original ID, new request ID,
`stage_cleanup_digest`, console revision, confirmation and CSRF token.

**Reviewed staging cleanup completed** describes only this new operation and the
current package absence verified at its recorded time. The original uninstall
retains its own outcome; later device changes require a new review. Queued,
stopped, pending, uncertain, cancelled and resolved states retain their distinct
evidence and available actions.

All routes use
`/tenant/:tenant/site/:site/computers/:uuid/netbird/removal-stage-cleanups`:

| Method | Suffix | Permission | Purpose |
| --- | --- | --- | --- |
| GET | empty | `software.read` | Scoped retained history, 20 requests per page |
| GET | `/review?original_id=…` | `software.assign` | Fresh exact cleanup review |
| POST | empty | `software.assign` | Queue the reviewed independent request |
| GET | `/:request` | `software.read` | Coherent retained receipt |
| POST | `/:request/cancel` | `software.assign` | Cancel before the permanent attempt |
| POST | `/:request/observe` | `software.assign` | Query the retained receipt |
| GET | `/:request/resolution` | `software.assign` | Review withdrawal or release |
| POST | `/:request/resolution` | `software.assign` | Commit one reviewed control |
| POST | `/:request/resolution/reconcile` | `software.assign` | Retain owned resolution proof |

Native forms return scoped 303 redirects; HTMX forms return 204 with their scoped
location. Every mutation uses production CSRF protection and an 8 KiB raw-body
limit before parsing. Duplicate, unknown and mixed query/body fields are refused.
Reader pages expose no mutations. History and receipts are `no-store`, escape
retained metadata and omit executable envelopes, certificates and broker keys.

Linux individual enrollment, publisher trust and physical installation/removal
acceptance remain separate roadmap requirements. Owned fixtures execute no host
or vendor operation.

## Verification

All consumers pin runtime module `v0.11.1-0.20260914160809-8685f28fa959`. Full
shared command/package races and cleanup fuzzing passed. Full agent native,
journal and command-service races, isolated Linux journal/command suites and
macOS/Linux/Windows builds passed. The complete selected console publisher race
suite passed in 3.708 seconds, covering one direct request, zero stream messages,
all retained outcomes, missing replies, cancellation, expiry, legacy rejection,
changed scope summaries and references, current certificates and old-version
responses. Fixtures perform no host or vendor NetBird operation.

Linux production console and worker builds passed with the same runtime pin.

The registered HTTP suite passed in 28.07 seconds, including independent cleanup
review, queue, cancellation, completion, observation, withdrawal and release.
It covers role/scope checks, native and HTMX redirects, strict CSRF/raw-body limits,
exact replay and the unchanged original unconfirmed uninstall. The startup test
binds and reuses the cleanup store and joins every worker. The shutdown race test
passed in 1.791 seconds. Linux console, handler and runtime test builds passed.

All view and CSRF middleware race tests passed. Chrome 152 completed all 2,871
browser cases, including 81 cleanup checks across 24 rendered states and three
widths. Tests cover absent/maximum metadata, exact submitted review values,
unchecked confirmation, retained original results, scoped pagination and nine
pending/duplicate-submit cases. Narrow review, absent-metadata and resolved
receipt screenshots were inspected. Fixtures perform no native endpoint cleanup.

The complete NetBird inventory selection passed against owned PostgreSQL under
the race detector in 942.714 seconds: 277 top-level tests, including 41 new cleanup
lifecycle tests. Coverage includes exact original release proof, all typed scope
bounds, changed current authority and summary fields, admission through Go and
SQL, concurrent cleanup/continuation/absence requests, permanent UUIDs, one
native delivery, lost and late receipts, audit rollback, retained observations,
explicit withdrawal/release, restart, immutable history and startup guards.
The final direct-SQL dispatch-stop regression also passed with a version-seven
attempt in 3.180 seconds.

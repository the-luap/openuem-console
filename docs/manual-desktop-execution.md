# Reviewed manual desktop execution

Server administrators can select, review and queue one task or profile from a
computer's task-report page. The former immediate execution URLs now require
the same explicit confirmation envelope. Bare IDs and display-name selectors
can no longer publish commands.

## Scope and confirmation

Choices, review, admission and dispatch require current server administrator
authority and the destination's exact organization/site. The computer must have
exactly one site and an admitted command channel. Both Enabled and No contact
allow a direct attempt. Individual enrollment additionally requires the current
unrevoked, unexpired identity and a completed, active command consumer.

An enabled source profile must have exactly one eligible audience:

- Global: no organization or site associations.
- Organization: the destination organization and no site associations.
- Site: the destination organization and its exact destination site.

Foreign, ambiguous and incomplete audiences are rejected. A task must remain in
its reviewed parent, be enabled, match the platform and have an implemented
mapper. Unknown platforms do not fall back to Linux. Individual Any tasks cannot
use the single-task mapper. A profile must have supported applicable tasks;
NetBird registration requires matching source, configured and destination
organizations.

Choices select public metadata only: literal name or exact ID search, at most
256 UTF-8 bytes of input and 50 matches. Pending work exposes its latest receipt
and suppresses another selection. Review identifies the computer, source,
parent, scope and task version or applicable task count. An initially unchecked
required checkbox confirms the target and the impact of the agent's system
privileges.

The fingerprint covers public source metadata, parent/audience, destination and
the relevant version vector. It exposes no credential/configuration digest.
Definition writers must advance task versions; stop older console writers
before enabling the new path.

## Durable intent and one attempt

Admission commits a canonical caller-generated request UUID, actor, exact
destination, source references, fingerprint and two-minute expiry together with
an audit receipt. HTTP admission never publishes a command and does not depend
on a fallible inventory reread after commit.

Only one request can remain queued per device. Replaying an identical UUID and
bound input returns the existing receipt; changed input conflicts. Historical
receipts remain readable after source/device removal, using current server
permission and the recorded valid site.

A background worker rechecks authority, membership, identity, source, parent,
versions and expiry. Guards remain held through handoff and terminal audit.
Before publishing, it commits a unique independent attempt record on a second
database connection. The pool must permit at least two connections.

Once attempt evidence exists, the request never calls the publisher again.
Cancellation, process loss, lost acknowledgement and completion-audit rollback
retain that evidence. Recovery finishes the request as unconfirmed. Audit
retention preserves queued request evidence; pruning terminal audit evidence
cannot reopen a terminal request.

The publisher makes one bounded NATS core request on the exact agent.ansible,
agent.windowstask or agent.runprofile subject with the validated device suffix.
These subjects are excluded from the configured durable command stream and
consumers. An owned broker test installs the actual command stream configuration
and verifies that manual requests produce no stored messages. The current
publisher reference is copied under a mutex.

| Receipt | Meaning |
| --- | --- |
| Queued | Intent committed; terminal handoff is pending |
| Delivery started | Independent attempt exists; completion is pending |
| Accepted | Agent returned an empty acceptance response |
| Rejected | Agent returned a nonempty rejection response |
| Stopped | A guard, preparation or expiry prevented the attempt |
| Unconfirmed | Delivery may have occurred; this request will not retry |

Acceptance does not mean execution or successful completion. Agent reply bodies,
broker errors and configuration errors do not enter user messages or audit
resources. Another command requires a fresh review; receipts have no repeat
command button.

## Payload and protocol limits

The standalone builder explicitly supports 34 platform/family combinations and
requires nonempty executable resources. Adding an editor family cannot silently
authorize an empty mapper. Existing worker/agent task identifiers are preserved.
Unix account removal now uses the correct Unix removal family.

The builder copies the source before decrypting legacy passwords. Short valid
hexadecimal plaintext never enters the legacy probe that can panic on a short
nonce; long hexadecimal ciphertext must decrypt with the master key. Failure
returns no payload and no private error text.

Names are bounded at 2,048 bytes, scripts at 128 KiB, other string fields at
16 KiB, aggregate task strings at 256 KiB and serialized single-task payloads at
512 KiB. Strings must be valid UTF-8 without NUL. Profile review rejects more
than 1,000 total tasks or an empty/unsupported applicable task set.

Single-task configuration is prepared from the locked task at dispatch.
**A profile request does not freeze configuration.** Existing agents acknowledge
its ID before asking the worker for then-current configuration. Review explains
this distinction. Immutable profile execution and signed correlated results
remain separate work; these receipts do not prove a particular report.

## Bounded computer task history

The replacement history reader selects bounded results and public labels. It
removes full task/configuration graphs, cross-organization source catalogs,
broker pings and provider-settings creation from this GET path.

One SQL statement couples totals, clamped page and rows, sorted by stored
profile-report time, NULL last, then descending report ID. Pages default to 25,
accept 1–100 entries and bound canonical page numbers to 1,000,000. Current
authority, complete endpoint membership and profile audience relations remain
held through the read audit. Report values and labels form a statement snapshot,
not immutable historical definitions.

Task labels require the current task to remain in the report's profile. Profile
labels/links require an eligible current audience and use that audience's actual
scope. Existing reports with missing definitions retain stored output. This
does not change deletion cascades or worker report updates.

Labels are limited to 512 characters, output/error previews to 4,096 and raw
completion text to 128 before leaving PostgreSQL. Truncation, unavailable
definitions, disabled tasks and missing/invalid times are explicit. Native
pages use wrapping, bounded keyboard-scrollable output, not embedded modals or
nullable-task dereferences.

## Routes, lifecycle and audit

Under /tenant/:tenant/site/:site/computers/:uuid:

- GET /execution: choices and latest receipt.
- GET /execution/review: review kind and numeric source ID.
- POST /execution: confirm UUID, kind, source and fingerprint.
- GET /execution/:request: recorded outcome.
- POST /runtask and /runprofile: the same envelope, bound to that source kind.

The three existing computer task-page scopes use the replacement history
reader. Inputs reject duplicate/unknown fields, malformed identities,
unexpected encodings and mixed query/body values. Confirmation bodies are
limited to 8 KiB before CSRF parsing, including wire padding and header-token
requests. Native submission returns 303; HTMX admission returns 204 with
HX-Redirect.

Inventory migration 11 adds requests and independent attempt/outcome evidence.
Audit migration 32 adds execution choices/review/read and desktop task-history
read events. The manual-execution audit source supplies scoped browsing,
export and retention. Resources contain identifiers and outcomes, never
commands, credentials or report output.

The inventory lifecycle starts and joins both refresh and manual workers.
Cancellation interrupts active database/broker work; restart processes retained
intent without repeating an attempted changing command.

## Verification and remaining acceptance

Owned PostgreSQL/race tests cover current roles, exact audiences, identity
expiry/revocation, consumer state, mixed/unsupported profiles, bounds, missing
definitions, stale review, idempotency, audit failure before and after handoff,
concurrent dispatch, held source/authority, retention, cancellation and restart.

Registered routes cover strict forms/queries, CSRF, native/HTMX redirects, former
execution URLs, private-field exclusion and receipts after device deletion.
Sixty-three focused Chrome cases cover native selection, explicit confirmation,
pending guards, exact forms, status meaning, keyboard paging/focus, bounded
outputs and 390/768/1440-pixel layouts. Mobile review/history views were inspected.

The full inventory and audit PostgreSQL/race suites pass in 125.326 and
11.377 seconds. Registered Apple/OIDC routes, including headerless native
submission through the compatible profile URL, pass. Affected macOS/Linux race
suites and the full Linux build pass. The complete 2,007-case Chrome matrix
passes in 109.155 seconds.

All commands/providers in these tests are owned fixtures. Physical device and
provider acceptance, immutable profile revisions, delegated legacy permissions
and broader software/settings/secret-lifecycle work remain open.

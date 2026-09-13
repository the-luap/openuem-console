# Durable NetBird operation storage

The inventory package provides an admission and recovery store for `up`, `down`
and `switchprofile`. The webserver initializes and joins its dispatcher, with a
versioned direct publisher and mandatory live journal inspection. The native
agent now opens the journal under its validated installation identity and binds
the managed command/control subscriptions. Exact-site console pages provide
review, submission, receipts, history and cancellation of unattempted requests.
An empty legacy reply cannot be adapted into a successful execution receipt.

This is a partial lifecycle migration. Install, uninstall, registration and peer
removal are temporarily unavailable through the console. Agents reject old
mutating subjects and old NetBird profile steps. Workers withhold entire profiles
containing active legacy NetBird steps before reading credentials or creating
provider keys. Disabled NetBird steps do not block other profile tasks. Upgrade
console, agent and worker together; there is no version negotiation or unsafe
fallback. Staged managed lifecycle operations must replace these temporary
restrictions before the NetBird roadmap is complete.

## Console workflow

Open `/tenant/{tenant}/site/{site}/computers/{device}/netbird`. The overview reads
reported inventory in an audited, authorized membership snapshot without provider
credentials or device/provider requests. Its explicit refresh action uses the
existing scoped inventory refresh queue. It does not refresh during GET.

Connection and profile actions open a review of the exact device, organization,
site, configured management URL and profile handle. Submission requires an
unchecked confirmation checkbox, a retained request UUID, the reviewed source
revision and CSRF protection. Duplicate clicks are suppressed while pending.
The browser redirects to a durable receipt after admission; it does not wait for
the CLI. Read-only users can inspect state, receipts and 50-row history without
command controls. History remains readable in its recorded scope after removal.

Receipts distinguish queued, sending, completed, stopped and unconfirmed work.
Only an unattempted queued request offers cancellation. An unconfirmed outcome
does not offer retry or release: coordinated console/agent resolution is still
required before exposing that action. Profile names are escaped display values;
selection and submission use the original structured handle.

## Authorization and review

Review and admission require `devices.security.manage` in the exact organization
and site. The target must have exactly one site association, an enabled or
no-contact status, a supported desktop platform and a reported installation.
Organization settings must contain a valid HTTPS management URL. Provider tokens
and setup keys are not read or stored by this connection-operation store.

The review fingerprint includes the device generation, site/organization,
organization provider ownership revision, provider configuration revision and
selected profile identity. Individual mode also binds the current certificate,
broker key and command-consumer revision. The certificate and desired command
consumer must be active and provisioned. Command lifetime is capped by the
certificate expiry as well as the request expiry.

Review, new admission and dispatch each perform a fresh read-only journal query
while holding the target and authority locks. The probe is bounded to two seconds
and certificate expiry. Only a valid `ready` state is accepted; older agents,
missing responders, unavailable/full journals and pending work cannot create an
execution attempt. The journal revision joins the source fingerprint. A changed
revision invalidates the review or stops an admitted request before sending it.

Database generations invalidate old reviews after device recreation, scope or
organization ownership changes, eligibility/platform changes and reported
installation changes, including changes that later return to their original
values. Ordinary hostname updates, enabled/no-contact transitions and changes to
a profile's active flag do not invalidate its selected identity. Profile IDs
come from reported local state; they do not establish provider peer ownership.

Admission uses a canonical nonzero request UUID and an exact source revision.
The same UUID and identical actor, scope, mode, device and input return the
recorded request. Reusing it for different input fails. A device can have one
queued request or unreleased uncertain outcome, across all recorded scopes.

## Execution and recovery

Each request has an immutable two-minute lifetime. A dispatcher locks a queued
row, then checks the current mode, permission, target and source again. It holds
those locks while calling the executor. Database work is bounded to two minutes
plus five seconds; the executor receives the earlier command deadline. This can
delay membership, permission or configuration writes during an execution.
There is no unbounded background execution contract.

Before invoking the executor, a second database transaction commits an immutable
attempt receipt and an audit event. It has no foreign key that could wait on the
locked request. Failure to commit either record prevents execution. The store
requires a connection pool with at least two connections; production workloads
need additional connections for normal reads and writes.

The receipt captures the canonical digest of the complete prepared message and
its actual expiry, including a shorter certificate deadline. A new completed
result must match this digest in both application checks and the database guard.
Migration `013_netbird_wire_receipts.sql` keeps older evidence unchanged instead
of manufacturing hashes for messages that were never captured. Historical
completed receipts remain readable; new completions require wire evidence.

| State | Meaning | Further device actions |
| --- | --- | --- |
| `queued` | Admitted; an attempt may already exist after a process failure. | Blocked |
| `completed` | The executor supplied a positive execution receipt matching the request, device, revision and operation. | Allowed |
| `stopped` | The request expired, lost authority/source eligibility, changed mode or was cancelled before an attempt. | Allowed |
| `unconfirmed` | Delivery/execution could not be positively established, or dispatch recovered an existing attempt. | Blocked until explicit release |

A transport error, nil receipt, negative result, mismatched identity, cancellation
or late response never becomes `completed`. Remote error strings and arbitrary
response payloads are not persisted. A later database/audit failure may leave a
request queued with its permanent attempt receipt. Recovery marks it unconfirmed
without invoking the executor again. Completion describes that operation; it
does not prove a lasting connection or authoritative provider association.

Cancellation only withdraws an unattempted queued request. The attempt is read
again after the request lock is acquired, so cancellation cannot overlook an
attempt committed while its original query was waiting. Explicit release
requires device-security permission in the recorded scope and retains the
original uncertain outcome, release actor and timestamp. It neither interrupts
an old process nor resubmits the command. The future console workflow must
present the uncertain outcome for operator review before calling release; the
agent journal must prevent overlapping or repeated local execution.

## History and retention

Request identity, terminal outcomes, release evidence and attempt receipts are
protected against rewriting. Request and attempt rows cannot be deleted through
ordinary row mutations. They have no cascading dependency on the endpoint,
organization or user, so removing inventory cannot erase duplicate protection.
Scoped reads and 50-row keyset history use the recorded site, including after
endpoint removal.

The `netbird-operations` audit source exposes identifiers, actors and outcome
metadata. It excludes provider configuration, secrets, selected profile names
and command result bodies. Review, admission, reads, attempts, terminal outcomes
and explicit releases are audited atomically with their related database work.
Audit events participate in the existing scoped retention policy; permanent
request and attempt records remain outside event retention.

Inventory migration `012_netbird_operations.sql` installs the storage and
generation/immutability triggers. Startup checks their presence, trigger kind
and enabled state. NetBird settings migration must also be installed before
using review or admission.

## Validation and remaining integration

Owned PostgreSQL tests cover scope and role checks, structured profile selection,
concurrent admission/dispatch, generation changes and reversals, individual
identity/consumer changes, expiry, cancellation races, retained authority locks,
audit failure, process cancellation, recovery, immutable records and retention.
The executor in these tests is an owned callback; no real device or provider is
contacted.

Production integration includes native initialization, joined shutdown and the
review/request/receipt/history/cancel routes. Coordinated resolution with durable
console intent and matching agent evidence remains open.
Installation/uninstallation, registration with
staged setup-key creation/cleanup and authoritative peer deletion are separate
operations and are not admitted by this initial store. Trusted Unix installers,
provider acceptance and physical-device validation remain open.

The shared `netbirdcommand` codec and agent `netbirdjournal`/`DurableExecutor`
components are implemented, together with expiring state/receipt/release control
messages. The agent service adapter bounds certificate lifetime, owns exact
subscriptions and joins callbacks before closing the journal. Native startup
derives stable storage from the protected individual identity directory or the
validated legacy configuration parent. Renewal retains installation identity;
scope changes close old subscriptions rather than reset duplicate protection.
The console publisher
uses the new direct subjects and checks complete receipt correlation; neither
commands nor controls enter the retrying agent stream. Owned codec, filesystem,
subprocess and NATS tests cover expiry, correlation, durable replay, response loss
and explicit uncertainty recovery. The reviewed console release must still
coordinate its durable resolution evidence with the agent before opening the
server barrier; the current database-only release API is not a user workflow.

Owned route tests cover current roles and scopes, strict forms, CSRF, idempotent
submission, completed receipts, cancellation and history after removal. The 51
new browser cases and full 2,145-case matrix pass at 390, 768 and 1,440 pixels,
including confirmation, pending controls, focus, long text and narrow layouts.
The full inventory PostgreSQL race suite passes in 135.517 seconds and the audit
suite in 10.988 seconds. Final registered-route fixtures pass. Full agent builds
pass for Linux, macOS and Windows; worker Linux/Windows and console Linux builds
also pass. Cross-compilation does not establish native Windows or physical
NetBird/provider acceptance.

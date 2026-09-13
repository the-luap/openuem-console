# Durable NetBird operation storage

The inventory package provides an admission and recovery store for `up`, `down`
and `switchprofile`. This is a backend foundation: the legacy HTTP handlers and
agent subscriptions do not use it yet. A compatible agent command protocol,
durable agent journal and reviewed console flow are required before enabling
production dispatch. An empty reply from a legacy NetBird subject cannot be
adapted into a successful execution receipt.

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

Production integration still needs an expiring correlated agent protocol on a
separate subject, agent journal/recovery, console review/history/release routes
and background-worker wiring. Installation/uninstallation, registration with
staged setup-key creation/cleanup and authoritative peer deletion are separate
operations and are not admitted by this initial store. Trusted Unix installers,
provider acceptance and physical-device validation remain open.

The shared `netbirdcommand` codec and agent `netbirdjournal`/`DurableExecutor`
components are now implemented. Owned codec, filesystem, subprocess and NATS
tests cover expiry, correlation, durable replay, response loss and explicit
uncertainty recovery. They are not yet attached to production subscriptions or
console dispatch. The console must persist the actual wire digest before sending
and coordinate the reviewed release with the agent's journal.

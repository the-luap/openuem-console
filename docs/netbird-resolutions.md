# Reviewed NetBird uncertainty resolution

An unconfirmed connection command blocks further NetBird requests until an
operator reviews matching agent evidence. Open its receipt in the recorded
organization/site and select **Review resolution**. Current device-security
permission is required. The original command stays `unconfirmed`, including
after resolution; a later receipt never rewrites the original console outcome.

## Review and confirmation

Review locks current permission, the request, the actual device/site association
and current enrollment identity. A historical read grant does not authorize
sending controls to a moved device. Individual mode requires an unrevoked,
unexpired certificate and a provisioned active command consumer. The current
certificate bounds every control deadline. Provider credentials, management URL
and reported installation status are not used as resolution identity.

The console queries the original command UUID and complete digest using the
current identity. A read query has a two-second bound. Its response must match
the query digest, device, original source revision and operation. A new review
fingerprint binds current scope/generation, certificate, broker/consumer revision,
retained receipt and any required journal state. A scope change that is later
reversed still invalidates a previous confirmation.

| Agent evidence | Available action |
| --- | --- |
| Retained completed receipt | Explicitly acknowledge the later completion evidence. No agent release is sent. |
| Retained unconfirmed receipt, matching pending journal entry, local execution ended | Explicitly request one durable agent release. |
| Missing receipt, unavailable journal, active/unjoined execution or another release identity | Keep further commands blocked. |
| Existing console resolution intent without confirmed evidence | Query its retained receipt. If a release was not retained and local execution has ended, a fresh review can explicitly authorize another recovery attempt. |

The form shows the original request, target, profile and remaining uncertainty.
It requires an unchecked confirmation, CSRF and exact resolution UUID/revision.
Pending controls are disabled and duplicate browser submissions are suppressed.
This is an explicit operator action, not an automatic retry or a promise that
the device remains connected. The agent's native boot rules still apply: an
agent process restart alone cannot release an orphaned CLI attempt.

## Durable intent and evidence

Migration `014_netbird_resolutions.sql` adds separate permanent intent and
evidence tables. A resolution has one immutable UUID per original request. Its
admission records the actor, scope, reviewed revision, complete prepared control
and canonical digest in an independent transaction, together with an audit
event. That transaction commits before a release RPC. It has no foreign key
that could wait on the request held by the outer transaction.

A release control expires within ten seconds and the current certificate
lifetime. The request/source/authority locks remain held through the bounded
control and evidence commit. The publisher sends once. Replaying the same
resolution form returns the retained intent; changed actor, UUID or revision
conflicts. A process failure, lost reply, deadline or outer audit rollback never
causes another mutating control.

**Check agent receipt** sends a fresh read-only query with the original command
UUID/hash and current device identity. An unconfirmed receipt must return the
exact retained resolution UUID. A completed acknowledgement must remain a
matching completed receipt. Wrong, missing or foreign evidence leaves the
barrier closed. Certificate renewal preserves access to the original command
evidence while using the current certificate for the new query.

Accepted evidence retains both the exact query and its correlated response.
The evidence row, original request's release metadata and release audit commit
together. Database guards reject partial/unmatched evidence, rewriting or
deleting intent/evidence, and any new database-only release without matching
evidence. Startup verifies all four new guards. Older historical release rows
remain unchanged; migration does not manufacture missing evidence for them.

The original receipt exposes the resolution UUID, admission actor/time and
confirming actor after completion. Scoped readers retain this metadata after
inventory removal and audit-event retention. Permanent request, attempt, intent
and evidence records have no cascading dependency on a device or user.

## Validation and limits

Owned PostgreSQL tests cover lost command/release replies, concurrent form
replay, conflicting identities, intent/audit failure, partial evidence, current
permission and membership locks, scope changes/reversals, invalid or expired
responses, certificate renewal/revocation/expiry, inactive consumers, retained
history after removal, audit retention and disabled database guards. Real route
fixtures check permission, CSRF, strict forms, review without release, pending
receipts, explicit reconciliation and the unchanged original outcome.

Twenty-four additional browser cases cover release, later completion, pending
and confirmed resolution, blocked evidence and long text at 390, 768 and 1,440
pixels. Together with the command pages, there are 75 NetBird operation cases
before the additional [recovery-attempt cases](netbird-resolution-retries.md).
The full browser matrix now passes 2,313 cases. Fixtures use owned callbacks and
brokers; no installed NetBird executable, real provider or physical endpoint is
invoked by these tests.

The full inventory PostgreSQL race suite passes in 200.398 seconds; the full
audit suite passes in 9.233 seconds and the affected view race test in 1.942
seconds. Final registered-route fixtures and the full Linux console build pass.

Missing journal evidence remains blocked. If the release request itself was
never received, read-only reconciliation cannot manufacture a release; there
is no automatic resend or journal reset. [Explicit recovery attempts](netbird-resolution-retries.md)
now allow a freshly reviewed release under the same resolution ID. Recovery of incomplete local
storage and physical-device acceptance remain separate work. Installation,
authoritative peer deletion and additional recovery protocols remain open.
[Managed registration](netbird-registrations.md) and its separate
[combined resolution](netbird-registration-resolutions.md) now cover reviewed
setup-key creation, cleanup and retained-key uncertainty.

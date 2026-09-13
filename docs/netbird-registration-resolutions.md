# Reviewed NetBird registration resolution

An unconfirmed registration keeps subsequent NetBird commands blocked. Open its
receipt in the recorded organization/site and select **Review registration
resolution**. The page shows provider key state and agent evidence separately.
For an unresolved request, current `ManageDeviceSecurity` authority and the
actual device/site association are required for review and resolution. The original outcome stays `unconfirmed`
after resolution; separate confirmation metadata opens admission.

## Eligible evidence and explicit actions

| Retained evidence | Resolution behavior |
| --- | --- |
| Known key; no device delivery attempt | Prove key absence, then resolve using the permanent delivery barrier. No agent control is needed. |
| Known key; matching completed agent receipt | Prove key absence, then acknowledge the later completion evidence. No agent release is sent. |
| Known key; matching unconfirmed receipt and ended local execution | Prove key absence before attempting one explicit agent release. Require its matching resolution UUID before opening admission. |
| Known key; version-two missing receipt and a ready journal | Explicitly request permanent withdrawal after key absence. A matching retained withdrawal is required to open admission. |
| Unknown key identity, changed key policy, unsupported withdrawal, active execution or another resolution identity | Keep admission blocked. |

Review only reads the provider and agent. The fingerprint binds the original
request and delivery digest, current scope/identity generations, key state,
retained stage attempts, agent receipt/journal and existing resolution metadata.
An explicit form confirmation rechecks that fingerprint. Individual mode uses
the current certificate, broker identity and active provisioned command consumer;
certificate renewal does not change the original command digest.

If the retained key has never had a cleanup attempt, confirmation may start its
first removal. Cleanup uses the original encrypted provider origin/token and the
exact key ID returned at creation. Its retained creation policy must match before
DELETE. Only a subsequent exact-ID GET returning 404 establishes absence. The
current resolving actor is audited without changing the original actor that
binds the encrypted snapshot. A recorded DELETE is never repeated.

**Confirm continuation** requires a fresh review of an existing resolution. It
can start only a cleanup or agent release that has not yet been attempted. This
covers a crash after intent admission or a key cleanup that becomes confirmed
later. The original resolution UUID, initiating actor and initial review revision
remain immutable; another currently authorized manager may confirm continuation.

**Check retained evidence** only reads external state. It can persist later key
absence or matching agent proof, but cannot start a previously unattempted
cleanup or send a release. In particular, if key absence becomes confirmed before
the first agent release, the manager must review again and explicitly confirm
continuation. Replaying the initial form returns its retained intent without
another provider mutation or release.

## Storage and failure ordering

Migration `016_netbird_registration_resolutions.sql` adds separate permanent
resolution intent, agent control attempt and final evidence tables. None has a
foreign key that could wait on the original request held by the outer transaction.

1. Independently commit the resolution UUID, actor, review revision, kind and
   original delivery digest, together with its audit event.
2. Perform only eligible first key cleanup, retaining its attempt before DELETE
   and its absence evidence independently. Provider uncertainty stops progress.
3. Recheck agent evidence after cleanup. Independently commit a canonical control
   attempt and audit event before sending one release. Release requires previously
   retained key absence and expires within ten seconds and the current certificate
   lifetime. Completed acknowledgements use a correlated read query instead.
4. Commit final evidence, release metadata and release audit together. Provider
   absence is mandatory. Agent proof must bind the original command UUID, device,
   operation, revision and complete version-two digest, including its setup key.

A lost release reply is recovered with a fresh receipt query using the current
device identity and the same retained resolution UUID. A final audit failure
rolls back confirmation but preserves the independently committed attempt, so
recovery does not repeat release. Current authority and device identity locks
remain held through the bounded external steps and final commit.

Database guards enforce stage prerequisites, matching evidence, immutable
records, and evidence before release metadata. Startup checks all seven new
guards. Both connection and registration admission exclude a resolved uncertain
registration from their shared barrier, while permanently reserving its request
UUID. Scoped receipt/history readers retain the original outcome and resolution
metadata after device removal. Audit retention cannot erase these records.

## Validation and remaining limits

Owned PostgreSQL and TLS fixtures cover completed/unconfirmed/no-delivery cases,
first cleanup by a different authorized actor, missing and changed evidence,
lost requests/replies, stale continuation, audit failure at each stage, immutable
guards, renewed/revoked/expired certificates, inactive consumers and moved devices.
Real registered-route tests exercise permissions, CSRF, strict forms, read-only
review/reconciliation, explicit continuation and retained historical receipts.
Browser cases cover keyboard confirmation, pending input locks across both
forms, focus recovery, blocked states and long content at 390, 768 and 1,440 pixels.
All 117 registration cases and the full 2,286-case browser matrix pass. The full
inventory PostgreSQL race suite passes in 183.913 seconds, including current
individual identity, permanent withdrawal and cleanup by another authorized actor. The audit race suite, affected
view race tests, registered-route fixtures and Linux console build also pass.

A missing creation response still cannot establish the provider key identity.
A missing agent receipt alone cannot prove non-execution after a delivery attempt.
The [permanent withdrawal protocol](netbird-registration-withdrawals.md) now
provides an explicit recovery path when the agent supports it and has no attempt.
An undelivered release request or a recorded DELETE whose key remains present
is not automatically retried. These cases need additional explicit recovery
protocols and remain blocked. No journal reset or mutable name/IP match substitutes
for evidence. Confirmed resolution does not establish provider peer ownership,
current connectivity or actual group membership. Trusted installers and physical
device/provider acceptance remain separate work. Tests do not invoke an installed
NetBird executable or a real provider.

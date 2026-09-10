# Native Windows disconnection notifications

The SyncML endpoint now accepts authenticated Windows disconnection notifications,
retires the native identity's server access, preserves interrupted work and shows
the report in device details and inventory. Server-requested disconnection,
missing-notification recovery and physical Windows cleanup acceptance remain
implementation work. This extension does not send an unenrollment command.

## Protocol meaning

Microsoft documents a best-effort generic alert sent as message 1 of a new
session after existing sessions are stopped and before local cleanup begins.
Its alert type is `com.microsoft:mdm.unenrollment.userrequest`, with integer data
`1` in alert `1226`. The notification can be the only packet the device sends.
Microsoft also describes this notification for server-initiated disconnection;
the alert alone does not identify who initiated it or prove completed cleanup.
[Microsoft disconnection protocol](https://learn.microsoft.com/en-us/windows/client-management/disconnecting-from-mdm-unenrollment)

The separate server-requested flow uses an Exec on the DMClient Unenroll node
with the provisioned ProviderID. Custom CSP commands continue to reject DMClient
and other enrollment-account roots; this work does not open that boundary.
[DMClient CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/dmclient-csp)

## Admission and access retirement

The existing direct TLS or pinned gateway identity boundary selects the real
current enrollment certificate. The service checks live scope, device access,
certificate validity and immutable management configuration, then locks the
protected nonce state and any active session. Admission requires the current
next-session OMA DM client digest. An old bootstrap digest cannot interrupt a
session after the next nonce has advanced. A valid first notification may reuse
the active wire SessionID without being mistaken for an old packet retry.

Exactly one complete top-level notification is accepted in a Final first package.
The notification has one item, the exact type and `int` format, and text data
`1`. Duplicate/nested notifications, alternate values, chunking, item targets,
extra notification metadata, redirects, old command outcomes and accompanying
mutations are rejected. Ordinary session-start alerts and bounded DevInfo reports
may accompany it; a complete inventory/probe exchange is not required. DevInfo
remains untrusted device input and does not replace enrollment identity.

The service returns only status acknowledgments and its existing server digest,
subject to the peer's response-size limit. It does not dispatch work or require a
second message to confirm server authentication. This is a unilateral device
notification authenticated by TLS and the current client digest, not a completed
mutual management exchange or a certificate-renewal confirmation.

One transaction:

1. Marks a live interrupted session aborted without adding a fictional packet or
   advancing its last-message number. Pending command effects become unknown;
   previously conclusive command outcomes retain their existing meaning.
2. Stores the bounded encrypted request/response evidence, nonce context and
   immutable endpoint configuration, linked to the actual transport certificate,
   initial encryption anchor and interrupted session.
3. Sets device access revocation and records the notification audit. All pending
   or confirmed certificate generations then lose management access together.
4. Rechecks the actual transport certificate's lifetime after audit/command waits
   and commits before returning any success bytes.

A failed audit, invalid proof or certificate expiry rolls back every change.
Concurrent notifications admit one transition. After acceptance, the retired
identity is denied for management, renewal and exact notification retries,
including resumed TLS. There is no revoked-key replay exception.

The original enrollment, certificates, bootstrap ciphertext, next-session nonces
and queued command records remain intact. A pending renewal is not falsely marked
confirmed. A separate OpenUEM agent retains its own identity. The original native
identity cannot resume management simply because local Windows cleanup failed.

## Protected history and console

Migration `012_unenrollment_notifications.sql` adds scoped append-only reports
and audits. It also allows an existing live session to become aborted without
inventing another message. Existing enrollment/session ciphertext and replay
records remain readable across migration and restart.

AEAD binds each report to its device/scope, actual and anchor certificate IDs,
transport fingerprint, request/response digests, interrupted session and received
time. The sealed record is bounded to 2 MiB; the existing 1-MiB SyncML wire limit
still applies. `UnenrollmentReport` requires fresh `devices.read` permission at a
concrete site. It verifies the sealed evidence, stored digests, exact alert,
bootstrap/configuration binding, both digest directions, reporting certificate
fingerprint, interrupted session and matching device revocation time. A read
audit must commit before protected metadata is returned. Generic serialization
and formatting omit report contents; wire payloads and nonces are never returned
as console metadata.

Device details show **Device disconnection reported**, the UTC report/revocation
time, report ID and reporting certificate fingerprint. The status is
**Disconnection reported; access revoked**. The page explicitly leaves local
policy, certificate and managed-data removal unverified. Enrollment, renewal and
command history remain accessible under their existing capabilities. An
interrupted command appears as **Effects uncertain**; it is not automatically
resent. Device readers can inspect the report without acquiring certificate or
CSP administration rights.

## Verification

Synthetic PostgreSQL/race tests cover first-packet admission without prior
management, live-session interruption with a fresh next nonce, stale proof,
concurrent notifications, preserved enrollment/nonces/queued work, protected
history, scope/roles, restart, immutable reports, tampering and migration
preservation. Acceptance/read audit failures return no successful result. A
short-lived synthetic certificate expires while waiting on the audit table and
leaves no committed notification or revocation. An owned TLS listener verifies
actual client-key presentation, rejection of invalid digest/forged hints and
retired-key denial on resumed TLS; pending replacement access is also denied.

Focused PostgreSQL/race tests pass in **11.542 seconds**. The complete Windows
suite passes in **123.217 seconds**, with protocol in **1.384 seconds**. Full
console integration passes under the race detector in **11.085 seconds**, with
Windows view tests in **2.904 seconds**. Focused Windows handler checks also pass. Fuzzing passes
**468,312 executions** in **30.457 seconds**; CI includes its bounded target.
Vet and Linux/Windows builds pass. Browser checks on an owned loopback fixture at
390, 768 and 1440 pixels verify contained layout, escaped names, clear report
semantics, absence of another revocation form and navigation to the retained
uncertain command. The fixture and its isolated schema are removed afterward.
Full CI for this extension is pending.

These fixtures create no host enrollment, profile, certificate-store entry or
physical device command. Real Windows disconnection behavior, local cleanup,
server-requested unenrollment and cases where no notification arrives remain
open in WIN-02.

# Native Windows disconnection lifecycle

The SyncML endpoint now accepts authenticated Windows disconnection notifications,
retires the native identity's server access, preserves interrupted work and shows
the report in device details and inventory. A typed store workflow now queues
server-requested disconnection and records explicit review when the notification
is missing. Its dedicated console forms and physical Windows cleanup acceptance
remain implementation work; the existing custom CSP editor cannot create it.

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
dedicated disconnection console actions and end-to-end recovery acceptance remain
open in WIN-02.


## Server-requested disconnection and explicit review

`EnqueueUnenrollmentRequest` requires current `devices.revoke` permission at the
exact device site. It queues a fixed `Exec` for
`./Device/Vendor/MSFT/DMClient/Unenroll`, with the originally provisioned ProviderID
as character data. The management options must come from the server configuration;
opening the original enrollment's protected bootstrap verifies their binding.
Custom CSP URI validation continues to reject DMClient, DMAcc, Enrollment and
Provisioning roots. The protected result grammar admits only this single Exec
when it carries the matching lifecycle owner.
[Microsoft Unenroll node](https://learn.microsoft.com/en-us/windows/client-management/mdm/dmclient-csp#deviceunenroll)

Migration `013_unenrollment_requests.sql` binds one immutable lifecycle request to
its durable CSP command, exact device/site, caller request UUID, creator and access
revision, and creation/expiry times. The reason and management options are sealed;
release reasons have separate authenticated ciphertext. Request identity, reviews
and lifecycle audit are append-only. Existing custom/update request ciphertext,
protected session state and exact delivery replay remain compatible. Expiry is
bounded to one minute through seven days. Reusing an exact request key returns the
existing request; changed intent or creator revision conflicts. A device cannot
have two unresolved disconnection requests. Its lifecycle slot is separate from
the 256-command custom/update queue; released historical uncertainty does not
consume normal queue capacity.

The operation has priority over queued custom/update work. It can follow an older
unrelated uncertain command after a fresh mutually authenticated session and
identity probe, without changing that command's evidence. Delivery and exact
packet replay recheck the creator's `devices.revoke` capability, original access
revision and deadline. The final deadline check follows audit waits. An expired
or unauthorized undelivered request is retired without sending its payload.

Once delivered, a request holds subsequent command delivery until explicit review
or an authenticated disconnection report retires access. A `200` Exec status means
command acknowledgment; `202`, failure and missing responses retain their existing
CSP meanings. None proves local cleanup or revokes access by itself. The separate
incoming notification still uses its original proof and access-retirement rules,
and cannot attribute who initiated the disconnection.

`UnenrollmentRequests` and `UnenrollmentRequestDetails` provide protected, audited
history under fresh `devices.revoke` permission. They verify the owning intent,
original enrollment configuration, fixed request, current command result and any
release record before returning data. `CancelUnenrollmentRequest` accepts only
queued/blocked requests at their reviewed revision. Custom-command cancellation
and abandonment reject lifecycle-owned requests, and their existing views hide
those forms and identify the disconnection owner.

`ReleaseUnenrollmentRequest` requires a reviewed command revision and a reason.
It can release a delivered request after investigation; it does not retry, undo,
or claim successful cleanup. A still-live delivery session becomes aborted,
leaving unresolved effects unknown while preserving conclusive device outcomes.
The immutable review records its actor, reviewed revision, time and protected
reason. Further management needs a new authenticated session. The released Exec
cannot be replayed; a later authenticated disconnection notification still
retires access. Existing explicit server-side device revocation remains available
when continued access is unwanted.

Synthetic PostgreSQL tests cover concurrent idempotency, authority revision
changes, fixed provider/configuration binding, raw-CSP isolation, priority over
unrelated uncertainty, exact result correlation, absent/200/202/500 responses,
late notifications, revision-checked cancellation/release, audit rollback,
protected storage damage and immutable history. Migration tests preserve existing
custom and update-owned encrypted deliveries. Deadline tests expire a synthetic
request while delivery or replay waits on audit, and retain later device evidence.
The complete Windows PostgreSQL/race suite passes in **130.999 seconds**, with
protocol in **1.426 seconds**. After the final queue-capacity correction, the
focused lifecycle and affected update-queue regression tests pass in **17.055
seconds**. Full console integration and focused Windows handler tests pass in
**12.629 seconds**, and Windows views in **2.994 seconds**. Vet and Linux/Windows
builds pass. Full CI for this request extension is pending. The dedicated console
workflow and physical acceptance remain pending.

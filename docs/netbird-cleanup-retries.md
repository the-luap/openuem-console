# Reviewed NetBird setup-key removal retries

A registration whose first recorded key removal did not establish absence can
now receive another explicitly reviewed removal attempt. This operates on the
exact retained setup-key ID and original encrypted provider snapshot. It never
creates a key, repeats registration, changes a peer, or sends an agent command.
The original registration result remains unconfirmed. Removing a setup key does
not disconnect a peer that already registered with it.

## Review and authority

`ReviewCleanup` requires `ManageDeviceSecurity` in the recorded organization and
site. Before any provider read for a key without retained absence, it locks and
checks the actual current device scope, supported platform, enabled state and
individual enrollment identity/consumer when applicable. A moved, removed,
revoked or expired target cannot acquire a new cleanup attempt. Certificate
renewal invalidates an old review and permits a fresh review under the current
identity. No live agent response is needed for provider cleanup.

Only an unconfirmed registration with retained key identity and a prior DELETE
attempt is eligible. The original encrypted provider origin and credential are
used even if organization settings have changed. Decryption or provider errors
block removal; current settings cannot silently replace the captured account.
The review exposes the original provider URL and key ID, never either secret.

| Fresh provider state | Offered action |
| --- | --- |
| Exact key ID and retained creation policy still match | Confirm one new removal attempt. |
| Exact-ID read confirms absence, not yet retained | Check key removal to retain that evidence; no DELETE. |
| Absence already retained | Review the separate registration resolution. |
| Changed key policy, unavailable provider or missing current authority | No new removal attempt. |

Usage counters and current validity can change after creation and are not
ownership identifiers. The immutable creation policy must still match. Neither
a mutable key name alone nor a reported hostname/IP establishes ownership.

## Durable attempts and evidence

Each confirmed form has a new UUID and the fresh review fingerprint. The
fingerprint includes the original request revision, retained creation metadata,
current device/enrollment generation, observed key state and latest cleanup
attempt. The server rebuilds it before accepting the submission. Concurrent forms
serialize on the original request; a newly admitted attempt invalidates an older
review even when the provider key remains unchanged.

Migration `020_netbird_cleanup_retries.sql` stores immutable attempts with actor,
review revision, key ID, the original cleanup target digest, monotonic sequence
and timestamp. Database guards require the original unresolved registration,
matching creation evidence and first deletion digest, with no retained absence.
Startup checks both insertion and immutability guards. These rows have no
cascading device foreign key and survive device removal.

The attempt and its audit event commit in a separate transaction before one
bounded DELETE. A replay of the same form returns retained state without any
provider call. Another DELETE requires another review and confirmation.

After the DELETE, only a fresh exact-ID GET confirming absence supplies positive
cleanup evidence. A successful DELETE reply alone is insufficient; a failed or
lost reply can still be followed by confirmed absence. Absence and its audit
commit independently, so a later response/audit rollback cannot discard a
completed removal. If the absence audit fails, the attempt still survives and
read-only `ReconcileCleanup` can retain the missing evidence later. Reconciliation,
dispatcher restart and registration resolution never automatically retry DELETE.

Key removal alone does not reopen either NetBird command admission barrier.
[Registration resolution](netbird-registration-resolutions.md) still requires
matching agent execution evidence or confirmation that no delivery was attempted.
The original uncertain outcome and all prior attempts remain unchanged.

## Console

The exact-site registration receipt and resolution pages link to
`GET /registrations/:request/cleanup/review`. The review has an unchecked required
confirmation for one removal attempt. The strict CSRF-protected
`POST /registrations/:request/cleanup/retry` accepts only its retry UUID, review
revision and confirmation fields. Provider origin, token and key identity are
never accepted from the form. Both routes require device-security permission.

Receipts and reviews display the latest cleanup attempt's ID, sequence, actor
and time. Attempt wording remains distinct from retained absence. All earlier
attempts remain in permanent storage. Pending submission disables the confirmation
and button and prevents duplicate HTMX requests.

## Validation

Owned PostgreSQL and TLS fixtures cover committed admission before mutation,
unsuccessful deletion, lost responses, unavailable post-delete reads, audit
rollback before and after mutation, concurrent identical and different forms,
fresh retry sequences, current identity renewal/revocation/expiry/consumer/scope,
original provider snapshots, permanent history and database/startup guards.
The focused race suite passes in 14.729 seconds and the view race suite in
1.939 seconds. Twenty-four browser cases pass at 390, 768 and 1,440 pixels,
including explicit confirmation, exact forms, pending submissions, blocked states
and long content. The full browser matrix passes all 2,367 cases. The complete
inventory PostgreSQL race suite passes in 231.864 seconds and the audit race suite
in 9.230 seconds. Actual registered-route fixtures pass, including permission and
CSRF checks, strict inputs, replay without provider calls, redaction and preserved
registration uncertainty. The full Linux arm64 console build also passes.

No installed NetBird executable, real provider account or physical endpoint is
used. Missing creation responses without retained key identity, authoritative
peer association/deletion, trusted installers and physical/provider acceptance
remain separate work in the full roadmap.

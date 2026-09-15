# Reviewed native NetBird installation in the console

A device's NetBird page links to **Install approved NetBird package** for users
with `software.assign` at its exact organization/site. **Installation history**
requires `software.read`. Organization package approval and permanent revocation
continue to use the [existing approval pages](netbird-package-approvals.md).
All new copy, validation messages and documentation are in English.

## Installation flow

1. Choose an active organization approval matching the device's platform and
   architecture. Pages contain at most 50 packages and expose version, identity,
   format, size, hash and approval ID. Source URLs and organization verification
   notes are never included. A site operator needs no organization-wide software
   rights to choose an already approved package.
2. Review the exact package and device. The existing admission service checks
   current individual enrollment, certificate/consumer, package approval and
   agent preparation/installation readiness. Confirm the possible replacement
   and interruption of the NetBird connection before queuing.
3. The [joined dispatcher](netbird-installation-dispatch.md) performs preparation
   and native admission. The request handler queues intent; it does not run an
   installer or wait for download completion. The original request UUID and
   review revision bind the form and its immutable replay.
4. Open the receipt and use **Reload status** to read retained progress. Status
   distinguishes queued, preparation pending/prepared, native delivery pending,
   stopped, cancelled, unconfirmed, completed and reviewed recovery. Loading a
   receipt or history never contacts the agent or provider.

An active request can be cancelled before any native attempt, including during
preparation. The cancellation has its own immutable UUID and explicit checkbox;
an in-progress download may finish, but the cancelled request cannot enter native
installation. An admitted native attempt has no cancellation or installer retry
button. Stops preserve the shared device barrier until explicit cancellation.

Completed installation proves the exact package at its retained completion time,
not current connection health or fresh inventory. The receipt preserves original
delivery outcomes separately from later receipt observations and recovery proof.
Released history does not claim successful installation or rollback.

## Uncertain outcomes and recovery

**Check retained receipt** performs only the existing current-agent receipt
query for the original command. A matching completed result can confirm completion.
Missing, pending or uncertain evidence does not authorize another installation.

**Review installation recovery** obtains fresh evidence and, when eligible, an
expiring review of permanent withdrawal or explicit journal release. Confirmation
binds the original installation revision, the expiring recovery review and the
permanent recovery ID. Additional recovery controls require another explicit
review and confirmation; they do not resend an installer. **Reconcile recovery
evidence** queries the exact owned receipt without sending another control.

Waiting, conflicting, completed, released and awaiting-confirmation reviews offer
no new mutation. See [withdrawal and release](netbird-installation-resolutions.md)
for the receipt, journal and immutable control requirements.

## Routes and retained reads

All routes below are relative to
`/tenant/:tenant/site/:site/computers/:uuid/netbird/installations`.

| Method | Suffix | Capability | Effect |
| --- | --- | --- | --- |
| GET | empty | `software.read` | Retained history, 20 requests per page |
| GET | `/new` | `software.assign` | Matching approved package choices |
| GET | `/review` | `software.assign` | Exact package and current device review |
| POST | empty | `software.assign` | Confirm reviewed request |
| GET | `/:request` | `software.read` | Coherent retained status |
| POST | `/:request/cancel` | `software.assign` | Confirm pre-native cancellation |
| POST | `/:request/observe` | `software.assign` | Read-only agent receipt observation |
| GET | `/:request/resolution` | `software.assign` | Fresh recovery review |
| POST | `/:request/resolution` | `software.assign` | Confirm reviewed recovery control |
| POST | `/:request/resolution/reconcile` | `software.assign` | Read-only owned recovery proof |

`Status` and `History` read package metadata and preparation/delivery/stop/recovery
records with the parent installation row locked for a coherent snapshot. Reads
remain available under the original scope after package revocation or changes to
current device authority. Cursors belong to the original scope and device;
package choice cursors additionally match platform and architecture. Revoking a
last-row package does not invalidate continuation of its immutable cursor.

The central route capability map and storage transactions both enforce rights.
Routes use `Cache-Control: no-store`, authenticated sessions and production CSRF.
POST forms accept only their exact fields, reject duplicate or unknown values,
query-string input and absent confirmation, and enforce an 8 KiB wire limit before
token extraction. No source, certificate, command envelope or transport diagnostic
is placed in a form or retained HTML receipt. Existing legacy install/uninstall
routes remain unavailable.

## Validation and remaining platform work

Owned PostgreSQL tests cover scoped matching, both pagination boundaries,
revocation, history without current device authority, coherent released/original
uncertain evidence, registered HTTP routes, confirmation, CSRF and exact replay.
The browser suite adds 90 cases across 390, 768 and 1440 pixels, including keyboard
confirmation, duplicate-submit suppression, pending state, long metadata, viewer
access, terminal receipts and recovery eligibility. Fixtures execute no vendor
installer, daemon, external provider or physical device.

The complete inventory PostgreSQL race suite passes in 488.699 seconds and
the focused new read/pagination suite in 6.263 seconds. All 2,562 browser cases
and the complete rendered-view race suite pass, as do the owned audit
(10.250 seconds) and CSRF middleware race tests, registered console routes with
PostgreSQL and the full Linux ARM64 console build. Native forms and HTMX both
retain exact reviewed intent; unknown-length padded POSTs are rejected before
form normalization.

The current individual enrollment registry supports Windows and macOS. Linux
choices fail current enrollment admission until Linux identity enrollment and
independent publisher trust are implemented. Local NetBird removal and physical
installation, upgrade, interruption and reboot acceptance remain separate work.

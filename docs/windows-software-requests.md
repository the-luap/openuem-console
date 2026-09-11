# Windows software requests and explicit dispatch

Open an approved Windows revision and select **Windows device requests**. An
operator can select an individually enrolled Windows endpoint, choose installation
or removal, and explicitly confirm the exact revision and operation. Readers can
inspect the scoped history. Preparation does not download an artifact, run an
installer, remove an application or establish installed state. For an approved
AMD64/ARM64 MSI or EXE, select **Review execution**, inspect the exact device,
revision, operation and deadline, then confirm **Dispatch to this device**.

Preparations remain inert, including rows created before the dispatch migration.
Only the separate review and confirmed POST can atomically create a signed,
encrypted individual-agent task and mark its preparation `dispatched`. The worker
never consumes preparation rows. WinGet coordinates still require immutable
installer resolution; x86 delivery remains unavailable.

## Admission and lifetime

Preparation requires current `ReadSoftware`, `ReadDevices` and `AssignSoftware`
rights in the requested scope and in the target's actual site. The transaction
locks the active individual Windows identity and site ownership, then its
inventory record and all inventory site edges. The endpoint must have exactly
one inventory site, matching its enrollment scope, and must have passed initial
admission and remain enabled (including an enabled endpoint with no recent
contact). Disabled endpoints cannot receive a preparation. It also locks the approved catalog revision against withdrawal.

The saved intent includes the immutable revision, installation/removal operation,
individual agent UUID, certificate-generation digest, original organization/site,
actor, request UUID and deadline. Native architecture must match the enrolled
agent architecture. The current individual enrollment supports AMD64 and ARM64;
catalog x86 approvals therefore have no eligible individual endpoint yet. The
selector does not claim that an inventory report establishes the required Windows
build or installed product. Those need operation-bound native checks before
execution.

Only one preparation can remain open on an endpoint across all catalog packages.
This conservative reservation also covers two catalog identifiers referring to
the same MSI product or uninstall registration. Concurrent different requests
produce one winner. Concurrent exact retries by the original actor return the
original request, without extending its lifetime or duplicating its audit.
Changed intent or another actor conflicts. Replays require current permissions;
they return historical cancelled/expired intent without restoring it or rebinding
it to a renewed certificate.

A preparation lasts at most one hour, capped by the current certificate expiry.
The transaction rechecks time after audit insertion. Read pages derive expiry
from the saved deadline, including when no service ran across that deadline.
Preparing new work closes and audits expired reservations in the same transaction.
Cancellation requires current rights in the original site and works for an
unsent preparation even if the device was subsequently revoked or moved.
Terminal history and assignment intent cannot be updated, deleted or truncated.
A dispatched preparation retains its immutable link to exactly one registry task.

## Dispatch admission and outcomes

Review requires current software/device read and assignment rights. It locks the
current identity and registered software recipient, enabled inventory and its
sole site, preparation, and approved revision in the worker's lock order. The
original certificate generation must still match. The review hash binds the
actor, original scope, device, preparation, immutable revision, operation,
certificate/recipient generation, decrypted canonical plan and original deadline.
The POST repeats every check; changing rights, inventory, approval, recipient or
identity invalidates admission. A GET only records a read audit.

MSI removal uses only the approved product/detection rule. EXE removal uses its
separately approved HTTPS artifact, digest and literal arguments. Private values
are decrypted only inside the trusted transaction and sealed for the endpoint's
registered recipient. Public and encrypted revision metadata must agree.

The signed task, immutable dispatch link, preparation transition and both audit
records commit together. Audit failure or identity/deadline expiry rolls back
admission. Deferred database constraints reject a link without its preparation
transition. Concurrent confirmations admit one task; exact retries by the same
actor return its existing state without resending, extending the deadline or
re-admitting a changed identity. Current original-scope permissions still apply
to historical retries.

The agent validates the envelope, stages and verifies its artifact, checks native
compatibility and exact before/after software state, and journals its signed
result. **Queued** and **Delivered** do not establish installation or removal.
History displays verified outcome observations, normalized failure reasons and
exit codes. An observed target is distinct from a rejected start, installer
failure, restart requirement or uncertainty. Restart and uncertain work keep the
device reservation; automatic retries cannot assume the installer stopped.

**Cancel queued operation** works only before delivery. It locks the original
identity before the task, so cancellation and worker delivery cannot both win.
It still works after inventory moves or identity revocation, with current rights
in the original site. Delivered work cannot be cancelled or restored to an unsent
preparation. Repeating a completed cancellation does not duplicate its audit.
History remains in the original scope and verifies retained task/receipt
signatures, including their certificate chain, without exposing private payloads.

## Read-only reconciliation after uncertainty or a required restart

Open **Software checks and restart evidence** in dispatch history. For a delivered
operation that is uncertain or requires a restart, an operator can select
**Review software check**, review the original device, operation, exact detection
expectation and deadline, then confirm **Check software state**. This separate
request authorizes only reading the original machine state. It neither installs
software nor initiates a restart. A withdrawn revision remains observable.

Review and confirmation require current software/device read and assignment
rights in the original site, an enabled Windows endpoint in that same sole site,
and its current individual identity. The review binds the actor, original signed
task, current certificate, exact scope and a separate deadline (normally fifteen
minutes, capped by certificate expiry). Changed authority or evidence invalidates
confirmation. Only one live check for the original operation can be admitted.
Its signed task, immutable console review link and audits commit together; failed
audits or expiry roll everything back. Exact retries return the same task without
extending its lifetime or re-admitting a changed endpoint.

The joined Windows service compares protected admission evidence with its current
native boot session. A service restart, resumed kernel session or changed boot
evidence around observation cannot establish a completed restart. Only a proven
later kernel boot and an exact native observation can produce a definite result.
The agent preserves the signed receipt before transmission and its acknowledgement
before allowing another executable task. It can resubmit an already signed receipt
after expiry or certificate renewal using fresh current-certificate proof.

| Check result | Meaning and reservation |
| --- | --- |
| Observed | Exact expected version or removal absence was read after a later boot; verified evidence releases the original reservation. |
| Drifted | Exact state differs from the original expectation after a later boot; verified evidence releases the reservation without claiming the original installer succeeded. |
| Waiting for boot | No later kernel boot is established; no package query runs and the reservation remains. |
| Unknown | The bounded native query failed or returned unusable output; the reservation remains. |
| Unavailable | Original admission or reliable boot evidence is unavailable; the reservation remains. |

History keeps original execution evidence separate from subsequent checks and
explicitly records which check released its reservation. It never changes an
uncertain installer outcome into success. Release permits a newly reviewed,
explicit execution request; it does not retry the original installer. Pending
checks can be cancelled with confirmation, including after an inventory move or
revocation when the operator retains original-site rights. Delivered checks cannot
be cancelled. Expired or inconclusive checks permit another explicit review while
the original reservation remains. Readers can inspect the verified history, with
50-entry scoped pagination, without mutation controls. Boot counters, nonces,
certificates and private installer data are not rendered.

## Forms, privacy and history

All routes are registered under the existing administrator,
organization and site console prefixes:

- `GET /software/catalog/:version/windows-requests`
- `POST /software/catalog/:version/windows-requests`
- `POST /software/catalog/:version/windows-requests/:request/cancel`
- `GET /software/catalog/:version/windows-requests/:request/dispatch`
- `POST /software/catalog/:version/windows-requests/:request/dispatch`
- `POST /software/catalog/:version/windows-requests/:request/dispatch/cancel`
- `GET /software/catalog/:version/windows-requests/:request/dispatch/reconcile`
- `POST /software/catalog/:version/windows-requests/:request/dispatch/reconcile`
- `GET /software/catalog/:version/windows-requests/:request/dispatch/reconciliations`
- `POST /software/catalog/:version/windows-requests/:request/dispatch/reconciliations/:reconciliation/cancel`

POST bodies are limited to 8 KiB before CSRF parsing. They accept only unambiguous
body fields, the CSRF token and explicit confirmation. Query parameters cannot
alter mutation intent. The middleware rejects an oversized body before admission.

Source URLs, installer arguments and property values remain in the encrypted
immutable catalog revision. Preparation stores no plaintext copy or broker
payload. Pages expose neither certificate digests nor execution parameters.
Read audits must commit before target or history data is returned. Mutation,
expiry and read events retain their original scope in the existing shared
catalog audit source.

Targets and request history each use a 50-row page, backed by bounded 51-row
queries. Device search treats percent signs, underscores and backslashes
literally. Independent cursors preserve the search and other section's page.
Request history remains in its original site after a device moves; a foreign
site cursor cannot reveal that history.

## Verification and remaining work

Owned PostgreSQL fixtures exercise real individual certificate enrollment,
concurrent exact/different requests, native-identity aliases, scope and platform
changes, inventory ambiguity, withdrawal, revoked rights, audit rollback,
certificate expiry after audit, expired reservations, immutable history and
pagination. Console tests use the real Ent schema, scoped router, sessions and
CSRF middleware. Browser checks cover six preparation states, twelve dispatch
states and fourteen read-only check states at
390/768/1440 pixels, including keyboard review/cancellation, exact device and
revision fields, paging, reader restrictions and overflow. Dispatch tests cover
four MSI/EXE install/remove plans, actual recipient registration, encrypted task
decryption, signed outcomes, concurrent retries, stale reviews, atomic audit
rollback, historical migration and cancellation. No package is downloaded or
executed in these console tests. Reconciliation tests use actual signed tasks and
results for all five outcomes, concurrent exact and competing confirmations,
current identity/permission changes, atomic review/result audit failures, expired
certificates, immutable original receipts, cancellation and bounded history. Route
tests exercise the complete review/queue/report/history path and strict form/CSRF
boundaries. The browser suite passes all 270 cases, including the 42 check cases.

WIN-01 remains in progress. Immutable WinGet manifest resolution and physical
install/remove, offline, restart and hibernate acceptance remain required. The
reconciliation tests use synthetic boot evidence; they do not reboot a physical
endpoint. Native staging, installation/removal and durable agent receipts have
separate agent tests, including owned synthetic Windows MSI execution. See
[approved Windows software](windows-approved-software.md) and the unchanged
[full roadmap](fehlende-funktionen-und-roadmap.md).

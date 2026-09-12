# Native Windows CSP commands and results

The Windows store now connects administrative command intent to the
[authenticated SyncML session](native-windows-sessions.md). It compiles bounded
custom CSP operations, persists a scoped encrypted queue, delivers eligible work
after mutual authentication and the DevId probe, and records correlated device
statuses and Get results. All local device exchanges use synthetic fixtures.
The [typed update extension](native-windows-updates.md) adds an operator-authorized
preflight/configuration/read-back workflow on this service. The optional
[listener/gateway integration](native-windows-operations.md) registers its device
transport. The [CSP console](native-windows-csp-console.md) provides protected
history/results, undelivered custom-command cancellation and explicit resolution
of uncertain effects. Its bounded JSON editor now reviews complete custom trees
through the shared compiler before confirmed admission. Physical Windows
acceptance remains open.

## Administrative command boundary

`EnqueueCSPCommand` accepts one `CSPCommandSpec`, an explicit organization/site and
device, a caller-generated request UUID, and a delivery lifetime. The new
`windows.csp.manage` capability belongs to organization and server administrators.
It is required for all custom operations, including Get, payload reads, metadata
lists, cancellation and abandonment. A custom Get can expose protected CSP data;
ordinary inventory permissions do not grant arbitrary node access.

The compiler supports Get, Add, Replace, Delete, Exec, Atomic and Sequence. Every
leaf has exactly one target. Values have explicit canonical string, signed
32-bit integer, Boolean, padded base64, XML, null or interior-node formats where
the operation permits them. XML markup must be self-contained; CSPs that expect
an XML string use escaped string data. Optional MIME values have no parameters.
The storage envelope is private and is never sent directly to a device.

Targets use canonical `./Device/Vendor/MSFT/...` or `./User/Vendor/MSFT/...` paths.
DevInfo and DevDetail are Get-only. External URLs, traversal, wildcards, property
queries, ambiguous escapes and enrollment/transport roots DMClient, DMAcc,
Enrollment and Provisioning are rejected. These exclusions protect those roots;
custom CSP access still grants broad device configuration authority. The caller
must deliberately select the intended operation and payload.

Atomic groups reject nested Atomic, Get descendants, and Add followed by Replace
on the same node. Directly nested Sequence is rejected. These restrictions follow
[Windows OMA DM protocol support](https://learn.microsoft.com/en-us/windows/client-management/oma-dm-protocol-support).
The generic compiler validates transport structure and value representation. It
does not assert that a particular CSP exists, supports the requested operation,
or is available on the device's Windows version and edition. Typed policy
catalogs must supply those checks before exposing guided workflows.

## Queue, eligibility and delivery

The request UUID makes enqueue idempotent only for the same device, creator,
current creator permission revision, lifetime and canonical payload. A conflicting
reuse fails; a completed request never becomes new work. Each request has a random
encrypted salt for its digest, preventing equality comparison or dictionary
recovery of low-entropy settings from database metadata.

The immutable request and latest result use separate AEAD purposes bound to
command/device identity, organization/site, creator and permission revision,
request identity/digest, timestamps, and delivery/result metadata. Mutable result
ciphertext also binds the row revision and phase. Metadata lists authenticate
the stored request/result before reporting a phase. Public payload DTOs omit their
contents from ordinary JSON/XML serialization and formatted diagnostics.

Queue ordering is per device, by creation time and UUID. An unresolved sent or
unknown command prevents another delivery. The next eligible command is appended
only after authenticated initialization and a successful correlated DevId probe.
Its actual command IDs include the server session UUID and dispatch message ID;
group and leaf IDs retain their tree relationships.

Before initial delivery or exact packet replay, the store checks the creator's
current capability and original permission revision. Changed authority retires
queued intent and denies replay of an already sent payload. It does not discard
subsequent authenticated evidence from an operation that may already have run.
Database deadlines are checked after lock/audit waits and before response commit.
Expiry prevents delivery; late evidence within a still-valid session is retained.

A user target requires Full enrollment and the enrolled-user login status `user`.
An ineligible user context, insufficient client MaxMsgSize, or insufficient
MaxObjSize leaves the command blocked with a protected reason. It keeps its queue
position and may become eligible in a subsequent session. Outgoing object
chunking is not implemented: the complete command tree must fit one negotiated
response. Oversized groups are never partly sent.

## Result meaning and uncertain effects

| Phase | Meaning |
| --- | --- |
| queued / blocked | No delivery was committed; blocked includes an eligibility reason |
| sent | Delivery was committed; required status or result evidence is outstanding |
| acknowledged | All operations have acceptable final statuses; every Get has a complete result |
| failed | Complete status evidence includes a reported failure; other operations may have succeeded |
| unknown | Asynchronous acceptance, failed rollback, abort, expiry or incomplete evidence leaves effects uncertain |
| abandoned | An administrator recorded a resolution note and released an uncertain command's queue barrier |
| canceled / expired | Undelivered intent was retired |

Status 200 is accepted; Add may also return 201. Status 202 is asynchronous
acceptance. Status 516 reports failed rollback and remains unknown. A successful
Atomic rollback status does not imply that the requested changes were applied.
Parent and child statuses are kept separately. An acknowledged custom command
does not prove compliance: configuration intent and effective read-back values
are distinct, as described by the
[Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-configuration-service-provider).

Statuses and results must reference the actual dispatch message/command and
expected node. Conflicting or duplicate evidence within one message is rejected.
The documented device-prefix omission in a result URI is accepted; user targets
remain distinct. A final status cannot be replaced by a different status, while
202 can advance to a final status in the same active session. A command may finish
before the device's package ends; later protocol housekeeping preserves its
immutable outcome. Once the session has ended, asynchronous verification needs
a separate future workflow.

Get objects can arrive in contiguous chunks. The first chunk declares the total
object byte size on the Item, intermediate chunks receive 213, and the final
size must match. Mismatch returns 424; interrupted objects produce alert 1225.
Partial values remain encrypted and are withheld from `CSPCommandDetails`.
The base64 receiver assembles one continuous encoded stream and checks the
decoded byte count, with padding only at the end. This implementation convention
still needs Windows device interoperability acceptance. Size and package rules
are based on [OMA DM Protocol 1.2.1, sections 6–7](https://www.openmobilealliance.org/release/DM/V1_2_1-20080617-A/OMA-TS-DM_Protocol-V1_2_1-20080617-A.pdf)
and [SyncML MetaInfo, section 5.2.16](https://www.openmobilealliance.org/release/Common/v1_2-20050509-C/OMA-TS-SyncML_MetaInfo-V1_2-20050509-C.pdf).

`CancelCSPCommand` requires the expected revision and undelivered intent.
`AbandonCSPCommand` requires current administrative scope, the expected revision,
an unknown outcome and a nonempty resolution note. Abandonment neither undoes an
operation nor retries it nor marks it successful. No automatic resend follows
uncertainty. Exact delivery replay is allowed only while the command remains
sent, authorized and within its deadline; final receipt packets remain replayable
under the session's existing identity, lifetime and nonce rules.

## Persistence and limits

Migration 005 adds scoped command, observation and audit tables. SQL triggers
protect immutable intent, delivery identity, terminal outcomes and append-only
history. Each encrypted observation binds the exact request digest and references
the actual saved session packet through a deferred foreign key. Request, result,
session, packet and audit changes commit together before response bytes escape.
Failed audit, invalid evidence, cancellation and expiry roll back the transaction.

| Boundary | Limit |
| --- | --- |
| Command tree | 32 group/leaf commands, depth 4 |
| Encoded private request envelope | 128 KiB |
| Aggregate accepted Get data | 256 KiB |
| Protected request, result or session JSON | 2 MiB each |
| Unresolved queue entries per device | 256 |
| Expired/unauthorized entries skipped per exchange | 32 |
| Delivery lifetime | 1 minute through 7 days, whole seconds |
| Metadata list page | 1–100 entries; offset at most 100,000 |
| Observation history page | 10 visible entries; 11 authenticated snapshots per call; offset at most 64 |
| Resolution note | 320 UTF-8 bytes, no surrounding whitespace or control characters |

`CSPCommandDetails` provides an audited current request/result read. Results and
original device errors are untrusted content; console views escape them as text.
The console shows the original request and latest correlated result, with a
separate [observation history](native-windows-csp-console.md#review-the-observation-history)
for immutable earlier snapshots. List and single-message reads authenticate the
existing encrypted history, preserve partial/completed distinctions and require
current scoped authority plus audit. [Audited JSON exports](native-windows-csp-export.md) now preserve original intent,
current results and all or selected historical snapshots. Retention remains work.

## Verification and remaining work

Portable tests cover canonical targets/types, group restrictions, redaction,
chunk accounting and outcomes. Owned PostgreSQL tests cover authenticated group
delivery, eight concurrent exact replays, durable chunk restart, failed/partial
objects, user/size eligibility, late package end, asynchronous evidence,
aborted/expired sessions, uncertain-queue release, changed creator revisions,
deadline waits, audit rollback, immutable history and upgrade of existing sessions.
A real loopback TLS exchange delivers a synthetic CSP operation and commits its
result; resumed TLS rejects completed-payload replay and revoked certificates.
Compiler and structured result-transition fuzz targets run in CI alongside the
full package race tests and native Windows portable tests.

The final local PostgreSQL 17/race suite passes in **49.024 seconds**, with
**86.4%** Windows package statement coverage. The compiler fuzz run passes after
**622,469 executions** and the structured result-transition run after
**21,261 executions**, each with a 30-second budget. Vet, formatting, whitespace
and local documentation-target checks pass. Both complete workflows pass for CSP
commit `a03800e`
([push](https://github.com/the-luap/openuem-console/actions/runs/34412236916),
[pull request](https://github.com/the-luap/openuem-console/actions/runs/34412241887)).
The subsequent typed update extension records its own evidence separately.

```sh
go test -race -count=1 -timeout=3m ./internal/mdm/windows ./internal/security/access
go test -run '^$' -fuzz='^FuzzCSPCompiler$' -fuzztime=30s -parallel=2 ./internal/mdm/windows
go test -run '^$' -fuzz='^FuzzCSPResultTransition$' -fuzztime=30s -parallel=2 ./internal/mdm/windows
```

Use the [reserved PostgreSQL fixture](native-windows-mdm.md#scoped-enrollment-credentials).
No test executes a command, installs a profile/certificate or changes host settings.
The typed update extension adds selected update policies and verified read-back.
The [enrollment/device console](native-windows-console.md) provides CA setup,
one-time credentials, scoped inventory and native access revocation.
Remaining WIN-02 work includes broader typed configuration policies, automatic
ring promotion, outgoing large-object chunking,
renewal/unenrollment, rotation/recovery,
Entra/Autopilot and physical device acceptance.

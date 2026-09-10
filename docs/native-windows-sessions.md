# Native Windows authenticated SyncML sessions

`NewSyncMLHandler` connects [the XML codec](native-windows-syncml.md),
[direct TLS identity](native-windows-management.md) and the encrypted credentials
created by [WSTEP enrollment](native-windows-enrollment.md). It persists an
authenticated exchange and an initial read-only `Get ./DevInfo/DevId` probe.
The optional [listener/gateway integration](native-windows-operations.md)
registers this service with direct or pinned gateway TLS. The
[enrollment/device console](native-windows-console.md) adds scoped administration;
command/update views remain open.
The [CSP command extension](native-windows-csp.md) adds administrative queues and
correlated results. The [typed update extension](native-windows-updates.md) adds
platform preflight and separate effective-policy read-back. Broader policies,
automatic ring promotion, certificate renewal and unenrollment remain open. WIN-02 remains
in progress.

## HTTP and authorization

The handler accepts POST at the configured HTTPS host and path, with a completed
TLS 1.2 or 1.3 handshake and the enrolled client leaf certificate, resolved from
direct TLS or the explicitly pinned gateway. It
requires `application/vnd.syncml.dm+xml`, optionally with `charset=utf-8`.
Encoded path aliases, queries, redirects, other content parameters, content
encoding and WBXML are rejected. The owner must configure TLS client certificate
requests, admission limits and HTTP header/read/write timeouts.

Each request reparses its actual certificate DER and authorizes current device,
certificate, organization/site and enrollment configuration inside the same
transaction as session processing. Scope and revocation locks remain held through
response and audit persistence. Database time rechecks session, certificate and
root expiry after lock waits and immediately before commit. A previously returned
public identity snapshot, TLS resumption or forwarded certificate header cannot
replace these checks.

The original encrypted bootstrap is opened using its enrollment-bound purpose.
Management never needs to decrypt the CA private key. A master encryption key is
required; wrong keys and unauthenticated ciphertext fail without response bytes.
HTTP errors have empty, fixed-length bodies, without SQL details or supplied
device data. Successful responses have an explicit content length and XML MIME
type. All responses use `no-store`, `no-cache` and `nosniff` headers.

## Exchange and credential transitions

The first message starts with message ID `1`. Subsequent IDs increase by one.
The source URI is frozen for that server session, the target must match the
configured management service, and a supplied target name must match the provider
ID. A device-supplied response URI is rejected. These strings are never fetched
or used to assign identity or scope.

Digest credentials use the server-assigned device UUID and the per-device client
secret. Missing or incorrect proof receives a bounded `407` or `401` challenge.
That response contains statuses only and stores no unauthenticated DevInfo.
One fresh client challenge and one server challenge are allowed per session.
The server supplies its own provider-ID/server-secret digest until the client
accepts it for the session.

Status `212` accepts credentials for the remainder of the session; a supplied
next nonce applies to the next session. Status `200` can require another proof
with a new nonce in the following message. Client and server directions maintain
separate encrypted nonce state. Authentication retries retain the wire session
ID and advance the message ID. These rules follow
[OMA DM Protocol 1.2.1, sections 8–9](https://www.openmobilealliance.org/release/DM/V1_2_1-20080617-A/OMA-TS-DM_Protocol-V1_2_1-20080617-A.pdf)
and [Windows OMA DM protocol support](https://learn.microsoft.com/en-us/windows/client-management/oma-dm-protocol-support).

Authenticated initialization accepts the five standard DevInfo nodes: DevId,
manufacturer, model, DM version and language. A Microsoft login-status alert is
acknowledged as a hint; it grants no account or administrative scope. The service
then sends the DevId probe to obtain an actual subsequent server-authentication
status and correlated command result. Results must reference the dispatched
message and command, identify the expected node and match the initial DevId.
Duplicate or conflicting references are rejected. A command ID includes the
server session UUID, preventing results from a previous use of a wire session ID
from acknowledging a new probe.

Bounded text objects can arrive in contiguous chunks. The first chunk declares
the total byte size, intermediate chunks receive `213`, and only an exact final
size can complete the object. A size mismatch reports `424`; interrupted objects
report alert `1225` and terminate this exchange. Requests for further messages use
alert `1222` without Final. The large-object and package rules come from
[OMA DM Protocol 1.2.1, sections 6–7](https://www.openmobilealliance.org/release/DM/V1_2_1-20080617-A/OMA-TS-DM_Protocol-V1_2_1-20080617-A.pdf).
DevInfo initialization and the identity probe retain their 4,096-byte limit.
The CSP extension provides its own bounded Get result receiver.

An exchange can finish with a successful result, a device-reported probe error,
an abort or a failure. `completed` describes protocol completion. It does not
mean a policy was applied or a failed probe succeeded: the protected probe status
and result remain separate. Other device-originated mutations receive rejection
statuses and are never executed. Unenrollment alerts are not acknowledged as
completed unenrollment.

## Persistence and replay

Migration `004_syncml_sessions.sql` adds scoped device nonce state, server
sessions, packet history and management audit. Composite foreign keys bind
sessions and their active pointer to the exact device, certificate and site.
Identity columns cannot change, revisions must advance, terminal sessions cannot
resume, and packet/audit rows are append-only. Migration does not replace existing
invitations, CAs, device certificates or provisioning.

AES-GCM protects nonce state, session data and exact response bytes. Associated
data binds scope, device, certificate, CA, certificate fingerprint, configuration,
server session identity and relevant revision/timestamps. Stored responses also
bind the message ID and SHA-256 request/response digests. DevInfo, source hints,
nonces, credential material and XML bodies are not plaintext database columns or
audit fields. Diagnostic formatting redacts protected state.

Concurrent requests serialize on the device state row. An exact retry in the
current session returns the persisted bytes and records a replay event without
rotating a nonce or generating another command. A different body with an already
used message ID conflicts. Replays still require live TLS identity, scope and an
unexpired session. A reused wire session ID with different initial bytes requires
the current next-session digest and a terminal or expired predecessor. An active
exchange cannot be displaced by a different wire session. Old server sessions
cannot become the current replay source again.

State, packet and audit writes commit together before any bytes are returned.
Audit errors, cancellation, expiry during a lock wait, invalid results and response
size failures leave the prior exchange intact. An expired active session can be
closed while a new session is created in the same transaction.

| Boundary | Current limit |
| --- | --- |
| Request or encoded response | 1 MiB, plus the independent XML codec limits |
| Response size | Client MaxMsgSize, capped at 1 MiB; 5,000 bytes if omitted |
| Accepted DevInfo object | 4,096 bytes |
| Advertised MaxObjSize | 256 KiB for the CSP Get result receiver |
| Session | 64 client messages, at most 15 minutes, no later than certificate expiry |
| Protected session JSON | 2 MiB |
| Authentication resynchronization | One challenge in each direction per session |

The default response size and session budgets are OpenUEM policies, not claims
that the protocol requires those values. Lifetime does not automatically delete
immutable history. Retention, recovery and key rotation need an explicit future
administrative lifecycle.

## Verification and remaining work

Portable tests cover successful and challenged authentication, next-session and
next-message nonces, server proof, command correlation, chunk assembly and errors,
abort, failed probes and message limits. Isolated PostgreSQL tests cover eight
concurrent identical requests, process restart, challenge recovery, wire-ID reuse,
scope constraints, immutable history, ciphertext corruption and rollback during
audit/cancellation/expiry waits. A real loopback TLS 1.2 exchange uses the issued
test client key, verifies fixed HTTP framing and rejects a revoked certificate on
a resumed connection. Portable request-state tests also cover TLS 1.3.

The final combined PostgreSQL 17/race suite passes in **33.144 seconds**, at
**89.4%** package statement coverage. The final 30-second transition fuzz run
passes after **325,599 executions**. Vet, formatting, whitespace and local
documentation-link checks also pass. CI includes the transition fuzz target, portable native
Windows checks and Linux PostgreSQL/TLS/race tests. Both complete workflows pass
for session commit `2c3c2ad`
([push](https://github.com/the-luap/openuem-console/actions/runs/34407599355),
[pull request](https://github.com/the-luap/openuem-console/actions/runs/34407601208)).
The subsequent CSP extension records its own evidence separately.

```sh
go test -race -count=1 -timeout=3m ./internal/mdm/windows
go test -run '^$' -fuzz='^FuzzSyncMLSessionTransition$' -fuzztime=30s -parallel=2 ./internal/mdm/windows
```

Use the [reserved PostgreSQL fixture](native-windows-mdm.md#scoped-enrollment-credentials).
All certificates and device messages are synthetic; no Windows profile or
certificate has been installed on the host. No physical Windows device has
completed acceptance. The CSP extension adds scoped queues and audited result
reads. Remaining work includes command/result views, broader configuration/update
policies, renewal/unenrollment, recovery, Entra/Autopilot and hardware acceptance.

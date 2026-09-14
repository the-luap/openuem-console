# Durable console NetBird package preparation

`inventory.NewNetbirdInstallationPreparationStore` connects an existing reviewed
installation request to one authenticated agent preparation RPC. Its `Prepare`
method retains the exact attempt before network delivery and appends a correlated
result afterwards. `ReadPreparation` exposes scoped, source-free history. This is
a backend component: no route or dispatcher starts it automatically, and no
native installation command is sent.

## Current admission and capability

Preparation requires current `software.assign` for the exact organization/site,
the original request actor and reviewed revision. Admission locks the installation
request and rechecks the encrypted approval, permanent revocation, individual
identity/certificate, active command consumer, native target, membership and device
generation. The complete source fingerprint must still equal the original review.
An absent NetBird client remains a supported target.

The constructor uses fresh `preparation-state` and `installation-state` controls.
Both must correlate with their exact kind, UUID and current recipient and report
the same ready journal state. Ordinary or registration readiness is insufficient.
The existing storage-only constructor cannot deliver a preparation. Linux still
needs individual enrollment and independent publisher verification; Windows keeps
its separate software workflow.

The request binds the exact private approved descriptor, original installation
UUID, reviewed revision, journal revision, current individual certificate and
issue/expiry times. Database time fixes the issue timestamp before digesting it;
expiry cannot exceed the original request or certificate. The original source
remains only in its existing encrypted approval envelope. Migration
`025_netbird_preparations.sql` adds immutable attempt metadata: wire version,
certificate hash, complete request hash and exact timestamps. Together with the
immutable installation request and encrypted approval, these fields can reproduce
and validate the original request bytes for subsequent native admission.

## One delivery without long database locks

The attempt and audit commit in one short transaction. Only then does
`Prepare` invoke its publisher. The five-minute RPC deadline also respects the
request expiry and caller cancellation. No database connection, approval lock,
identity lock or authorization transaction is retained across the download.
Cancelling the local wait cannot retract an already delivered preparation; the
agent retains its own download deadline and bounded cache cleanup.
Revocation and pre-install cancellation can therefore finish while preparation
is in flight. An attempt that lost its caller or server process is never treated
as permission to send another request.

`Handler.PublishNetbirdPreparation` sends the strict envelope directly to
`agent.netbird.prepare.<device UUID>`. It validates identity/lifetime, bounds the
call and accepts only a strict response matching the complete request digest.
It creates no stream record, retry or legacy installer message. An empty reply,
unknown field, malformed envelope or different recipient/hash cannot establish
preparation. The transport returns neutral errors without package source or agent
diagnostics.

The store appends `prepared`, `blocked`, `conflict` or `unavailable` only from a
matching response. Missing, invalid, cancelled or expired replies become
`unconfirmed`. The result and its audit commit together under a separate bounded
transaction, including after caller cancellation. An audit/storage failure keeps
the committed attempt without a result. Exact repeat calls read `pending` or the
retained result, without another capability query, download or native invocation.
Current assignment permission is still required for that repeat; scoped history
reads require `software.read` and do not reveal certificate hashes or source URLs.

Database guards reject attempts after cancellation/expiry or changed approval and
recipient authority, prohibit attempt/result rewrites and deletion, and require
source-free response JSON to match the exact retained identity and hash. Startup
verifies the presence and activation of every new guard.

## Cancellation and native installation boundary

Preparation downloads and inspects a package; it cannot authorize installation.
Cancellation may therefore finish before or during preparation. A later reply
remains historical evidence and never clears cancellation. The agent may retain
that old prepared artifact until its bounded cache expiry; a new UUID cannot
silently replace it. A `prepared` database row does not prove that the cache still
exists, that the device has not restarted, or that approval/assignment is current.

The next native-delivery stage must lock the request again, reject cancellation,
recheck current actor/approval/recipient/journal authority, reconstruct and verify
the exact preparation digest and its lifetime, then durably admit a fresh
version-three command before sending it. Its issue time must not precede the
preparation. Native command attempts must also extend the cancellation guard;
uncertain installation requires retained receipts and explicit recovery, not
pre-delivery cancellation. The existing connection/registration publisher still
rejects version three. Native command dispatch, lifecycle UI and local removal
remain separate integration work.

## Verification

Owned PostgreSQL tests cover digest/timestamp retention before RPC, current
approval and permissions, both capabilities, changed recipient/consumer/journal,
concurrent replay, cancellation and revocation during download, exact private
history, expiration, malformed replies, caller cancellation, audit rollback,
permanent SQL evidence and startup guard verification. A duplicate during a held
RPC returns the committed pending attempt without waiting for that RPC or sending
another one. Owned NATS tests cover exact response correlation, loss, malformed
messages, cancellation and absence of preparation stream records. No package is
downloaded and no NetBird installer, daemon or provider is executed by these tests.

The focused preparation PostgreSQL race suite passes in 29.040 seconds. The full
inventory and audit race suites pass, as do the registered console route fixture,
compiled owned NATS publisher tests and complete Linux ARM64 console build.
The CI inventory, audit and handler package suites include these new tests.
The shared runtime contract remains pinned to
`v0.11.1-0.20260914054338-0060dbf7d6a4`; this console change adds no wire fields,
agent process, broker permission or automatic native command dispatch.

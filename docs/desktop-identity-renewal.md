# Individual desktop identity renewal

The console pins shared registry commit
[`e0d6829`](https://github.com/the-luap/openuem-nats/commit/e0d68290a50e74b4caefd2b64afadbcd9fa0433d),
which implements persistent renewal preparation and candidate confirmation while
preserving device ID and organization/site. Its
[protocol and lifecycle documentation](https://github.com/the-luap/openuem-nats/blob/e0d68290a50e74b4caefd2b64afadbcd9fa0433d/enrollment/identity-renewal.md)
defines proof domains, expiry bounds, permanent key ownership and retry behavior.
The [shared-library CI](https://github.com/the-luap/openuem-nats/actions/runs/34469009791)
passes native Windows checks and Linux/PostgreSQL/race/fuzz tests.

This dependency and the console integration below are implementation components.
Automatic endpoint renewal is not enabled yet. Authenticated HTTPS/gateway routes,
rate limits, protected candidate/activation journals, scheduling, broker runtime
reconnect and agent/worker/service release integration remain necessary.

## Registry lifecycle

Desktop startup applies registry migrations 007–009 with its existing migrations.
Preparation accepts current old-key proofs only within the 30-day renewal window,
requires a real certificate extension and retains exact candidate issuance for
up to 168 hours, bounded by source expiry. A fresh proof for the same request ID
and intent recovers its committed result. Source, candidate and retired keys remain
owned by the same device; another enrollment cannot claim them.

Preparation preserves the current identity. A distinct candidate proof permits
atomic activation: certificate/key fields change, device ID/scope/command consumer
remain, and existing broker sessions enter the durable disconnect outbox. Old
certificate authentication fails after activation. Fresh broker keys reject new
old-key connections; existing sessions have the established bounded lease and
disconnect retry behavior. Same-key certificate renewal remains supported.

Encrypted immutable issuance and confirmation records bind exact source/target
certificates, request/device IDs, scope and time. Retries after a lost commit reply
or restart recover only the still-current confirmed generation and do not repeat
disconnect effects. An older confirmation cannot restore a retired generation.
Revocation and changed scope remain authoritative.

## FileVault key-processing coordination

The routing worker can receive an encrypted FileVault result before the console
has retained the returned recovery key. That worker receipt must not authorize a
certificate switch: retiring its certificate/recipient too soon would prevent
the console from completing the original key-processing transaction.

The console now writes the registry's authenticated reconciliation acknowledgement
in the same transaction as verified result handling, returned-key retention,
final rotation state and both audit records. The acknowledgement binds the exact
signed receipt digest. It is issued after successful `rotated`, `unverified`,
superseded-candidate or authenticated non-key outcomes, and after independently
verified resolution of a stopped uncertain attempt. Rejected/malformed results,
unresolved uncertainty, full key history and failed audit do not acknowledge work.

Both stores derive separate encryption keys from the same configured
`ENCRYPTION_MASTER_KEY`; no raw master key is retained in the Apple store.
The registry verifies the console acknowledgement before allowing handoff.
Completed worker receipts without it remain blocked. A failure in the final
registry audit rolls back the newly retained key, final console state and audit
together, preserving the original return key and receipt for retry.

Registry migration 009 is required for rotation readiness. A partial upgrade
cannot silently finish key processing without acknowledgement storage; the
pending return key remains available until the registry is upgraded. Existing
completed rows predating this feature are not guessed to be safely processed or
automatically acknowledged. A separately verified historical reconciliation path
is still required before those attempts can release automatic renewal.

After handoff, original receipts, ordinals and encrypted recovery keys remain.
The agent must register a fresh recipient epoch against its new certificate while
retaining its original local installation/replay anchor and recipient key.
Delivered pending read-only checks must finish first; queued undelivered work is
cancelled by existing certificate-epoch triggers and needs fresh admission.

## Verification and remaining acceptance

Library tests cover concurrent preparation/confirmation and revocation races,
permanent key reservations, exact retry after restart/source expiry, multiple
certificate generations, immutable and authenticated history, migration of existing
identities, audit rollback, stale proof rejection, DST-independent expiry, broker
handoff and FileVault coordination. Local full library race suites pass; confirmation
wire fuzzing passes 449,004 executions. Vet and Linux/Windows builds pass.

Console PostgreSQL tests verify that acknowledgement follows actual encrypted-key
retention, cannot survive either console or registry audit rollback, binds the
same root key across separately constructed stores, and remains absent for rejected
receipts. Tests cover verified uncertainty resolution and partial registry upgrade.
A synthetic linked Mac completes a rotation, is initially denied renewal while its
returned key is unprocessed, then activates its replacement certificate after
console processing. The original key/receipt remain available and the same local
recipient key registers a new server epoch.

The final focused console integration passes in **5.008 seconds**. The complete
Apple race suite passes in **262.823 seconds**; desktop in **19.407 seconds**, its
authorization service in **3.857 seconds**, command service in **3.933 seconds**
and protocol in **1.305 seconds**. Affected handler checks pass in **1.981 seconds**.
Vet, module consistency and complete Linux/Windows builds pass. Console CI for
this integration must be checked independently of the shared-library run above.

These tests use disposable PostgreSQL schemas and synthetic keys/certificates.
They do not install an agent, execute FileVault on a physical volume, contact a
provider, deploy a service or demonstrate a signed production release. Physical
Windows/macOS renewal/restart acceptance, historical reconciliation, CA/master-key
rotation and the complete PKI-01 work package remain open.

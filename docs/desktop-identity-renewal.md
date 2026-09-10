# Individual desktop identity renewal

The console pins shared registry commit
[`06ec5c5`](https://github.com/the-luap/openuem-nats/commit/06ec5c578a4f8682a223fb42bbea10b4febe0a94),
which implements persistent renewal preparation and candidate confirmation while
preserving device ID and organization/site. Its
[protocol and lifecycle documentation](https://github.com/the-luap/openuem-nats/blob/06ec5c578a4f8682a223fb42bbea10b4febe0a94/enrollment/identity-renewal.md)
defines proof domains, expiry bounds, permanent key ownership and retry behavior.
The [shared-library CI](https://github.com/the-luap/openuem-nats/actions/runs/34471335722)
passes native Windows checks and Linux/PostgreSQL/race/fuzz tests.

This dependency and the console integration below are implementation components.
Automatic endpoint renewal is not enabled yet. The HTTPS client, console routes
and pinned gateway transport are implemented. Protected candidate/activation
journals, scheduling, broker runtime reconnect and agent/worker/service release
integration remain necessary.

## HTTPS and gateway transport

The existing [desktop listener](desktop-public-protocol.md) and gateway expose only
these two canonical POST routes for renewal:

- `/enroll/desktop/identities/<device-uuid>/renewal/prepare`
- `/enroll/desktop/identities/<device-uuid>/renewal/confirm`

Each JSON body must bind the exact path device and configured public origin.
Preparation verifies both current private keys and the candidate broker key;
confirmation verifies both candidate private keys against the retained issuance.
Public certificate headers, browser cookies and the gateway certificate cannot
substitute for these proofs. Confirmation remains reachable with candidate proofs
after activation retired the original certificate and its commit reply was lost.
The private listener still requires its configured gateway pin on the TLS transport.

Renewal neither consumes an invitation nor requires an approved installer release.
Tests start with a revoked original invitation and an empty catalog. Listener
startup still requires its configured release directory and trusted release keys;
an unavailable repository is a startup error, as documented for that listener.

Requests are limited to 32 KiB for preparation and 8 KiB for confirmation, with
strict versioned JSON, a 10-second body deadline and a 20-second handler context.
The registry adds its own 15-second transaction bound. Claims and renewals share
four concurrent proof-processing slots and the existing bounded global/source
rate limits. Shutdown cancels and joins waiting requests before storage closes.
The completed-body deadline is cleared before database work, including on HTTP/2.
Methods, query parameters and encoded/extra path aliases are rejected by the shared
gateway/listener allowlist; administrator network restrictions remain in force.

Successful responses contain only the public prepared or confirmed renewal DTO.
HTTP 409 returns exactly `{"version":1,"code":"not_due"}`, `pending` or
`recovery_pending` in the same shape. Denied or unknown identities return a fixed
404; operational/audit failures return a fixed 503; admission returns 429 with
`Retry-After`. Responses are not cached, offer no CORS permission and do not expose
proofs, database diagnostics or private keys. Existing browser origin restrictions
apply to both routes.

The shared `HTTPClient.PrepareIdentityRenewal` and `ConfirmIdentityRenewal` methods
require the independently authorized origin and trusted local source/target. They
validate proofs before network I/O and validate the exact returned candidate,
device, scope and times afterward. Responses are bounded to 96 KiB and 2 KiB.
The client uses verified HTTPS without redirects, environment proxies, cookies or
automatic retries; known conflicts become fixed local typed errors.

Before sending, an endpoint must durably retain candidate keys and the request ID.
It must retain verified issuance and its confirmation decision before confirmation.
A timeout, cancellation or error response can follow a committed activation;
never discard the candidate or restore old credentials solely on that result or
preparation expiry. Retain the exact target and retry with a fresh candidate proof.
These transport methods do not install credentials or supply that protected journal.

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
Vet, module consistency and complete Linux/Windows builds pass. The
[console PR CI for `1634d39`](https://github.com/the-luap/openuem-console/actions/runs/34470176352)
and its [push CI](https://github.com/the-luap/openuem-console/actions/runs/34470172473)
also pass for this FileVault integration.

The subsequent HTTPS integration passes its focused race suite in **8.088 seconds**
and route checks in **1.322 seconds**. A real SDK client traverses both direct HTTPS
and the pinned HTTP/2 gateway into PostgreSQL. It recovers a lost commit response
after client reconstruction and concurrent fresh-proof retries, preserving one
identity, one invitation use and one activation audit. Old certificate access then
fails while the candidate succeeds. Tests also cover each missing/corrupt key
proof, scope movement, revocation, all three typed conflicts, browser/body limits,
forged forwarding headers, direct unpinned TLS rejection and exact route isolation.
Four concurrent preparations or confirmations wait on an observed database lock;
the fifth receives 429, and shutdown joins all four without issuance, activation,
key reservations or audit changes. Audit failure rolls back both operations before
any success response. A synthetic Mac retains a delivered encrypted read-only
recovery task until its signed completion, then renews through the gateway without
losing the receipt. Shared response fuzzing passes **459,737 executions**.

The complete transport regression passes with `-race -count=1`: desktop in
**28.950 seconds**, authorization service in **7.027 seconds**, command service in
**3.589 seconds**, protocol in **1.176 seconds** and gateway in **3.154 seconds**.
Affected-package Vet, unchanged `go mod tidy -diff` and full Linux/Windows builds
also pass. Handler capability checks pass in **1.737 seconds**; the real console
router/PostgreSQL test, including desktop permissions, passes in **12.097 seconds**.
These local results do not substitute for the subsequent console CI run.

These tests use disposable PostgreSQL schemas and synthetic keys/certificates.
They do not install an agent, execute FileVault on a physical volume, contact a
provider, deploy a service or demonstrate a signed production release. Physical
Windows/macOS renewal/restart acceptance, historical reconciliation, CA/master-key
rotation and the complete PKI-01 work package remain open.

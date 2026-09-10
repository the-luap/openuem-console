# Individual desktop identity renewal

The console pins shared registry commit
[`07a6ac8`](https://github.com/the-luap/openuem-nats/commit/07a6ac8e2a5e07f63778b2c1f4d75e72ca7e2fa3),
which implements persistent preparation, confirmation and permanent cancellation while
preserving device ID and organization/site. Its
[protocol and lifecycle documentation](https://github.com/the-luap/openuem-nats/blob/07a6ac8e2a5e07f63778b2c1f4d75e72ca7e2fa3/enrollment/identity-renewal.md)
defines proof domains, expiry bounds, permanent key ownership and retry behavior.
The [shared-library CI](https://github.com/the-luap/openuem-nats/actions/runs/34479270024)
passes native Windows checks and Linux/PostgreSQL/race/fuzz tests.

The HTTPS client, console routes and pinned gateway transport are implemented,
as are the agent's protected candidate, activation and authoritative-resolution
journals. Agent
[`cdffd2c`](https://github.com/the-luap/openuem-agent/commit/cdffd2cf6a38990fc4e5497187f9e4f910932511)
now connects those components to the installed individual Windows/macOS service:
automatic scheduling, joined credential handoff, startup recovery and complete
broker/recipient reconstruction. The [agent lifecycle documentation](https://github.com/the-luap/openuem-agent/blob/cdffd2cf6a38990fc4e5497187f9e4f910932511/docs/individual-identity-renewal.md)
describes the ownership and retry contract. Production signing, distribution and
physical-device acceptance remain separate work; an old or unavailable server
cannot authorize fallback during an uncertain handoff.

## HTTPS and gateway transport

The existing [desktop listener](desktop-public-protocol.md) and gateway expose only
these three canonical POST routes for renewal:

- `/enroll/desktop/identities/<device-uuid>/renewal/prepare`
- `/enroll/desktop/identities/<device-uuid>/renewal/confirm`
- `/enroll/desktop/identities/<device-uuid>/renewal/resolve`

Each JSON body must bind the exact path device and configured public origin.
Preparation verifies both current private keys and the candidate broker key;
confirmation and resolution verify both candidate private keys against retained
issuance, using independent signature domains.
Public certificate headers, browser cookies and the gateway certificate cannot
substitute for these proofs. Confirmation remains reachable with candidate proofs
after activation retired the original certificate and its commit reply was lost.
The private listener still requires its configured gateway pin on the TLS transport.

Renewal neither consumes an invitation nor requires an approved installer release.
Tests start with a revoked original invitation and an empty catalog. Listener
startup still requires its configured release directory and trusted release keys;
an unavailable repository is a startup error, as documented for that listener.

Requests are limited to 32 KiB for preparation and 8 KiB for confirmation/resolution, with
strict versioned JSON, a 10-second body deadline and a 20-second handler context.
The registry adds its own 15-second transaction bound. Claims and renewals share
four concurrent proof-processing slots and the existing bounded global/source
rate limits. Shutdown cancels and joins waiting requests before storage closes.
The completed-body deadline is cleared before database work, including on HTTP/2.
Methods, query parameters and encoded/extra path aliases are rejected by the shared
gateway/listener allowlist; administrator network restrictions remain in force.

Successful responses contain only the public prepared, confirmed or resolved renewal DTO.
HTTP 409 returns exactly `{"version":1,"code":"not_due"}`, `pending` or
`recovery_pending` in the same shape. Denied or unknown identities return a fixed
404; operational/audit failures return a fixed 503; admission returns 429 with
`Retry-After`. Responses are not cached, offer no CORS permission and do not expose
proofs, database diagnostics or private keys. Existing browser origin restrictions
apply to all three routes.

The shared `HTTPClient.PrepareIdentityRenewal`, `ConfirmIdentityRenewal` and
`ResolveIdentityRenewal` methods
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

## Atomic resolution

A candidate-key resolution request returns the original `confirmed` outcome if
that exact generation is already current and authorized. Otherwise it permanently
cancels the candidate while the original source remains current, valid and
authorized. Cancellation works before or after preparation expiry, permitting
retained recovery work to finish without waiting for an expired preparation.
Neither expiry nor an unknown/error response grants permission to resume old keys.

Migration 010 retains AES-GCM cancellation evidence with exact source/candidate
hashes and an immutable original timestamp. It commits with audit before any reply.
Retries after reconstruction recover the same outcome; a later generation,
revocation or expired original source prevents old-credential recovery. A cancelled
attempt cannot be re-prepared or confirmed, but a new signed request can follow.
The device, broker sessions, recipient, tasks, receipts and key reservations remain.

Database guards protect rolling upgrades too. They reject cancelled-certificate
activation and contradictory confirmation/cancellation evidence. Cancellation
publishes a new identity row version with identical field values; an older writer
using READ COMMITTED, REPEATABLE READ or SERIALIZABLE cannot activate from a stale
snapshot. No credential, scope, recovery or consumer transition is performed by
that row-version change. Registry evidence is authenticated before retries or
before ignoring cancelled history for the pending-preparation check.

## Protected endpoint journal

Agent [`e12bc24`](https://github.com/the-luap/openuem-agent/commit/e12bc24b6c3a19e6b52a05b297be13a07ddf9315)
adds the [native renewal journal and caller contract](https://github.com/the-luap/openuem-agent/blob/e12bc24b6c3a19e6b52a05b297be13a07ddf9315/docs/individual-identity-renewal.md).
The store preserves candidate keys and request ID before preparation, exact
verified issuance afterward, one exclusive confirmation-or-abandonment decision,
and verified activation or authoritative resolution before returning selected credentials. Every record is
bound to the original protected installation and exact ordinal/predecessor; all
128 bounded attempt slots are checked for missing stages, gaps and later fragments.
DPAPI and noninteractive Keychain use their existing immutable publication rules.

An unresolved confirmation decision prevents `Load` from returning original
credentials, including after transport cancellation, a lost server reply or original
certificate/preparation expiry. A fresh candidate proof can recover a committed
result. Earlier confirmations cannot replace a later generation. Abandonment can
win only before confirmation intent and cannot cancel a server reservation.
`ResolveRenewal` requires an existing confirmation decision, stores the actual
resolution proof/outcome in `renewal-resolved-v1-NNN`, then reloads and validates
the selected identity. It never fabricates confirmation evidence. Both positive
acknowledgements may coexist only with the same original confirmation time; the
earliest local receipt preserves later generation ordering. A durable cancellation
closes that attempt, but original keys remain unusable at or after their expiry.
A missing final record retains quarantine. An older agent ignoring the new stage
continues to fail closed on the retained confirmation decision.

The original release/executable checkpoint, enrollment anchors, X25519 recipient
key and FileVault attempt ordinals remain unchanged. Historical receipts are
verified with their exact original certificate at its authenticated retirement
time, while only the selected current certificate must remain unexpired. Historical
reads cannot admit another mutation; new intent/result publication rechecks the
durably selected identity and rejects stale journal handles or handoff uncertainty.
The service controller stops and joins existing credential/security users before
confirmation, then constructs a fresh Agent with the selected identity, broker
connection and server recipient registration.

The original journal local native macOS race suite passes: protected store **30.632 seconds**,
runtime **9.053**, bootstrap installation **1.555**, enrollment command **1.826**,
activation **4.516**, lifecycle **1.292** and Mac service **3.456**. Tests include
real SDK HTTP/2, both missing-response boundaries, native publication failures,
concurrent confirm/abandon decisions, source expiry, multiple generations,
exhausted capacity and FileVault continuity. Vet, module consistency, Windows test
compilation and Linux/Windows/native-macOS builds pass. The
[agent journal CI](https://github.com/the-luap/openuem-agent/actions/runs/34476393712)
passes Linux, native macOS and native Windows checks for `4b782a1`. Resolution
at `e12bc24` additionally passes the local native macOS store race suite in
**44.678 seconds**, runtime in **9.933**, bootstrap installation in **1.558**,
enrollment command in **1.814**, activation in **4.519**, lifecycle in **1.297**,
Mac service entry point in **3.484** and service coordination in **2.913**. Vet,
module consistency, Windows test compilation and all three platform builds pass.
The resolution commit also passes
[Linux, native macOS and Windows CI](https://github.com/the-luap/openuem-agent/actions/runs/34480704684).

### Automatic service handoff

The controller owns a private native process lease from initial local validation
through recovery, all runtime generations and joined shutdown. Each Agent borrows
that ownership. Windows holds an exclusive non-inheritable file handle and pins
the protected directory; macOS uses a root-owned private flock. Protected native
history exposes public installation/checkpoint metadata during quarantine, so the
controller can verify platform, architecture and the enrolled executable before
network recovery without releasing old keys. `Load` independently enforces current
credential validity. Corrupt history or changed ownership/binding stops the Agent.

Preparation preserves the active generation. A verified response triggers full
joined shutdown, separate FileVault execution exclusion, confirmation and, after
an error, authoritative resolution. Uncertain outcomes keep the Agent offline.
Startup recovery finishes before Agent readiness. The common lifecycle separates
an initialized recovery controller from its first usable Agent. Windows reports
the controller `Running` and accepts SCM stop/shutdown while withholding Agent
readiness and logging its offline state. It uses `StartPending` only for finite
local initialization; [SCM cannot deliver normal stop controls in that state](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-controlserviceexw).
The replacement loads independent protected keys and reconstructs all credential
users. Source expiry never grants fallback.

Checks run immediately after startup and then hourly with jitter. Each request
has a 20-second deadline; retries back off from one minute to one hour. Task and
transport contexts end at the active leaf's expiry. Durable cancellation evidence
sets a restart-stable cooldown, normally seven days and shortened as the original
certificate nears expiry. Prepared expiry or a seven-day-old candidate without
confirmation may be explicitly abandoned while retaining all native records and
server reservation guards. Confirmation intent is never abandoned. The existing
128-attempt limit still applies.

The local native macOS race suite passes with this controller: protected store
**52.333 seconds**, agent **8.472**, service lifecycle **1.299**, Mac service
**3.478**, FileVault security **39.286**, and the remaining bootstrap, activation,
readiness, package, SFTP and hardware checks. Final controller changes pass a
focused race run in **1.638 seconds**. Vet, module consistency, complete native
macOS/Linux/Windows builds and Windows storage/controller/SCM test compilation
pass. The original controller `bf48781` also passes
[Linux, native macOS and Windows CI](https://github.com/the-luap/openuem-agent/actions/runs/34485183033).
The subsequent stoppable-recovery correction `cdffd2c` passes the full affected
native macOS race suite: agent **8.156 seconds**, lifecycle **1.182**, and Mac
service **3.383**; Vet, all three platform builds and Windows SCM test compilation
pass. Its [branch CI](https://github.com/the-luap/openuem-agent/actions/runs/34486258522)
also passes Linux, native macOS and native Windows, including the actual Local
System recovery/stop fixture and Windows file IDs captured from held handles
before and after process exit.

## Registry lifecycle

Desktop startup applies registry migrations 007–010 with its existing migrations.
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

Encrypted immutable issuance, confirmation and cancellation records bind exact source/target
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
Console `3a49b79` also passes its
[push CI](https://github.com/the-luap/openuem-console/actions/runs/34472852010) and
[PR CI](https://github.com/the-luap/openuem-console/actions/runs/34472855743).

The resolution integration passes its complete affected race suite: desktop
**30.309 seconds**, protocol **1.298**, gateway **3.174**, authorization **3.736** and
command service **3.788**. Tests reconstruct the real SDK and registry after lost
confirmation/resolution replies through both direct HTTPS and the pinned gateway,
recover concurrent exact outcomes, and reject late confirmation after cancellation.
All three operations share the tested concurrency/shutdown, body, origin, route,
proof and audit-rollback boundaries. A delivered encrypted read-only FileVault task
can finish with the original certificate after authoritative cancellation; its
recipient and signed receipt remain. Vet, tidy consistency and full Linux/Windows
builds pass. Shared resolution proof/response fuzzing and CI also pass. Console
`da07f38` passes both its
[push CI](https://github.com/the-luap/openuem-console/actions/runs/34480897518) and
[PR CI](https://github.com/the-luap/openuem-console/actions/runs/34480901938).

These tests use disposable PostgreSQL schemas and synthetic keys/certificates.
They do not install an agent, execute FileVault on a physical volume, contact a
provider, deploy a service or demonstrate a signed production release. Physical
Windows/macOS renewal/restart acceptance, historical reconciliation, CA/master-key
rotation and the complete PKI-01 work package remain open.

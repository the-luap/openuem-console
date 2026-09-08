# Individual desktop enrollment implementation

This is the active implementation design for ENR-01, the desktop portion of
ENR-02, and agent transport in NET-01. It is not a delivery or hardware acceptance
claim. Shared proof, durable registry, broker authorization, gateway transport and
worker request boundaries, service runtimes and scoped console administration now
have automated evidence. New installation invitations, native-agent storage,
installers and production deployment wiring remain open.

## Source baselines

Local related repositories were checked out from upstream into sibling directories:

| Component | Baseline commit | Relevant finding |
| --- | --- | --- |
| Agent | `ee23c21` | Reads an initial `agent.cer`/`agent.key`; uses global request subjects and creates its own JetStream consumer |
| NATS client library | `98373a4` | Shared connection helper and messages; certificate response includes a private key |
| Certificate manager | `6b136eb` | Generates common agent keys and a NATS configuration whose agent permissions span device IDs |
| Worker | `c852d70` | Global `report`, `agentconfig` and deployment subjects trust body identity/scope |
| Docker deployment | `28ede14` | NATS/public ports and certificate-mounted components need the new reference gateway integration |

The console remains on its native Apple feature branch. Related repositories use
feature branches named `feature/individual-agent-enrollment`. The NATS library and
worker and certificate manager are now forked under `the-luap`; the
agent and Docker repositories are still local upstream
checkouts. Feature branches are implementation work, not signed releases.

Local NATS library commit `0a8ad01` adds the shared endpoint-generated CSR/NKey
proof, canonical device request parsing, private inbox validation and bounded
subject policy. Local commit `df18641` adds explicit WSS connections and bounded auth callout
grants. Real NATS 2.14.6 / Go client 1.53.1 tests cover individual keys, private
subjects/replies, pre-provisioned JetStream consumers, active-session kicks,
certificate expiry and authorization outages. Its race tests and full library
test/build suite pass. Commit `c33596f` adds the durable PostgreSQL registry,
limited invitations, organization CA creation/import, scoped issuance and atomic
revocation/session outbox. The combined real-broker/database test passes. The
worker pins published library commit `2af211c88d57` using the Go module replacement
`github.com/the-luap/openuem-nats v0.11.1-0.20260907232712-2af211c88d57`.
[Library CI passed](https://github.com/the-luap/openuem-nats/actions/runs/34170105505)
for that exact commit. Later library commit `7462b7bd9e56` adds the bounded
authorization service, durable disconnect batches and protected key-file loading.
Its [CI passed](https://github.com/the-luap/openuem-nats/actions/runs/34171176156),
including native Windows ACL tests. The console authorization executable was
introduced with that dependency; later pins are recorded below.

The console now includes the private `openuem-agent-auth` executable with separate
authorization/revocation NKeys, verified TLS, loopback readiness and graceful
shutdown. Its real PostgreSQL/TLS broker race test passes locally and covers active
revocation and broker failure. Its [CI passed](https://github.com/the-luap/openuem-console/actions/runs/34171756069)
at commit `74ab1b8`. See [service operations](agent-authorization-operations.md).
Production provisioning and released-agent use remain open.

The console gateway now supports an optional exact native-agent WSS route with
mutual TLS to the private broker, strict upgrade validation, bounded concurrent
streams and explicit stream shutdown. Real-broker tests cover TLS, routing,
private replies and HTTP deadline survival. This is transport evidence; the
production console and released agent are not integrated yet.

Worker commit `6c7cc1f` adds opt-in versioned subscriptions, private reply validation,
body/device/scope binding, current revocation checks and profile/task ownership.
It also fixes targeted profile queries that previously omitted organization/site
limits. Its actual deployment-exclusion handler was tested through a real broker
and isolated PostgreSQL schema. The test rejects forged replies, foreign body IDs
and requests from a revoked but still connected device. Linux/Windows builds pass
without the temporary local workspace;
[worker CI passed](https://github.com/the-luap/openuem-worker/actions/runs/34170316983)
for this exact commit. Startup
in both console and worker now preserves newer additive columns/indexes.
[Console CI passed](https://github.com/the-luap/openuem-console/actions/runs/34170372575)
for commit `ffac98f`, including the gateway, access controls and guided Apple portal.

Worker commit `c705189` adds the production TLS/NKey service runtime for CLI and
installed Linux/Windows services. It requires separate protected environment
configuration and returns startup or asynchronous broker permission failures.
It stops accepting work before closing its database. The actual runtime passes
the deployment-exclusion integration test, including deliberately partial broker
permissions. [Worker CI passed](https://github.com/the-luap/openuem-worker/actions/runs/34172361553),
including race tests and Linux/Windows builds. Its shared-library pin is now
`6940f11772a9`; [library CI passed](https://github.com/the-luap/openuem-nats/actions/runs/34172052566)
with broker restart/reconnection and native Windows ACL tests. Inherited handler
operations still need a consistent upper time bound.

Certificate Manager commit `a5a15e3` adds the `individual-broker` setup command:
protected service keys, public broker configuration, partial setup recovery,
identical retries and explicit conflicts/missing-key failures. Its
[Linux/Windows CI passed](https://github.com/the-luap/openuem-cert-manager/actions/runs/34173268997).
The shared library now renders the actual stock NATS account configuration and
provisions bounded fixed consumers. Its database work queue handles issuance,
revocation, site moves, expiry, leases, stale completions and periodic recovery.
[Library CI passed](https://github.com/the-luap/openuem-nats/actions/runs/34173775027)
at `b46d0913482e`; the console now pins this version. The executable
`openuem-agent-commands` passes its local PostgreSQL/TLS race test, including
broker-state repair and revocation deletion. See [command service operations](agent-command-operations.md).
[Console CI passed](https://github.com/the-luap/openuem-console/actions/runs/34174306948)
for commit `a39a21f`, including both isolated service lifecycles and both platform builds.

The console now initializes the registry and exposes scoped public metadata,
organization-authority setup/import, invitation revocation and identity revocation
with confirmation and CSRF. Its real-router PostgreSQL tests and browser fixture
cover these actions. See [desktop administration](desktop-console.md).
[Console CI passed](https://github.com/the-luap/openuem-console/actions/runs/34176188721)
for this administration work at `d3030a5`, including route/database race checks
and Linux/Windows builds. Browser acceptance also caught and fixed the fixture's
shutdown ordering and the dark-mode heading/header foreground.

Library commit `53e1022ff390` adds authenticated immutable installer manifests,
strict target/content binding and persistent-checkpoint validation. Its
[Linux and native Windows CI passed](https://github.com/the-luap/openuem-nats/actions/runs/34176695980).
The console now pins that version and adds a persisted installer catalog and
`openuem-agent-releases` administration command. Local PostgreSQL race checks cover
concurrent admission, rollback/sequence reuse, restart, withdrawal and verified
file descriptors. See [release admission operations](agent-release-operations.md).
[Console CI passed](https://github.com/the-luap/openuem-console/actions/runs/34177682716)
for that catalog and administration command at `9ea4162`.

Library commit `b589b84da570` adds caller-owned invitation/claim transactions while
retaining the existing convenience APIs and key-proof checks. Its
[CI passed](https://github.com/the-luap/openuem-nats/actions/runs/34178488009).
The console pins this version and uses those transactions for exact installer
release binding and canonical-origin checks. PostgreSQL tests observe actual lock
dependencies to prove that withdrawal serializes after already authorized issuance
and prevents later claims. Failed bindings leave no orphan invitations or uses.
Signed artifact selection, new console invitations, endpoint storage/bootstrap
and reference deployment wiring remain open.

## Required boundaries

1. A console invitation determines organization, site, platform, architecture,
   expiry, permitted artifacts and use count. GET instructions/downloads cannot
   consume it. Issuance requires explicit proof from endpoint-generated keys.
2. The endpoint generates an RSA certificate key and a separate broker NKey. A
   broker signature binds the CSR, invitation and target. The server reconstructs
   the certificate identity and extensions; requested CSR names cannot assign
   authority. Retries recover only the same key binding, never a second identity.
3. An individual database record binds the issued device ID, scope, certificate,
   broker key and lifecycle. The worker resolves this record instead of trusting
   a report's organization/site. Every body device/resource must match that scope.
4. Requests use `uem.v1.agent.<id>.request.<operation>` and replies use a private
   `uem.v1.agent.<id>.reply` prefix. Workers must validate the reply as well as the
   request: otherwise a forged reply could turn a privileged response into another
   device's reboot or other command.
5. Agents cannot create or modify JetStream consumers. A trusted service provisions
   the consumer and fixed filters before the agent connects. Consumer-name-only
   permissions are insufficient if the agent can change its filters.
6. The gateway routes only the exact agent WSS path to private NATS. Agent identity
   must remain provable through TLS termination; forwarding a certificate header
   to NATS does not establish that identity. The selected broker integration must
   validate nonce proof, issue exact subject permissions, enforce expiry and
   disconnect revoked sessions. NATS auth callout provides the connection-time
   mechanism; its service must run in an isolated account and remain unavailable
   to ordinary agents. [NATS auth callout](https://docs.nats.io/learn/security/auth-callout).
7. Installer bytes stay signed and unchanged. Separate authenticated, signed
   configuration selects approved artifacts and a limited invitation; neither
   configuration nor command lines contain shared permanent credentials.
8. Local key storage, renewal, revocation, process restart and certificate overlap
   must be implemented across the agent and PKI components. A console-only endpoint
   or a source package that has not reached the agent release is insufficient.

## Validation still required

Run real NATS integration with multiple synthetic agents and organizations. Prove
that an agent cannot impersonate another report, change scope in a body, forge a
worker reply to a command, subscribe to another device/inbox, create a broader
consumer, replay a nonce or reconnect after revocation. Verify queued commands,
renewal, broker/worker restart, WSS proxying and concurrent bootstrap claims.

Then build and install versioned Windows/Mac artifacts on physical endpoints,
verify individual registration and software deployment, and prove the reference
installation's inbound firewall exposes only TCP 443. Signing/notarization and
physical endpoint access are outstanding external acceptance inputs.

# Individual desktop enrollment implementation

This is the active implementation design for ENR-01, the desktop portion of
ENR-02, and agent transport in NET-01. It is not a delivery or hardware acceptance
claim. The shared endpoint proof/subject library has been started; the server,
broker, worker, agent, installer and deployment integration below remains open.

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
local `feature/individual-agent-enrollment` branches. No related repository fork,
dependency version or remote CI result is implied by a local checkout.

Local NATS library commit `0a8ad01` adds the shared endpoint-generated CSR/NKey
proof, canonical device request parsing, private inbox validation and bounded
subject policy. Local commit `df18641` adds explicit WSS connections and bounded auth callout
grants. Real NATS 2.14.6 / Go client 1.53.1 tests cover individual keys, private
subjects/replies, pre-provisioned JetStream consumers, active-session kicks,
certificate expiry and authorization outages. Its race tests and full library
test/build suite pass. Production broker and application wiring remain open; the library is not yet used
by the released agent or console.

The console gateway now supports an optional exact native-agent WSS route with
mutual TLS to the private broker, strict upgrade validation, bounded concurrent
streams and explicit stream shutdown. Real-broker tests cover TLS, routing,
private replies and HTTP deadline survival. This is transport evidence; the
persistent identity database and released agent are not integrated yet.

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

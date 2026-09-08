# Mac agent and MDM association

Roadmap MAC-01 requires one Mac record and detail page with two management
channels, conflict handling and continuity across re-enrollment. This requirement
is **partially implemented**. Authenticated hardware evidence is available;
challenge issuance, association reconciliation and the shared device experience
are not implemented yet. Existing agent and native MDM records remain separate.

## Implemented evidence path

The console pins shared protocol `4e6e26103fd9`. Desktop initialization runs
registry migration 003, which creates `uem_agent_hardware` with a composite
organization/site/identity foreign key. The broker authorization service includes
the device-scoped `hardware` operation. Ordinary inventory JSON is unchanged.

The Mac agent preserves the actual hardware model and distinguishes its
installation UUID, platform UUID and optional provisioning UDID. It enables the
separate RPC only after an individual worker advertises version 1. Windows,
legacy agents and unsupported versions skip that RPC. The worker advertises
support only for Mac identities with the required schema available. Upgrade
console/registry and broker authorization before the worker, reconnect devices
to refresh broker permissions, and update agents last.

The worker checks strict bounded JSON, subject/body identity, platform, existing
desktop scope and current registry authorization. The registry locks the active
identity against concurrent revocation and rechecks certificate expiry and site
ownership. Only a committed observation receives a successful receipt. Hardware
changes and their audit receipt commit together; unchanged reports refresh the
observation timestamp without creating duplicate hardware-change events.

An optional proof contains a native MDM device ID, challenge ID and 256-bit random
token. The agent reads it at send time from the protected system managed-preferences
domain `eu.openuem.device-binding`. It accepts bounded XML/binary plists from a
root-owned regular file through protected directory descriptors. The proof is
excluded from ordinary report serialization and logs. The database stores only
SHA-256 of the canonical base64url token. Omitting the proof clears old proof
columns. No association or additional action permission follows from recording
this evidence.

## Remaining implementation

1. Issue a short-lived, device-specific challenge in a System-scoped managed
   preferences profile over the authenticated native MDM channel. Encrypt the
   pending command, reserve the profile namespace, and track installation,
   expiry, replacement, consumption and cleanup. Do not expose the token in
   administrator inventory or profile downloads.
2. Reconcile fresh evidence against the challenge and both currently authorized
   identities in the same organization/site. Require consistent model, serial
   and appropriate platform/provisioning identifiers. A matching serial alone
   must never merge records. Treat this as channel correlation, not hardware
   attestation: an administrator controlling an endpoint can copy observations.
3. Keep a stable device identity and channel history across re-enrollment.
   Concurrent active claims and hardware/scope conflicts must produce explicit
   unresolved states, without silently transferring another endpoint's authority.
4. Show one list row and detail page with separate channel health/actions.
   Preserve old links and history. MDM view permission must not grant access to
   legacy desktop actions, which still require global administrator permission.
5. Exercise the complete path through PostgreSQL, real broker and simulated MDM
   command receipts, then separately verify real Intel/Apple-silicon enrollment,
   managed preference delivery, removal, renewal and re-enrollment.

## Evidence

- Shared protocol and PostgreSQL registry tests cover normalization, proof
  hashing, scope constraints, audit rollback, expiry, site moves and concurrent
  revocation. [Shared-library CI](https://github.com/the-luap/openuem-nats/actions/runs/34246345384).
- Agent tests use synthetic hardware/plists and a real TLS/WSS NATS server.
  They check compatibility negotiation, strict receipts, proof exclusion from
  ordinary reports, model preservation and protected-file metadata checks.
  [Agent implementation](https://github.com/the-luap/openuem-agent/commit/d168593b2bca3245f42d5a40b397028318a36e84).
- Worker tests use real PostgreSQL and TLS/NKey broker connections for Windows
  and Mac identities, accepted hash persistence, foreign identity denial,
  disappearing schema capability and revocation on an existing connection.
  [Worker implementation](https://github.com/the-luap/openuem-worker/commit/79f7c372e8b2becf61bf52a0828844fde0341b24),
  [passing Linux tests and Linux/Windows builds](https://github.com/the-luap/openuem-worker/actions/runs/34247235314).

Protocol fixtures do not establish physical-device acceptance. Apple's
[managed-preferences schema](https://github.com/apple/device-management/blob/67045e2fa06f528b196c01edee6a8bf88b844beb/mdm/profiles/com.apple.ManagedClient.preferences.yaml)
defines the payload used by the planned MDM challenge delivery.

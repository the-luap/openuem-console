# Mac agent and MDM association

The console can group a verified native Mac enrollment and an individual agent
under one scoped device identity, list row and detail page. It retains separate
channel authorization and enrollment history. [Managed user-channel profiles](macos-user-channels.md)
have a separate implemented workflow. Roadmap MAC-01 remains open for further
Mac templates and physical-device acceptance.

## Verify a Mac

1. Configure native Apple management and individual agent enrollment. Enroll both
   channels in the same organization and site, using an agent and worker that
   support hardware protocol version 1.
2. Open the native Mac detail and select **Verify management channels**. This
   requires the enrollment capability, available to a site operator or an
   administrator within their scope. Keep the Mac online and its agent running.
3. The Mac acknowledges a temporary System managed-preferences profile. The agent
   reads its protected preference and returns the proof through its independently
   authenticated hardware RPC. Both channels need hardware observations from the
   last 24 hours. Normal inventory scheduling supplies these observations.
4. After reconciliation, the list and detail show a stable device identity, MDM
   state, agent state and channel history. Verification can be cancelled while
   queued or installed. Expired or conflicting verification can be requested
   again after its temporary profile has been removed.

The server checks model, serial and provisioning UDID. When provisioning UDID is
absent, the Intel fallback additionally requires an explicit non-Apple-silicon
MDM inventory value and equality between its MDM UDID and the agent's platform
UUID. It never treats an Apple-silicon MDM UDID as a platform UUID. Missing or
conflicting evidence does not merge devices. A serial number alone is insufficient.
This verifies management-channel correlation, not hardware attestation: an
administrator controlling an endpoint can copy hardware observations and proofs.

## Challenge and cleanup lifecycle

Each challenge has a new UUID, a 256-bit random token and a unique profile
identifier beneath `eu.openuem.device-binding`. The profile sets exactly
`ChallengeID`, `DeviceID` and `Token` in that managed-preferences domain. Its
lifetime is at most 24 hours and never extends beyond the native certificate's
expiry. Repeated requests return the same active challenge.

Pending command bytes are encrypted. The challenge table and agent observation
store only the SHA-256 token hash. Administrator inventory, profile downloads,
command error text and audit records exclude proof tokens and profile contents.
The profile namespace is reserved against ordinary profile uploads and assignment.
All verification commands, including older cleanup attempts, remain classified as
internal and cannot be retried through generic command controls.

Consumption, cancellation, failure, expiry, revocation and check-out erase the
stored installation command bytes. A profile that was never delivered needs no
removal. Delivered profiles receive `RemoveProfile` for their unique identifier;
a late response for an older challenge cannot remove a newer challenge profile.
A new verification waits for earlier cleanup to finish.

Automatic cleanup has a six-hour retry interval and at most five attempts per
cycle. An authorized operator can retry a failed, expired or cancelled cleanup
immediately; retry after the fifth failure starts a new bounded cycle. Pending
commands show **Waiting for the Mac**. Successful removal completes cleanup.
A withdrawn MDM channel cannot perform removal; the console identifies the need
to remove the old MDM enrollment on the Mac. Server cleanup is not evidence of
physical removal in that case.

## Stable identity and conflicts

Optional migration `maclink_migrations/001_mac_devices.sql` runs after native MDM
and individual agent registry initialization. Apple-only installations remain
usable. `uem_mac_devices` holds the scoped canonical identity; separate MDM and
agent channel tables retain current and retired enrollment IDs. Composite foreign
keys enforce organization/site consistency across these records.

Association requires an installed, live challenge, its exact token hash and two
currently authorized identities. Identity locks serialize decisions with agent
revocation and hardware updates. Proofs, scope and database-time certificate
expiry are rechecked after lock waits. A site-level transaction lock serializes
competing associations. The association, challenge consumption, cleanup command
and audit event commit together. Failures roll back partial attachments.

To replace either channel, explicitly revoke the replaced identity or check out
the native enrollment, enroll its replacement in the same scope, and verify
again. A certificate merely expiring does not authorize replacement of an active
identity. When both channels are replaced, a fresh two-channel proof and the same
complete hardware tuple can recover the existing canonical identity. Previous
source IDs remain in history. Historical native GET links redirect to the current
Mac detail; mutation routes always address their original enrollment ID.

Multiple active proof holders, another active channel, inconsistent hardware,
legacy inventory assigned to another site, or already retired source identities
produce a conflict without silently transferring authority. Resolve replaced
identities before retrying. A hardware identity change is intentionally unresolved;
this change does not provide a manual hardware-repair or cross-site merge tool.
A new hardware platform UUID does not establish continuity with a previous Mac.

Canonical device reads do not grant legacy desktop action permission. The agent
inventory/actions link appears only for a global administrator and only when the
current legacy inventory is complete (hardware, OS and release) and has exactly
the same site. MDM actions keep their own
capability checks. Both channels have separate health and certificate state.
The legacy overview displays unknown status when optional antivirus or update
inventory has not been reported, instead of dereferencing absent inventory.

## Authenticated evidence path and upgrade order

The console pins shared protocol `249bb9d5e690`. Registry migration 003 creates
`uem_agent_hardware` with a composite organization/site/identity foreign key. The
broker authorization service includes the device-scoped `hardware` operation.
Ordinary inventory JSON remains unchanged.

The Mac agent distinguishes installation UUID, platform UUID and provisioning
UDID. It sends the separate RPC only when an individual worker advertises version
1. Windows, legacy agents and unsupported versions skip it. Upgrade the console,
registry and broker authorization before the worker, reconnect devices to refresh
broker permissions, and update agents last.

The worker checks bounded strict JSON, subject/body identity, platform, existing
desktop scope and current registry authorization. Only a committed observation
receives a successful receipt. Hardware changes and their audit receipt commit
together; unchanged reports refresh observation time without duplicate events.

The agent reads `/Library/Managed Preferences/eu.openuem.device-binding.plist` at
send time. It accepts bounded XML/binary plists from a root-owned regular file
through protected directory descriptors. Proofs are excluded from ordinary report
serialization and logs. An observation without a proof clears old proof columns;
it does not remove an already established canonical association.

## Verification evidence and remaining acceptance

- PostgreSQL tests exercise actual native SCEP enrollment, MDM profile delivery
  and receipts, individual registry claims and hardware persistence, consumption,
  cleanup retries, expiry, revocation, check-out and audit rollback.
- Association tests cover Intel/silicon identifier rules, multiple active claims,
  concurrent replicas, proof changes and expiry during lock waits, scope changes,
  canonical reads and replacement of either or both channels without losing history.
- Real console-router tests cover scope, capability and CSRF checks, one-row
  grouping, historical GET aliases, unchanged mutation targets and the legacy
  action boundary. Render tests cover pending, conflicting, cleanup and linked
  states, including readers without mutation controls.
- Browser checks at 390, 768 and 1440 pixels cover all five verification states,
  keyboard access to channel history, visible controls and no page overflow.
  A loopback browser fixture also exercises repeated verification/cancellation
  through production forms, cookie/Origin CSRF middleware and PostgreSQL.
- The shared protocol, agent and worker have real PostgreSQL and TLS/NKey/WSS
  evidence: [shared-library CI](https://github.com/the-luap/openuem-nats/actions/runs/34247709134),
  [agent CI](https://github.com/the-luap/openuem-agent/actions/runs/34247941275),
  [worker CI](https://github.com/the-luap/openuem-worker/actions/runs/34247933994).

These fixtures do not establish physical-device acceptance. Verify a real Intel
Mac and an Apple-silicon Mac separately: native enrollment, agent installation,
managed preference delivery/read/removal, renewal, re-enrollment and resulting
inventory/profile continuity. Actual signing, vendor credentials and device
operations remain separate acceptance work. Apple's
[managed-preferences schema](https://github.com/apple/device-management/blob/67045e2fa06f528b196c01edee6a8bf88b844beb/mdm/profiles/com.apple.ManagedClient.preferences.yaml)
defines the payload used for challenge delivery.

# Native Mac management

The native Apple module accepts manual Mac Device Enrollment alongside iPhone and
iPad enrollment. This implements part of MAC-01 and MAC-02 in the
[roadmap ledger](implementation-status.md). Native and agent channels can share a
verified Mac identity, and new enrollments support separately managed user
channels. FileVault supports staged profiles, encrypted recovery escrow and
audited retrieval, authenticated validation and journaled rotation. Broader Mac
security workflows and physical-device acceptance remain open. See [channel linkage](macos-agent-mdm-linkage.md),
[Mac user management](macos-user-channels.md) and [FileVault](macos-filevault.md).

## Enroll and identify a Mac

An authorized administrator creates an invitation in **Apple setup & enrollment**.
The invited browser selects **Mac**, confirms the organization and downloads the
SCEP enrollment profile. Open the profile and complete the prompts in System
Settings → General → Device Management; older macOS versions use a different
Profiles location. The page remains pending until device registration finishes.
See [Apple's Mac profile instructions](https://support.apple.com/en-gb/guide/mac-help/mh35561/mac).

The selected platform determines instructions and advertised bootstrap-token
support. It does not grant management capabilities. Authenticated model evidence
identifies the platform, and a reported platform that conflicts with the selection
or the existing enrollment is rejected. The generated database column distinguishes
`ios`, `ipados`, `macos` and `unknown`; pending invitations are not assumed to be
phones. An authenticated partial response preserves existing model/version data.
Unknown or missing versions first receive DeviceInformation before additional
commands become eligible. A newly reported version schedules the additional fields
and commands without waiting for the six-hour inventory interval.

The `/devices` filters distinguish Windows, Linux, macOS, iOS, iPadOS, Apple MDM and
unknown platforms. The existing `/ios` route remains an Apple MDM list alias, and
existing `/ios/:id` detail links continue working for native Apple devices.
Organization/site permissions apply to Mac inventory, enrollment, profiles,
updates, identity renewal and read audits.

New Mac invitations can explicitly include device lock and passcode removal
rights for Recovery Lock management. The administrator needs device security
permission, and the device owner separately confirms the rights. Existing
enrollments retain their original rights through renewal. This option does not
itself set a password; see [Recovery Lock scope and progress](macos-recovery-lock.md).

New Mac enrollment profiles advertise `com.apple.mdm.bootstraptoken` and
`com.apple.mdm.per-user-connections`. Their saved layout retains these capabilities
during automatic identity replacement. Existing device-only Mac enrollments stay
device-only when renewed. Existing
phone/iPad enrollment layouts retain their original capabilities. See
[SCEP enrollment](apple-scep-enrollment.md) and
[identity renewal](apple-identity-renewal.md) for the cryptographic lifecycle.

## Capabilities and inventory

The server derives action eligibility from the persisted platform and OS version.
These thresholds describe implemented protocol support, not hardware acceptance.

| Capability | iPhone / iPad | Mac |
| --- | --- | --- |
| System profiles | iOS 4+ | macOS 10.7+ |
| Installed applications | iOS 5+ | macOS 10.7+ |
| Declarative management | iOS/iPadOS 15+ | macOS 13+ |
| Specific OS update enforcement | iOS/iPadOS 17+ | macOS 14+, reported supervision and readiness checks below |
| DDM software update identifier | iOS/iPadOS 18+ | macOS 15+, reported supervision |
| Bootstrap-token exchange | Not implemented | macOS 10.15+, enrolled device identity |
| User channel | Not implemented | macOS 10.7+, new per-user enrollment; user profile lifecycle |
| FileVault profiles and recovery escrow | Not applicable | macOS 10.13+, device channel; user approval or supervision on 10.15+ |

The version and channel thresholds follow Apple's pinned
[profile command](https://github.com/apple/device-management/blob/67045e2fa06f528b196c01edee6a8bf88b844beb/mdm/commands/profile.install.yaml),
[application inventory](https://github.com/apple/device-management/blob/67045e2fa06f528b196c01edee6a8bf88b844beb/mdm/commands/application.installed.list.yaml),
[declarative command](https://github.com/apple/device-management/blob/67045e2fa06f528b196c01edee6a8bf88b844beb/mdm/commands/declarativemanagement.yaml) and
[specific update declaration](https://github.com/apple/device-management/blob/67045e2fa06f528b196c01edee6a8bf88b844beb/declarative/declarations/configurations/softwareupdate.enforcement.specific.yaml)
schemas.

Mac inventory requests supervision from 10.15, ProvisioningUDID from 11.3, Apple
silicon and SoftwareUpdateDeviceID from 12, and battery information from 13.3.
Macs do not receive phone-only capacity, locator or Activation Lock queries.
SoftwareUpdateDeviceID also comes from DDM status on eligible OS versions; the
classic field is deprecated in OS version 26. An update identifier is required
for Mac catalog matching; the marketing model is not substituted. ProvisioningUDID
is distinct evidence and is not treated as proof of agent/MDM linkage. See Apple's
[device inventory schema](https://github.com/apple/device-management/blob/67045e2fa06f528b196c01edee6a8bf88b844beb/mdm/commands/information.device.yaml).

Mac SecurityInfo responses retain only an explicit set of non-secret management,
bootstrap and FileVault state fields, plus their collection time. Recovery
material goes to the separate encrypted FileVault store, never general inventory.
Supervision distinguishes reported false
from not yet reported. An upgrade recovers the reporting flag only from a boolean
in existing inventory, rather than inferring it from an enrollment label.

Profiles use the device channel and System scope. An explicitly different or
malformed PayloadScope is rejected; it is not silently converted. Payload-specific
OS support and approval requirements still matter, and devices can reject a
profile. Assignment, acknowledgement and verified ProfileList state remain separate.

## Bootstrap-token escrow and update readiness

Bootstrap tokens are opaque authorization material. The Mac can store, replace,
retrieve or clear its own token through its certificate-authenticated check-in
endpoint. Token messages do not require UDID; if supplied, it must match exactly.
User-channel fields, other device identities, candidate or retired renewal keys,
revoked enrollments and phone/iPad requests cannot access Mac escrow. Empty or
omitted token data clears escrow; the data limit is 64 KiB. This follows Apple's
[SetBootstrapToken](https://github.com/apple/device-management/blob/67045e2fa06f528b196c01edee6a8bf88b844beb/mdm/checkin/setbootstraptoken.yaml) and
[GetBootstrapToken](https://github.com/apple/device-management/blob/67045e2fa06f528b196c01edee6a8bf88b844beb/mdm/checkin/getbootstraptoken.yaml)
Mac device-channel definitions. The separate iOS 26/ADE token flow is not enabled.

Escrow uses authenticated encryption bound to organization, device and purpose.
The database enforces the organization/device relationship. Console inventory
contains only an escrow-presence flag; there is no administrator token-download
endpoint. Store, read and clear operations require a committed audit receipt,
with no token contents in audit metadata. Failed audit or database writes roll
back changes. Checkout and revocation delete active escrow; backups need their
own retention policy. Confirmed device-key renewal preserves the token and moves
access to the newly active identity.

OpenUEM applies the following conservative readiness checks before issuing a Mac
update policy: macOS 14+, explicit supervision, security inventory no older than
24 hours, reported user-approved Device Enrollment, and a known processor family.
Apple silicon additionally requires allowed bootstrap authentication, reported
bootstrap update authorization and an escrowed token. Intel does not require
escrow for this gate. Missing evidence keeps enforcement unavailable and explains
what to refresh in the device page. These are server preconditions; Apple still
checks installation conditions. A token-enabled user may need to sign in before
macOS escrows a token. See Apple's
[bootstrap-token guidance](https://support.apple.com/guide/deployment/use-secure-and-bootstrap-tokens-dep24dbdcf9e/web)
and [software update behavior](https://support.apple.com/guide/deployment/install-and-enforce-software-updates-depd30715cbb/web).

Release selection uses the `macOS` group in Apple's GDMF catalog and the reported
software update identifier, version/build and availability dates. Mac enrollment
does not issue the legacy AvailableOSUpdates query, whose results require a
separate scan and do not describe DDM-managed updates. Phone/iPad use of that
query requires reported supervision and iOS 9–25. See Apple's
[legacy update query schema](https://github.com/apple/device-management/blob/67045e2fa06f528b196c01edee6a8bf88b844beb/mdm/commands/system.update.available.yaml).

A token or capability change reconciles the update policy in the same transaction.
Lost authorization withdraws the declaration even if catalog data is stale.
Restoration requires both readiness and a current compatible catalog entry. The
periodic reconciler also checks freshness. Desired version and deadline remain
visible while unavailable, and the administrator can remove the policy. DDM
responses recalculate current capabilities; a stale policy alone cannot grant
update authorization. Fresh OS inventory, rather than push acceptance, determines
compliance.

## Verification and remaining acceptance

The [agent and MDM association](macos-agent-mdm-linkage.md) uses a temporary native
MDM profile and an independently authenticated agent proof to establish one scoped
Mac identity. Challenge expiry/cleanup, conflicting evidence, revocation, concurrent
association and re-enrollment history have PostgreSQL coverage. The shared detail
retains separate MDM and agent authorization; legacy actions remain restricted to
global administrators. Hardware observations alone never merge records.

Automated PostgreSQL, SCEP and HTTP/TLS tests cover Mac enrollment and instructions,
platform filters, minimal-inventory discovery, profile install/remove verification,
version gates, DDM update identifiers and catalog isolation. Bootstrap tests cover
encryption, malformed inputs, organization boundaries, audit rollback, renewal
access transfer, concurrent revocation, migration backfill, checkout and update
withdrawal. Tests do not contact
APNs or install profiles on physical devices.

Rendered Mac enrollment, Mac detail and the shared device list were checked at
390, 768 and 1440 pixels, including disabled update enforcement and keyboard help.
The native macOS/Safari installation prompts, actual token escrow, update/reboot
continuity and agent/MDM linkage still need hardware acceptance
as recorded in the roadmap. Subsequent changes add
[FileVault escrow and validation](macos-filevault.md) and a
[firewall profile editor](macos-firewall.md). Recovery Lock, key rotation and
broader profile/security templates remain open.

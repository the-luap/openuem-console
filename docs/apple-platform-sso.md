# Mac Platform SSO profiles

The profile editor creates a System-scoped Extensible SSO configuration using
the modern `PlatformSSO` dictionary. It requires macOS 14 or later, an installed provider extension,
provider support for the selected authentication method, and fresh user-approved
MDM security inventory before assignment.

## Provider and account settings

The editor accepts the extension bundle identifier, developer team identifier,
identity-provider URL prefixes, authentication method, account display name,
shared device keys and optional login-window account creation. Login-window
account creation requires shared device keys and Password or Smart Card
authentication. Setup Assistant options retain their operating-system and
provider defaults unless the operator selects unattended ADE setup. This mode
requires macOS 26, shared keys and login-window account creation; it explicitly
enables registration during setup and disables first-user creation during setup.
The editor does not verify that the provider extension is
already installed.

Optional provider data is entered as a JSON dictionary and converted into plist
values. The parser preserves booleans, integers, real numbers, strings, arrays
and nested dictionaries. It bounds input size, depth and element count, rejects
duplicate keys, and rejects null because plist has no equivalent value.

An optional provider-issued registration token remains a top-level
`RegistrationToken`. Saved profiles and queued command payloads are encrypted.
The token is excluded from ordinary profile-list HTML; authorized profile
managers can download the complete configuration, including the token. The
operator must use the provider's documented token scope and validity rules.

## Assignment and compatibility

The same validation applies to editor output and uploaded Platform SSO payloads.
Legacy top-level authentication supports the macOS 13 shape; modern nested
authentication requires macOS 14. Shared device keys are System-only. Uploaded
`EnableRegistrationDuringSetup` and `EnableCreateFirstUserDuringSetup` switches
require macOS 26. Ordinary Credential/Kerberos SSO payloads do not inherit
Platform SSO-specific restrictions.

Uploaded profiles also validate routing across their Extensible SSO payloads,
including ordinary Redirect and Credential configurations. Duplicate URL prefixes
use case-insensitive scheme and host matching; paths remain case-sensitive.
Credential host names are compared case-insensitively. Distinct URL prefixes and
wildcard suffixes remain allowed. The URL and host namespaces are separate, and
fields that Apple ignores for a payload type do not create reservations.

Assignments reserve their exact retained routing revisions under the device's
transaction lock. A catalog update, ADE correction or cancelled sent command does
not free the previous routes. Only a newly accepted profile inventory that
verifies the replacement UUID or removal releases them. A conflicting assignment
or failed audit rolls back its reservations, commands and profile revision.
Reservation rows contain snapshot references; URL values and provider credentials
stay in encrypted profile history. A missing legacy snapshot remains unresolved
until replacement or removal is verified.

System profiles are checked against the device and its managed users. Separate
user channels retain separate effective profile sets. The same Platform SSO
extension and team can configure both System and User scopes: Apple merges their
settings, with device values taking precedence. This does not permit duplicate
routes within the same channel or between unrelated providers.
[Apple's device/user Platform SSO configuration](https://developer.apple.com/documentation/devicemanagement/configuring-platform-single-sign-on)

These checks cover profiles managed through the native assignment workflow.
Inventory does not expose another management system's provider URL configuration,
so installation verification and physical-device acceptance remain necessary.

Batch assignment and profile revision updates must pass platform and approval
checks before committing. Removing a profile remains possible after those
prerequisites change. A verified profile assignment means the configuration was
reported installed. It does not establish provider registration, account
creation, credential synchronization or successful sign-in.

[Retained profile revisions](apple-profile-revisions.md) provide separately
encrypted immutable history, protected downloads and confirmed restoration as a
new revision. Restoration rechecks current Mac compatibility and queues fresh
UUID verification for active assignments. Deleting an unused catalog entry keeps
its protected history, including any historical provider credentials.

## Unattended ADE prerequisites

An ADE enrollment profile can bind an immutable System profile revision to an
approved provider application revision. The operator must confirm the extension
and provider's silent registration support and record a review reason. The policy
also requires macOS 26, automatic advance, the Setup Assistant hold and a managed
administrator with primary account creation skipped.

The ADE form searches current SSO profiles in pages of 25. It identifies profiles
that still need unattended setup configuration, retains selected snapshots across
searches, and includes the provider app in the maximum of 16 required applications.
Search results contain metadata and eligibility, never registration tokens or
provider configuration dictionaries. Profile read permission is required in
addition to organization ADE access; creating the binding additionally checks
profile assignment, software assignment and account-management permissions.

Admission retains the reviewed profile/app pair. Catalog revisions do not advance
that enrollment's profile assignment while its setup hold remains active.
Ordinary assignment, removal and host-app version changes cannot bypass the
requirement. Setup release requires fresh verification of the retained profile
and the existing exact-version managed application checks. A device must report
that its hold ended before ordinary profile ownership resumes. Provider
registration begins after `DeviceConfigured` and is not a pre-release condition.

The device page shows the current reviewed pair, profile verification and its
retained review and repair histories. Before release dispatch, an authorized
operator can resend the same snapshot with confirmation and a reason. That action
queues profile delivery and fresh inventory and commits its immutable repair
receipt and audit event together. History is scoped to the device and organization
and paginated at 100 records. An installation observation or a repair request does
not establish successful identity-provider registration.

Before the first setup-release dispatch, the operator can correct the two
required revisions together. Both selections must belong to the original profile
and provider application; the application revision must remain approved and
compatible. The form requires a renewed provider confirmation and a reason.
Profile assignment, application delivery, the reviewed pair and audit records
commit in one transaction. A failure rolls back all of them. A sent installer
with an unresolved outcome prevents an application revision change. A profile-only
correction can retain that application revision, while setup still waits for its
installation evidence.

The original requirement stays immutable. Each correction has its own retained
revision identifier and links to its predecessor. Forms name that exact reviewed
revision, so an old form remains stale even if later corrections return to the
same profile/app combination. Corrections require profile observations from a
query created after the new review. Repair receipts reference the exact reviewed
pair and profile snapshot that they resend. The migration preserves every
original receipt field while attaching the historical pair reference.

An earlier setup-release dispatch keeps prerequisite changes and profile repairs
closed even when a failed release is explicitly retried. The checks consult all
retained release attempts for the enrollment, because retrying replaces the current
command pointer. Retrying release with the same prerequisites remains supported.

## Validation and remaining acceptance

Tests cover typed payload placement, invalid URL and
account-policy combinations, legacy/modern/version boundaries, user-channel
restrictions, bounded provider JSON, encrypted storage, rejected assignment
batches, revision rollback and console permissions.

At [`a1d9a4a`](https://github.com/the-luap/openuem-console/commit/a1d9a4affbf04250b32454e1c7ba96d09d3e2935),
both complete workflows passed all four jobs in
[PR CI](https://github.com/the-luap/openuem-console/actions/runs/34325631687) and
[push CI](https://github.com/the-luap/openuem-console/actions/runs/34325627197).
This includes Linux/Windows builds, native Windows checks, synthetic console
renderings, scoped console routes, the native Apple race suite, gateway and
authorization checks, existing model tests and desktop agent regression.

Browser checks used the actual CI-rendered profile page at 390, 768 and 1440
pixels. All three passed expanded-form layout, keyboard validation and
confirmation, exact provider values, System scope and CSRF checks without page
overflow. An isolated fuzz harness copied the unchanged production provider
parser, text validator and fuzz property, recorded source SHA-256 values, and
passed 28,837 inputs in 21.414 seconds. Accepted dictionaries were encoded and
decoded as plist. Full native integration tests remain distinct from this
focused parser check.

No real identity-provider registration, account creation or profile deployment
was performed. Physical-device and provider-specific acceptance remain open.

Immutable profile history, ADE prerequisites and the combined revision correction
workflow are implemented. An app-only correction cannot change an active provider
binding. Cross-profile routing reservations are implemented with full integration
validation pending. Provider-specific registration evidence and token provisioning
remain open.

The ADE binding and unattended editor at `2eaeb5d` passed both complete workflows:
[push CI](https://github.com/the-luap/openuem-console/actions/runs/34339173364) and
[PR CI](https://github.com/the-luap/openuem-console/actions/runs/34339178970).
The native Apple race suite passed in 566.538 seconds, scoped console routes in
12.160 seconds, and desktop regression in 26.896 seconds in the push run. The
profile/app picker at `f31e044` also passed its
[complete push workflow](https://github.com/the-luap/openuem-console/actions/runs/34339525979).

Thirty-six browser scenarios used the actual CI-rendered pages from `67b968c` at
390, 768 and 1440 pixels: three unattended editor cases, three ADE selection cases,
21 device status/repair/history cases, six paired correction cases and three
reviewed revision history cases. They passed keyboard operation, required confirmation
and reasons, optional-field activation, escaped display text, pagination, failed
and stale search replies, retained selections, scoped form bodies, CSRF and role
restrictions without page overflow.

The status/repair fixture fix at `c32763d` passed both complete workflows:
[push CI](https://github.com/the-luap/openuem-console/actions/runs/34340874284) and
[PR CI](https://github.com/the-luap/openuem-console/actions/runs/34340878052).
The historical dispatch guard at `bf1bf25` also passed both complete workflows:
[push CI](https://github.com/the-luap/openuem-console/actions/runs/34341231423) and
[PR CI](https://github.com/the-luap/openuem-console/actions/runs/34341236033).

The paired correction at `67b968c` passed all four jobs in both complete workflows:
[push CI](https://github.com/the-luap/openuem-console/actions/runs/34344021741) and
[PR CI](https://github.com/the-luap/openuem-console/actions/runs/34344025025).
The push run passed the native Apple race suite in 588.807 seconds, scoped console
routes in 12.011 seconds and desktop regression in 28.495 seconds. Local checks
applied all 32 migrations and
prepared 282 production statements plus 13 synthetic route fixture statements.
An isolated PostgreSQL check preserved existing reviews and repair receipts,
rejected history changes and stale predecessor pointers, and enforced exact
repair-to-pair references, approved applications and the historical release guard.
The integration cases additionally exercise concurrent corrections, audit failure
rollback, unresolved installers, 101-record pagination, a return to the original
pair with a new review identifier and fresh profile verification.

The subsequent within-profile routing parser passed 32 table-driven cases and two
ignored-field checks in an isolated Go harness. The harness copied the production
routing implementation, text validation and dictionary accessor without changes
and recorded their source hashes. The full-suite upload case separately exercises
two different provider payloads with duplicate URLs and then distinct URLs.

The reservation migration and five new production SQL statements pass an isolated
PostgreSQL check, bringing the checked totals to 33 migrations and 287 statements.
Existing System and User assignments retain both known dispatched revisions and
missing historical snapshots. The actual release queries preserve unresolved and
foreign-scope reservations, retain the installed revision after verification, and
free all revisions only for verified removal. Full integration cases cover sent
commands, wrong and delayed inventories, concurrent conflicting assignments,
audit and catalog rollback, user isolation, provider merging and migration
recovery; their CI results are pending. The native race-suite timeout is explicitly
20 minutes because the existing complete suite already takes nearly 10 minutes.

Sources checked 9 September 2026:

- [Apple Extensible SSO payload schema](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.extensiblesso.yaml)
- [Apple's unattended Platform SSO sequence](https://developer.apple.com/documentation/devicemanagement/implementing-platform-sso-for-unattended-device-enrollment)

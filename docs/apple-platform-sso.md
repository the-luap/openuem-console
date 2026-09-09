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

The device page shows retained revision metadata, current profile verification,
the provider review and repair history. Before release dispatch, an authorized
operator can resend the same snapshot with confirmation and a reason. That action
queues profile delivery and fresh inventory and commits its immutable repair
receipt and audit event together. History is scoped to the device and organization
and paginated at 100 records. An installation observation or a repair request does
not establish successful identity-provider registration.

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

The immutable profile and ADE prerequisite foundations are implemented. A combined
correction workflow for the profile and provider application revisions remains
open; an app-only correction cannot change an active provider binding. Cross-profile
URL collision checks, provider-specific registration evidence and token provisioning
also remain open.

The ADE binding and unattended editor at `2eaeb5d` passed both complete workflows:
[push CI](https://github.com/the-luap/openuem-console/actions/runs/34339173364) and
[PR CI](https://github.com/the-luap/openuem-console/actions/runs/34339178970).
The native Apple race suite passed in 566.538 seconds, scoped console routes in
12.160 seconds, and desktop regression in 26.896 seconds in the push run. The
profile/app picker at `f31e044` also passed its
[complete push workflow](https://github.com/the-luap/openuem-console/actions/runs/34339525979).

Twenty-seven browser scenarios used actual CI-rendered pages at 390, 768 and 1440
pixels: three unattended editor cases, three ADE selection cases and 21 device
status/repair/history cases. They passed keyboard operation, required confirmation
and reasons, optional-field activation, escaped display text, pagination, failed
and stale search replies, retained selections, scoped form bodies, CSRF and role
restrictions without page overflow.

The status/repair integration run at `05be000` detected that its synthetic fixture
reused a withdrawn application. The fixture now selects the still-approved
revision; a fresh complete CI run is required. The legacy profile migration fixture
now constructs its historical schema from preceding migration files so later
foreign keys cannot invalidate that setup. Local checks applied all 31 migrations
and prepared 272 production statements plus 11 synthetic route fixture statements
in an isolated PostgreSQL transaction.

Sources checked 9 September 2026:

- [Apple Extensible SSO payload schema](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.extensiblesso.yaml)
- [Apple's unattended Platform SSO sequence](https://developer.apple.com/documentation/devicemanagement/implementing-platform-sso-for-unattended-device-enrollment)

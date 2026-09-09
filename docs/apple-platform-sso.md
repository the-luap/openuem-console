# Mac Platform SSO profiles

Implementation and validation are in progress. The profile editor creates a
System-scoped Extensible SSO configuration using the modern `PlatformSSO`
dictionary. It requires macOS 14 or later, an installed provider extension,
provider support for the selected authentication method, and fresh user-approved
MDM security inventory before assignment.

## Provider and account settings

The editor accepts the extension bundle identifier, developer team identifier,
identity-provider URL prefixes, authentication method, account display name,
shared device keys and optional login-window account creation. Login-window
account creation requires shared device keys and Password or Smart Card
authentication. The editor does not enable first-user creation during Setup
Assistant or claim that the provider extension is already installed.

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

## Remaining work and acceptance

Full CI, browser acceptance and physical/provider verification are pending for
this implementation. Tests cover typed payload placement, invalid URL and
account-policy combinations, legacy/modern/version boundaries, user-channel
restrictions, bounded provider JSON, encrypted storage, rejected assignment
batches, revision rollback and console permissions.

Unattended ADE still needs an immutable SSO profile requirement bound to the
required extension application, managed administrator policy and setup sequence.
The extension and profile must be installed before `DeviceConfigured`; silent
provider registration begins afterwards. Cross-profile URL collision checks,
provider-specific registration evidence and token provisioning remain open.

Sources checked 9 September 2026:

- [Apple Extensible SSO payload schema](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.extensiblesso.yaml)
- [Apple's unattended Platform SSO sequence](https://developer.apple.com/documentation/devicemanagement/implementing-platform-sso-for-unattended-device-enrollment)

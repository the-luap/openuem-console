# macOS application firewall profiles

Organization and server administrators can create a firewall profile under
**Apple profiles → Create a Mac firewall profile**. Choose firewall and stealth
settings, optional automatic allowances for signed software, and app-specific
allow/block rules. App lists accept one bundle identifier per line and up to
64 rules in total. Duplicate identifiers, conflicting app rules and malformed
switch values are rejected. The profile always uses System scope.

Saving creates an organization profile. Assign it to Macs using the existing
profile controls. Installation requires macOS 10.12 or later; explicitly changing
either signed-software allowance requires macOS 12.3 or later. iPhone, iPad and
unknown-platform targets are rejected. Mixed incompatible batches roll back all
assignments. Revising a profile checks every assigned Mac before saving or
queueing the replacement. Removal uses the existing verified removal workflow.

The same field and platform checks apply to uploaded firewall profiles. Uploaded
legacy logging settings are restricted to macOS 12–14 because Apple removed them
in macOS 15. Other payload types retain their existing validation behavior.

Multiple firewall profiles can coexist; macOS combines their most restrictive
settings. Disabling the firewall in one profile does not override another profile
that requires it. Blocking incoming traffic can affect remote access and apps
that listen for connections. Review all assigned profiles when investigating a
conflict. Automatic conflict previews and firewall traffic acceptance on actual
Macs remain outstanding.

The implementation follows Apple's pinned
[firewall payload schema](https://github.com/apple/device-management/blob/67045e2fa06f528b196c01edee6a8bf88b844beb/mdm/profiles/com.apple.security.firewall.yaml).
Unit and PostgreSQL tests cover generated and uploaded payloads, platform/version
gates, atomic batch rejection, revision rollback and verified install/removal.
Console tests cover administrator permissions, CSRF, duplicate fields and saved
choices. Browser checks cover administrator, operator and viewer pages at 390,
768 and 1440 pixels, including keyboard expansion and form submission. The
profile page wraps long identifiers and action buttons within those widths.
A confirmed profile revision proves MDM installation, not the effective network
behavior of the firewall.

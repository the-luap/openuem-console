# Mac privacy profiles (PPPC/TCC)

The privacy editor creates one application rule for one selected service. Uploaded
profiles can include multiple rules and services. Profiles use the existing
encrypted catalog, immutable revision history, scoped assignment and verified
installation/removal workflow. Saving requires profile-management permission,
CSRF protection and explicit review confirmation.

## Supported policies

All 24 services in Apple's current PPPC schema are represented, with their minimum
macOS versions. The payload requires macOS 10.14 or later, System scope and
user-approved MDM; User Enrollment is unsupported. Later services require macOS
10.15, 11, 13 or 14. The server checks each present service, including empty lists.

Camera, microphone, input monitoring and screen capture cannot receive an access
grant from a profile. The latter two can let a standard user configure access on
macOS 11 or later. This permits a user decision rather than granting access.
Accessibility grants are deprecated from macOS 26.2 and unavailable from macOS 27;
denial remains supported. Conflicting profiles use the most restrictive policy.

The editor writes the legacy boolean `Allowed` for allow/deny and `Authorization`
for the standard-user choice. Uploads accept supported authorization strings but
require exactly one of these keys per identity. Unsupported service/policy pairs
are rejected. The console disables unavailable choices, reports when switching
services resets the policy to Deny and displays the selected version boundary.

## Application identity

Application bundles use a case-sensitive bundle identifier. Nonbundled binaries
use an absolute POSIX path without redundant segments. Each identity requires a
code requirement; Apple Events rules also require the receiver's identifier,
identity type and code requirement. Receiver fields on another service are
rejected, including inactive empty fields submitted by a client.

The server checks field types, length bounds, identifiers and paths. Code
requirement text is bounded and rejects invalid encoding and control characters
other than ordinary multiline whitespace. It does not compile Apple's requirement
language or inspect the target binary. The target Mac evaluates the supplied
requirement against the application; a syntactically accepted upload is not proof
of a matching signature. Obtain the expression from the signed target application
or its vendor and review it before deployment.

Static code validation is optional and omitted by default. The editor exposes it
for applications that invalidate their dynamic signature. Application helpers
inside a bundle inherit their enclosing application's permissions. Optional
comments remain descriptive text and do not change the privacy rule.

## Delivery and evidence

Assignments require fresh native security inventory showing user-approved MDM,
in addition to compatible platform and OS evidence. Mixed-device batches fail
atomically. Saving or restoring a revision rechecks active assignments and rolls
back catalog changes, retained snapshots and commands on failure. Compatible
allow/deny profiles can coexist because macOS applies its documented precedence.
Removing a profile uses fresh native profile inventory for verification.

The isolated core checks pass with unchanged production validation, platform and
version helpers, and data types. They cover all 24 services and policy choices,
minimum versions, macOS 27 grant removal, authorization exclusivity, bundle/path
identities, receiver requirements, malformed values and stale/future management
inventory. Template formatting/generation and JavaScript syntax checks pass.

Full native tests add mixed-platform and revision rollback, stale approval,
compatible conflicting-policy assignment, macOS 27 denial versus grant and
verified profile removal. Console tests cover roles, CSRF, repeated/unrelated and
query fields, forbidden grants, receiver fields, static code options, binary paths,
user-choice authorization and escaped display labels. Full CI and browser checks
for this change are pending.

Physical acceptance must verify signatures, user prompts and access behavior for
the intended applications and OS releases. Profile delivery alone does not prove
access was granted, denied or selected by a user. These tests do not change TCC
permissions, run a target application or install a profile on the development host.

Source checked 9 September 2026:
[Apple Privacy Preferences Policy Control schema](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.TCC.configuration-profile-policy.yaml).

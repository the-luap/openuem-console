# Required applications during Automated Device Enrollment

ADE profiles can pin approved Mac application revisions, inherit those
requirements at admission, and hold Setup Assistant until the exact managed app
versions are observed. The console provides application search, explicit
per-device revision correction and retained history. Platform SSO configuration,
provider registration and physical-device acceptance remain separate work.

## Console workflow

1. Approve the signed Mac package and exact bundle version in **Approved software**.
2. Open **Automated Device Enrollment**, select the connected Apple server and
   create a Mac profile with the Setup Assistant hold enabled.
3. Search approved applications and select one revision per application. Search
   and pagination preserve the selection; up to 16 applications can be required.
4. Publish the profile and assign its serial numbers. Each admitted Mac shows
   **Required setup applications**, its observations and links to operation history.

Operators with enrollment and software assignment authority can assign the
approved policy within their authorized scope. Creating the ADE policy and
correcting an admitted device's requirement additionally require organization
certificate-management authority. Software readers can inspect scoped status and
revision history. The picker and history never return package download URLs.

## Policy and delivery

A policy can require up to 16 approved macOS PKG revisions, with one revision per
application identity. It requires the Mac platform and the Setup Assistant hold.
Publishing and assigning the policy check software assignment authority in
addition to ADE enrollment authority. The policy's original package references
are immutable and checked against its encrypted profile definition.

The enrollment service uses the ordinary approved-artifact installation path.
Only the absence of an assignment permits an automatic first installation.
Deferred delivery keeps the same native command; failed, cancelled, expired and
unknown attempts require explicit operator action. Neither command acceptance nor
an older installed version releases Setup Assistant. Required observations must
show the selected managed app and exact bundle version, after command acceptance
and within the last day. Configuration-profile and account prerequisites still
apply. A sent `DeviceConfigured` command remains distinct from the device's
observed release of the MDM hold.

## Correcting an unavailable revision

Withdrawal prevents new delivery. A revision already installed and verified is
not retroactively treated as uninstalled. A required revision withdrawn before
installation keeps the hold in place.

A per-device correction must select another approved revision of the same
application and record a reason. The original profile requirement stays intact;
immutable history links the previous and replacement revisions to the actor and
reason. The change, native command and audit records commit together. Queued or
explicitly deferred app operations can be cancelled as part of the correction.
An unresolved sent installer cannot be replaced. Once a setup-release command
has been dispatched, the prerequisite cannot be changed for that admission.

No action silently drops a required app or rewrites the published profile.
Changes for future enrollments require a new ADE profile version.

## Validation

The 27 actual Apple migrations and 156 affected static application/ADE SQL
statements passed an isolated PostgreSQL migration and parameter-inference check.
Transaction-control statements are exercised by integration tests rather than
PostgreSQL `PREPARE`. Integration cases cover pinned admission, exact-version
readiness, withdrawal and correction, retained history, site boundaries, unknown
and cancelled operations, and invalid policy combinations. Console tests cover
role and site isolation, CSRF, repeated or unrelated form inputs, literal search
wildcards, withdrawn revisions, bounded pages, response privacy and escaped history.

The backend passed both complete CI workflows at
[`f1c445b`](https://github.com/the-luap/openuem-console/commit/f1c445b0d50f2c61ab4df3aeeb0980a981f29ba6).
The console and additional database tests at
[`1fd33bf`](https://github.com/the-luap/openuem-console/commit/1fd33bf7ad9a3fd04d3e3f0f71b4237467202687)
passed builds, render tests, console authorization tests and the complete native
Apple race suite in
[push CI](https://github.com/the-luap/openuem-console/actions/runs/34323651846) and
[PR CI](https://github.com/the-luap/openuem-console/actions/runs/34323655566).

Eighteen browser scenarios used the actual CI-rendered pages at widths 390, 768
and 1440 pixels. They verified selection limits, one revision per application,
pagination, empty/failed searches, out-of-order responses, repeated HTMX setup,
confirmation, keyboard operation, scoped form payloads and unavailable correction
controls. No horizontal page overflow occurred. The final picker accessibility
change at `45441e6` was rerun against all 18 scenarios, including focus following
the selected revision and descriptive screen-reader button labels.

Synthetic tests do not install packages or configure real Apple devices.
Installer ambiguity across retired and replacement enrollments now has explicit
[stopping-evidence recovery](apple-application-reenrollment.md), with a named ADE
waiting state and resumed exact-version verification. Physical reenrollment
acceptance remains open.
Unattended Platform SSO additionally requires its extension app and SSO profile
before `DeviceConfigured`; provider registration begins after that command.
[Apple's unattended Platform SSO sequence](https://developer.apple.com/documentation/devicemanagement/implementing-platform-sso-for-unattended-device-enrollment)

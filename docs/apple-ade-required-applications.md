# Required applications during Automated Device Enrollment

Implementation is in progress. The backend pins approved Mac application
revisions to an ADE enrollment profile, inherits those requirements at admission,
and holds Setup Assistant until the exact managed app versions are observed.
Console selection, per-device correction/history workflows and the complete
integration acceptance are still being completed. Platform SSO configuration and
provider registration remain separate work.

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

## Validation in progress

The 27 actual Apple migrations and 153 affected static application/ADE SQL
statements passed an isolated PostgreSQL migration and parameter-inference check.
Transaction-control statements are exercised by integration tests rather than
PostgreSQL `PREPARE`. Integration cases cover pinned admission, exact-version
readiness, withdrawal and correction, retained history, site boundaries, unknown
and cancelled operations, and invalid policy combinations. Their full CI result
is pending for this implementation.

Synthetic tests do not install packages or configure real Apple devices.
Unattended Platform SSO additionally requires its extension app and SSO profile
before `DeviceConfigured`; provider registration begins after that command.
[Apple's unattended Platform SSO sequence](https://developer.apple.com/documentation/devicemanagement/implementing-platform-sso-for-unattended-device-enrollment)

# Mac Recovery Lock

Recovery Lock is a password protecting access to recoveryOS on Apple silicon
Macs. It is separate from a user's login password and the FileVault personal
recovery key. The current implementation adds the enrollment permission needed
for this workflow. Password creation, verification, rotation, removal and audited
retrieval are still under implementation; this document does not claim those
operations or physical-device acceptance are complete.

## Enrollment permission

In **Apple setup & enrollment**, an administrator with both device enrollment and
device security management permission can select **Allow Recovery Lock and device
lock management (Mac only)**. It is off by default. The invitation is then limited
to Mac enrollment, and the invited browser must separately confirm these rights
before downloading its SCEP profile. Operators can still create ordinary device
invitations, but cannot request additional lock rights.

The choice adds Apple's `DeviceLockAndRemovePasscode` access-right bit (`4`) to
the existing `7955` mask, producing exactly `7959`. It grants device lock and
passcode removal rights; it does not include device erase (`8`). Installing the
profile does not itself set a Recovery Lock password. Apple's
[MDM payload schema](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.mdm.yaml)
defines these bits and forbids adding access rights when updating a profile.

Existing invitations and enrollments retain `7955`. To obtain the additional
permission, an existing Mac needs a new enrollment created with this option.
Coordinate that enrollment change with the device owner; identity renewal cannot
add these rights. The Mac detail page reports the enrollment permission separately
from device security state.

## Persistence and authorization

Migration `018_enrollment_device_lock.sql` adds the immutable invitation choice
`mdm_apple_devices.device_lock_allowed`, defaulting to false. A database trigger
rejects changes to that choice. Saved enrollment layouts must match the choice,
and additional rights require a Mac platform claim. The layout trigger also
rejects changed access rights during renewal.

The console rechecks persisted enrollment and security permissions inside the
invitation transaction. Permission and site ownership locks remain held through
insertion and audit. An additional `apple.enrollment.device_lock.allow` event
records the explicit choice under the administrator and device identifier.
Failure of either audit insert rolls back the invitation.

Public form values cannot upgrade an ordinary invitation. Mac-only invitations
reject missing, non-Mac or conflicting platform claims. Browser confirmation,
CSRF protection and bounded identical-profile retries apply. Identity renewal
retains the original rights through replacement-key activation. Recovery of lost
layout UUIDs reads the immutable stored invitation choice; neither reported Mac
hardware nor the `ProfileList` response is treated as proof of additional rights.
An existing layout that conflicts with that choice is rejected.

The `device_lock_allowed` inventory field describes the invitation permission.
It is not evidence that a Recovery Lock password exists, matches an escrowed
password or was removed.

## Remaining protocol and acceptance work

Apple documents `SetRecoveryLock` and `VerifyRecoveryLock` for Apple silicon,
macOS 11.5 or later, on the device channel. User Enrollment is excluded. Setting
or rotating an existing password requires its current password; an empty new
password requests removal. MDM unenrollment removes the recovery password.
See Apple's [set command](https://github.com/apple/device-management/blob/release/mdm/commands/passcode.recovery.set.yaml)
and [verify command](https://github.com/apple/device-management/blob/release/mdm/commands/passcode.recovery.verify.yaml).

The schema marks supervision as unnecessary, while the
[developer reference](https://developer.apple.com/documentation/devicemanagement/set-recovery-lock-command)
lists supervision as required for macOS. Command eligibility must resolve this
discrepancy or conservatively require reported supervision. Enrollment permission
alone is insufficient evidence of command eligibility.

The remaining workflow needs encrypted password history, dedicated retrieval
authorization and audit, at most one mutation delivery per attempt, independent
candidate verification, durable uncertainty handling, and explicit correlation
of late responses. A negative password verification cannot establish that
Recovery Lock is disabled. Real enrollment, renewal, recoveryOS access, password
rotation/removal and offline/error behavior require separate Mac acceptance.

Tests cover exact access masks, additive migration and replay, immutable choices,
platform confusion, duplicate form parameters, owner confirmation and CSRF,
scoped roles and revoked permissions, atomic audit failure, identical profile
downloads, SCEP identity replacement/activation, and conservative layout recovery.
They use disposable PostgreSQL schemas and synthetic device peers.

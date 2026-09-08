# Mac Recovery Lock

Recovery Lock is a password protecting access to recoveryOS on Apple silicon
Macs. It is separate from a user's login password and the FileVault personal
recovery key. OpenUEM implements opt-in enrollment rights, encrypted password history,
creation, import, verification, rotation, removal and separately authorized
retrieval. These workflows use native device-channel commands. Physical Mac
acceptance remains open; synthetic results are not evidence of recoveryOS access.

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

## Eligibility and protocol

Apple documents `SetRecoveryLock` and `VerifyRecoveryLock` for Apple silicon,
macOS 11.5 or later, on the device channel. User Enrollment is excluded. Setting
or rotating an existing password requires its current password; an empty new
password requests removal. Apple documents that MDM unenrollment removes the
recovery password. Server-side revocation alone is not device unenrollment and
is not evidence that the password was removed. See Apple's
[set command](https://github.com/apple/device-management/blob/release/mdm/commands/passcode.recovery.set.yaml)
and [verify command](https://github.com/apple/device-management/blob/release/mdm/commands/passcode.recovery.verify.yaml).

The schema marks supervision as unnecessary, while the
[developer reference](https://developer.apple.com/documentation/devicemanagement/set-recovery-lock-command)
lists supervision as required for macOS. OpenUEM conservatively requires reported
supervision, reported Apple silicon, device and security inventory no older than
24 hours, no reported User Enrollment, and a management certificate valid for
more than one minute. It rechecks the immutable enrollment layout before both
queueing and delivery. The inventory query currently requests Apple silicon
information on macOS 12 or later, so macOS 11.5 without that evidence remains
unavailable. Refresh inventory if the readiness explanation requires it.

## Password workflow

Administrators with `ManageDeviceSecurity` can use the Mac's **Recovery Lock**
panel. Setting, rotating, removing and importing require an explicit confirmation
in addition to CSRF protection. The server rechecks persisted permissions and
scope inside the transaction that stores the operation and its audit event.

- **Set and escrow password** generates 32 random bytes encoded as a 43-character
  password. OpenUEM stores it encrypted before any delivery. An existing unknown
  password must be imported first; OpenUEM does not guess or bypass it.
- **Import and verify password** stores the supplied password encrypted and sends
  only `VerifyRecoveryLock`. Successful verification makes it the managed current
  password. Import preserves whitespace and accepts valid XML characters up to
  1,024 UTF-8 bytes; this is an OpenUEM limit, not a claimed Apple protocol limit.
- **Verify current password** requests another read-only check.
- **Rotate password** first verifies the current password. Only a timely positive
  response can authorize a change. The distinct generated replacement becomes
  current only after its own positive verification, not on Set acknowledgment.
- **Remove password** first verifies the current password and then sends an empty
  new password. Its terminal state is **removal acknowledged**. This does not claim
  independent verification that no password exists.

Only one active operation is allowed for each device. A change payload is
consumed on its first committed delivery and is never sent again, including
through the generic command retry route. Read-only checks can be redelivered.
A database guard also prevents replaying a delivered mutation. The command
lifetime is at most one hour and never exceeds the management certificate's
expiry. A failed delivery transaction returns no plaintext command and preserves
its undelivered state.

## Unresolved results and retained history

A lost Set acknowledgment or `NotNow` does not cause another password change.
The next eligible connection checks the proposed password. Its positive result
can resolve a set/rotation whose acknowledgment was lost. A negative check does
not prove that Recovery Lock is disabled or that a previously delivered change
can no longer execute, so the attempt remains unresolved and blocks further
changes. Candidate checks can be explicitly requested again.

Checking a retained previous password can resolve an uncertain rotation only
after the exact Set command has returned acknowledgment or error. A previous
password match alone is insufficient while the change may still execute.
Removal without its final response remains unresolved; OpenUEM cannot infer
absence from a rejected password. A late removal acknowledgment is accepted.

Responses must match the device, attempt and selected check. Superseded checks,
duplicate final responses and responses to completed attempts cannot promote
historical passwords or refresh evidence. Verification timestamps use dispatch
time as a conservative observation bound, so a delayed response is not displayed
as a newly performed check. Invalid responses and device errors produce fixed
error codes; arbitrary device error text is not retained.

Password history is retained across failed operations, removal, checkout and
server-side revocation. Each password uses authenticated encryption bound to
its tenant, device and key identifier, separately from encrypted command data.
Identical imported passwords reuse their retained entry. History is capped at
128 distinct passwords per device and each attempt at 32 commands; reaching a
limit refuses further queueing and preserves existing records. Do not delete
records to force another change while an outcome is unresolved.

`RetrieveRecoveryKeys` is required to see password history controls and retrieve
an individual password through a CSRF-protected, audited POST. The response is
plain text with caching disabled and restrictive framing/content headers. No
password appears in device metadata, ordinary pages or audit details. Keep the
OpenUEM master secret with the protected database backup: password ciphertext
alone is insufficient for recovery.

## Validation and remaining acceptance

Automated coverage includes exact enrollment masks and immutable renewal rights,
password escaping and byte boundaries, readiness changes, native set/rotate/remove
sequences, lost/late/duplicate results, expired preflight, strict verification
booleans, encrypted history, authorization and scope, audit/delivery rollback,
concurrent requests and polls, revocation, and real-console role/CSRF/form handling.
Tests use disposable PostgreSQL schemas and synthetic certificate-authenticated
peers; they never invoke password or recovery commands on the development host.
Rendered fixtures cover eligible, active, uncertain, removed, stale and restricted
views. Current execution evidence is recorded in the implementation ledger.

Physical acceptance must separately demonstrate opt-in enrollment and renewal,
recoveryOS access with the retained password, existing-password import, rotation,
removal, offline and error behavior, and unenrollment. Recovery Lock does not
complete the broader MAC-02 package, local administrator password management,
FileVault recovery acceptance or the full roadmap.

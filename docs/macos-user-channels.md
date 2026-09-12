# Managed Mac user channels

New manual Mac enrollments advertise `com.apple.mdm.per-user-connections`.
Device and user channels share the enrollment certificate, but use separate push
credentials, commands, profile assignments and profile inventory. User management
requires macOS 10.7 or later and an enrollment that advertised this capability.
Existing enrollments retain their original channel configuration during certificate
renewal; enabling user channels on a device-only enrollment requires re-enrollment.

## Console workflow

Open a Mac and select an account under **Managed Mac users**. The account appears
after macOS sends UserAuthenticate or a user TokenUpdate. The installing local
user and eligible network/mobile users follow Apple's enrollment rules; creating
an arbitrary local account does not automatically make it managed.

Create a configuration with **User** scope in the profile editor, or upload a
mobileconfig whose root `PayloadScope` is `User`. Select that profile on the user
page. System profiles remain device assignments. Scope and root identifier cannot
change when editing a saved profile. A new revision queues current assignments
on active channels; resuming a paused channel also uses the latest revision.

Installation acknowledgement changes the assignment to **Verifying on device**.
A subsequent user ProfileList must report the assigned revision's UUID before
installation is verified. The query must follow the assignment acknowledgement;
an older retained revision is checked against its own immutable snapshot. Apple's
[ProfileList schema](https://github.com/apple/device-management/blob/release/mdm/commands/profile.list.yaml)
does not return `IsManaged` on macOS, so this field is not required. Removal
requires a later inventory without that profile
identifier. A stale, duplicated, superseded or different user's response cannot
verify the assignment. Failed and expired commands can be retried only while they
still represent current desired state. A retry receives a new command UUID.

The query creation time also orders accepted inventory snapshots. A delayed older
query cannot overwrite a newer profile list, change its receipt time or reverse
its verification result. Migration 030 starts recording this boundary with the
next accepted report when historical query provenance is unavailable.

**Pause this user** clears push credentials and cancels pending commands. It does
not remove installed profiles. Remove profiles and verify their absence first if
they should stop applying. **Resume user management** prepares current assignments
and waits for a new user TokenUpdate, normally after login. Revoking or checking out
the native enrollment also withdraws all its user channels and staged credentials.

Readers can inspect user metadata and history. Operators can refresh inventory,
assign profiles, retry commands and resume management within their assigned scope.
Pausing requires device-revocation permission. Profile creation and editing retain
organization-wide profile-management authorization. Forms require CSRF tokens;
all reads and mutations validate the exact tenant, site, device and user scope.

## Protocol and capability boundaries

UserAuthenticate returns an empty DigestChallenge: the service accepts account
handles reported by the authenticated OS and does not claim directory-password
verification or an IdP sign-in. Password-digest authentication, account-driven User
Enrollment, Shared iPad user channels and user-channel declarative management are
not implemented. Unsupported or paused user enrollment receives HTTP 410.

Only ProfileList, InstallProfile and RemoveProfile enter the user command queue.
Device inventory, bootstrap-token access, device identity confirmation and Mac
agent/MDM linkage remain on the device channel. NotNow receives an empty response
so macOS can finish login. Commands and push notifications wait while the user
reports NotOnConsole; already-delivered receipts may still be processed.

User push credentials and command payloads are encrypted with channel-specific
authenticated context. Public models and audit events exclude these secrets.
Commands expire after seven days and erase their payloads at terminal states.
Inventory is requested at six-hour intervals while a user is on the console.
Push leases last five minutes; delayed APNs results cannot overwrite replacement
credentials. Each native enrollment admits at most 1,000 user handles.

During certificate renewal, user TokenUpdates signed by the candidate certificate
are staged separately. Only device-channel confirmation promotes that certificate
and its staged user tokens together. Candidate user command connections receive
no work and cannot confirm the identity; retired certificates cannot use user
channels. Renewal failure, cancellation and enrollment withdrawal delete staged
tokens. The immutable per-user capability is persisted independently of recovered
profile inventory.

The embedded capability catalog records Apple's macOS channel, version and
enrollment requirements at commit
[`67045e2fa06f528b196c01edee6a8bf88b844beb`](https://github.com/apple/device-management/tree/67045e2fa06f528b196c01edee6a8bf88b844beb/mdm/profiles).
It rejects unknown user payload types and device-only settings, including PPPC and
FileVault. MCX variants sharing a payload type are distinguished by their setting
keys. This checks channel eligibility, not every payload field or its device-side
effect. To regenerate the checked-in facts from a reviewed Apple revision:

```sh
go run ./cmd/openuem-apple-profile-capabilities -revision 67045e2fa06f528b196c01edee6a8bf88b844beb
```

Protocol behavior also follows Apple's
[MDM payload](https://github.com/apple/device-management/blob/67045e2fa06f528b196c01edee6a8bf88b844beb/mdm/profiles/com.apple.mdm.yaml),
[UserAuthenticate](https://github.com/apple/device-management/blob/67045e2fa06f528b196c01edee6a8bf88b844beb/mdm/checkin/userauthenticate.yaml),
[TokenUpdate](https://github.com/apple/device-management/blob/67045e2fa06f528b196c01edee6a8bf88b844beb/mdm/checkin/tokenupdate.yaml),
and [network/mobile login guidance](https://developer.apple.com/documentation/devicemanagement/enabling-network-and-mobile-user-logins).

## Verification and remaining acceptance

PostgreSQL protocol tests cover cross-user and device-channel isolation, encrypted
credentials, inventory freshness, profile revision identity, withdrawal, pause and
resume, push leases, token rotation and candidate-certificate staging. Console
tests exercise roles, scope, CSRF, profile creation, assignment and user controls.
Rendered fixtures cover managed, paused and read-only user pages.
Browser checks at 390, 768 and 1440 pixels found no horizontal overflow, verified
keyboard expansion of the pause control and confirmed that reader pages expose no
user mutation forms.

No test enrolls a physical Mac or sends live APNs traffic. Acceptance still needs
an installing local user, eligible network/mobile users, fast user switching,
offline recovery, physical profile effects and certificate renewal with active
user sessions. Broader Mac templates and security workflows remain tracked in
the [roadmap ledger](implementation-status.md).

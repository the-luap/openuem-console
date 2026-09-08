# FileVault profiles and recovery escrow

The Mac device page can stage FileVault activation, receive encrypted personal
recovery keys and audit administrator retrieval. This is part of MAC-02, not its
completion: console integration of key validation against the volume, recovery-key rotation,
escrow certificate rotation and physical Mac acceptance remain open.

## Policy lifecycle

Select an enrolled Mac with macOS 10.13 or later. Device and security inventory
must be current; macOS 10.15 and later require reported user approval or
supervision. An organization or server administrator can select **Enable
FileVault with recovery escrow**. Operators and viewers can read status.

1. A new ProfileList checks for existing FileVault configuration. Conflicting
   catalog assignments or installed payloads prevent activation.
2. OpenUEM installs a System profile containing a per-device RSA encryption
   certificate and `com.apple.security.FDERecoveryKeyEscrow`. Its `DeviceKey` is
   the native enrollment ID; the certificate is independent of the enrollment CA.
3. A new ProfileList must contain the exact managed escrow profile UUID.
4. Only then does OpenUEM install the separate deferred FileVault activation
   profile. The user completes activation at login/logout, can defer at login
   three times and sees their personal recovery key. No user password is sent to
   OpenUEM. Setup Assistant enforcement is not requested.
5. Another new ProfileList confirms both profiles. SecurityInfo separately
   reports encryption and the encrypted personal recovery key.

Each phase has its own command UUID. Generic command retries cannot replay these
commands. A deliberate policy retry starts from a new preflight request. Errors,
expiry and missing or unmanaged profiles stop advancement. Recent subsequent
profile inventories detect drift. Installation acknowledgement is not proof of
profile presence, encryption or a usable recovery key.

**Remove FileVault management profiles** first removes the activation profile,
verifies its absence, then removes and verifies absence of the escrow profile.
It does not decrypt the disk or delete any stored recovery material. Checkout
and administrator revocation also retain encrypted recovery history.

## Recovery state

An already encrypted Mac may not provide a new personal key merely because an
escrow profile was installed. It may require key rotation; this implementation
does not yet initiate rotation. The console keeps encryption, installed policy,
key escrow and key validation as separate states. Keys remain **Not yet validated
against the Mac volume** until console task authorization and signed-result
reconciliation are connected to the agent validation transport described below.

## Agent validation transport

Shared protocol `f9b56160e167`, worker `c9961c4` and agent `e446530` implement
private recovery validation transport. The console uses the same shared version,
applies registry migration 004 during desktop startup and generates the new
individual `recovery` RPC permission. No durable command stream filters change.
Update the console/authorization service and broker configuration first, then
the worker and agent; reconnect agents to obtain current broker permissions.

The Mac keeps a separate X25519 recipient in its protected System keychain,
registers it using a signed challenge, and accepts only HPKE ciphertext bound to
its identity, scope, signing certificate, recipient epoch, native enrollment,
recovery-key version, task ID and expiry. The worker cannot read the recovery key.
The root agent checks the key using bounded, read-only `fdesetup validaterecovery`
with plist standard input and returns an RSA-signed outcome and nonce. Plaintext
is cleared before sending; lost acknowledgments retry the signed receipt only.
The worker commits that receipt and its audit record together, scrubs terminal
ciphertext and periodically erases stale tasks even for offline agents.

The console does not yet create these tasks or mark escrowed keys verified from
their receipts. That next step must transactionally authorize security management,
recheck the current canonical native/agent association and key version, and verify
the signed result against the still-current certificate and recipient. Late,
foreign, revoked or superseded results must not validate the current key. Native
recovery-key rotation and physical volume acceptance remain separate open work.

## Recovery access

`devices.security.manage` and `devices.recovery.retrieve` are separate
capabilities, currently granted to organization and server administrators.
**Recovery key history and retrieval** lists current and previous versions.
Selecting a key submits a CSRF-protected POST and opens a plain-text response in
a separate tab. The retrieval audit must commit before any key is returned.
Responses prohibit caching, framing, scripts and referrers. GET/HEAD, another
organization/site, revoked administrator permissions and invalid CSRF cannot
retrieve a key. Native device revocation does not prevent an authorized
administrator from recovering its stored keys.

Private escrow keys and personal recovery keys use authenticated encryption
bound to organization, enrollment, record ID and purpose. The database enforces
the same scope. CMS responses, private keys and personal keys are excluded from
device JSON, generic inventories, command history and audit details. Security
command errors are redacted. A newer accepted observation prevents an older
queued SecurityInfo response from replacing the current key. Repeated reports
of the same key update its observation time without creating another version.
Malformed or incorrectly addressed envelopes preserve existing keys.

History is bounded to 128 versions per enrollment; reaching the limit reports an
error and preserves the existing records. There is no automatic deletion or
administrator forget action yet. Backups must preserve both the database and
the configured encryption master key. Loss of that key prevents decryption.

## Protocol evidence and validation

The implementation follows Apple's pinned
[recovery escrow payload](https://github.com/apple/device-management/blob/67045e2fa06f528b196c01edee6a8bf88b844beb/mdm/profiles/com.apple.security.FDERecoveryKeyEscrow.yaml),
[FileVault payload](https://github.com/apple/device-management/blob/67045e2fa06f528b196c01edee6a8bf88b844beb/mdm/profiles/com.apple.MCX.FileVault2.yaml)
and [SecurityInfo schema](https://github.com/apple/device-management/blob/67045e2fa06f528b196c01edee6a8bf88b844beb/mdm/commands/information.security.yaml).
Apple's [rotation command example](https://developer.apple.com/documentation/devicemanagement/rotate-filevault-key-command)
also demonstrates legacy BER/3DES encrypted recovery material. The separate
bounded decoder accepts the required BER/DER envelope forms and AES-CBC or
3DES-CBC decryption. SCEP's stricter cipher policy is unchanged. Decryption and
recovery-key syntax validation do not establish that the key unlocks a volume.

Synthetic cryptographic tests and fuzzing cover malformed envelopes, recipient
binding, truncation, nesting limits and cipher interoperability. PostgreSQL tests
exercise profile ordering, receipt isolation, scoped encryption, history,
retention, audit rollback and competing assignments. Console tests cover roles,
CSRF, retrieval headers, read auditing and secret-free device pages. These tests
do not establish interoperability or recovery on a physical Mac.

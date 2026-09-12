# FileVault profiles and recovery escrow

The Mac device page can stage FileVault activation, receive encrypted personal
recovery keys, validate and rotate them through the linked Mac agent, and audit
administrator retrieval. Escrow certificate rotation, broader Mac security
workflows and physical Mac acceptance remain open under MAC-02.

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
escrow profile was installed. It may require key rotation. Agent rotation requires
an already escrowed, independently validated current key; initial key recovery
for a Mac without that material still needs a separate assisted workflow. The
console keeps encryption, installed policy,
key escrow and key validation as separate states. Keys remain **Not yet validated
against the Mac volume** until the linked Mac agent returns an authenticated
successful check and the console accepts that result.

An organization or server administrator can select **Validate current recovery
key**. This action checks the exact key version shown on the page, requires a
current individual Mac agent with a registered recovery recipient and a verified
MDM association, and sends an encrypted request that expires within 15 minutes.
Both channels need recent, matching hardware inventory. The action does not
return the key to the browser or change disk encryption. Duplicate submissions
reuse a pending request. Refresh the device page to see its eventual outcome.

The page distinguishes a valid key from an invalid key, an unavailable check,
an unsupported agent, expiry, cancellation and an unauthenticated response. A
later negative check is shown even if an earlier check succeeded; the last
successful timestamp remains historical evidence in recovery-key history.

## Agent validation transport

Shared protocol `2e8eb22e1208`, worker `ba586d5` and agent `50b7e14` implement
private recovery validation and rotation transport. The console applies registry
migrations 004–009 during desktop startup and generates the individual `recovery`
and `rotation` RPC permissions. No durable command stream filters change.
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

Native migration 016 stores the console's independent expectations for every
request. Queueing holds the administrator's security permission through commit,
then serializes against channel attachment, native enrollment, agent identity
and inventory changes. The console checks the native and agent channels, current
key version, organization/site, recipient epoch, certificate and hardware again
before accepting a receipt. It independently verifies the RSA signature and
expected nonce hash; a routing worker cannot turn an invalid result into success.
Both queueing and completion commit their audit events in the same transaction.

Maintenance processes up to 25 due checks per pass and fairly reschedules pending
requests. Revoked, expired, replaced or conflicting identities cancel the check;
a newer escrow key supersedes the old request. Pending ciphertext is erased on
cancellation. An authenticated result received before its deadline can be accepted
after a console delay only if the current key and both identities still match.
The recorded validation time is the original result time, not the later processing
time. Historical keys and previous successful timestamps are never discarded by
a failed check. Native-only deployments remain usable without agent tables.

This is an authenticated OS report, not hardware attestation. Escrow-certificate
rotation and physical volume acceptance remain open.

## Controlled recovery-key rotation

On an eligible Mac, expand **Replace the current recovery key** and select
**Rotate current recovery key**. This scoped, CSRF-protected POST requires
`devices.security.manage`, a successful current-key validation within 24 hours,
current security and hardware reports, and both exact managed FileVault profiles
confirmed after the policy became active. A later negative validation prevents
rotation until another successful check. The key version in the form must still
be current. The retained native escrow private key must open successfully, match
its certificate, and remain valid through the execution and receipt reserve.
The agent uses macOS 10.14 or later PRK authentication on APFS.

Rotation requires protocol version 2 on both the agent and worker; read-only
validation remains version 1. Native migration 017 stores independent console expectations and an encrypted
per-attempt X25519 return key. The old PRK is HPKE-encrypted for the agent's
protected recipient; a returned candidate is independently HPKE-encrypted for
the console. The worker can decrypt neither direction. The console reserves
certificate lifetime beyond the five-minute task deadline, and its permission,
current-key, escrow and channel checks remain locked through the queue/audit commit.
Concurrent duplicate submissions reuse the same queued attempt.

The root Mac agent holds a private OS lease, durably records one immutable intent,
including its kernel boot-session UUID, validates the old key, and invokes a bounded `fdesetup changerecovery` with plist
stdin. Keys never become command arguments, log output or temporary plaintext
files. It retains a returned candidate even after timeout or a process error,
validates the candidate when possible, then signs, encrypts and durably saves its
receipt before sending. Restart or lost acknowledgment cannot repeat the mutation.
The two-minute certificate reserve leaves time for signing and durable publication.

The console independently checks the original context, nonce, certificate,
recipient, native association and pre-expiry delivery before decrypting a receipt.
A late authentic receipt can still preserve a changed key after task expiry.
`rotated` stores the new key and its volume-validation timestamp; `unverified`
stores the candidate and requests an independent check. A key already received
through native MDM is reused. A newer unrelated native observation remains current,
while the returned candidate is retained in history. An older queued SecurityInfo
request cannot replace a newly accepted rotation result. Escrow changes and native
or agent channel/hardware changes cancel unresolved delivery through database
triggers, including writes by older replicas.

`uncertain` means an admitted attempt has no trustworthy returned key. It blocks
another mutation and profile removal. Refresh security inventory to obtain native
escrow, then validate the latest stored key. The registry admits this read-only
recovery check only after the agent's immutable signed uncertainty receipt proves
`execution_stopped: true`. A freed parent lease, agent reconnect or elapsed
deadline does not prove that a launched child stopped. The v2 agent records the
kernel boot-session UUID at admission and signs this proof after reaping its
exact command or observing a different kernel boot. During same-boot intent-only
recovery it waits without repeating the mutation. No reboot is performed
automatically. Legacy intents or uncertainty receipts without this evidence
cannot authorize automatic resolution. A previously queued v1 resolution check
is rejected without updating the key validation timestamp, and cannot stall
subsequent reconciliation batches. The console authenticates the stop proof
before displaying the validation action. Only the
explicitly selected subsequent `valid` proof, independently accepted by the
console against its current key and association, resolves the attempt. Invalid,
unavailable or replaced proofs keep rotation blocked. Resolution retains the
original receipt, proof and permanently consumed ordinal.

Native escrow must already be active because a process can die between the OS key
change and local receipt persistence. These systems cannot form one atomic commit.
Authority changes retain encrypted recovery evidence but prohibit accepting it
under a replacement channel. No automatic retry, reenrollment, key deletion or
disk decryption is used to resolve uncertainty. There are at most 128 immutable
attempts per individual identity. If recovery history fills after queueing, the
console retains the encrypted receipt and return key, reports the history limit
and blocks another request instead of discarding the candidate.

The console also authenticates a permanent acknowledgement of the exact rotation
receipt after retaining its key/final result and audit in the same transaction.
This prevents [desktop identity renewal](desktop-identity-renewal.md) from retiring
the certificate before returned-key processing finishes. A completed worker row
alone is insufficient. Audit failure rolls back both acknowledgement and key
processing; verified uncertainty resolution uses the same boundary. Registry
migration 009 is required for rotation readiness. Older completed attempts receive
no automatic acknowledgement. They require the dedicated signed current-key
reconciliation described below, which preserves the original evidence.

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

Older completed rotations without a trusted processing acknowledgement can block
desktop identity renewal. The console now schedules a separate read-only check of
the current retained key, bound to the exact old signed receipt in an immutable
encrypted registry admission. Its signed valid result, final state and audit must
commit together. Existing ordinary validations are preserved and cannot substitute
for the dedicated historical proof. Current-key changes, unsuccessful checks,
expired authority, altered records and audit failures keep renewal blocked.

The page reports pending historical reconciliation and failed checks. Maintenance
uses batches of at most 25 rows with an hour between scheduling attempts and a
24-hour delay after a failed completed check. The existing authorized validation
action can retry sooner. The registry retains at most 256 such checks per agent;
it does not prune attempts or bypass the limit. Verified non-mutating old receipts
can be acknowledged without requesting a key. All old receipts, final rotation
states and keys remain. This establishes current recoverability, including after
an old return private key was erased; it cannot recreate a lost historical key.
See [desktop identity renewal](desktop-identity-renewal.md) for migration and restore
requirements.

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
CSRF, retrieval headers, read auditing and secret-free device pages.

Validation tests exercise the real encrypted task and signed receipt protocol,
concurrent request deduplication, all endpoint outcomes, independent receipt
tampering, permission revocation, identity and recipient changes, key replacement,
site conflicts and transactional audit failures. They also cover certificate
expiry while waiting for a database lock and timely receipts processed after the
task deadline. Router tests verify scoped POST-only actions, CSRF and role-aware
states. Browser checks cover six rendered states at 390, 768 and 1440 pixels,
including keyboard submission and history expansion. No test invokes the host's
FileVault command. These tests do not establish interoperability or recovery on a
physical Mac.

Rotation tests exercise encrypted queueing, recent evidence, current-key selection,
concurrent submissions, native/agent invalidation, candidate deduplication, newer
native escrow, late receipts, full-history retention, signature/context tampering,
audit rollback and explicit uncertainty resolution. HTTP and rendered-view tests cover role and CSRF boundaries, pending
controls, successful escrow and separately audited old/new key retrieval. All
device command execution remains synthetic; physical rotation and recovery are
required acceptance work.

Rotation browser checks cover eight states at 390, 768 and 1440 pixels, including
keyboard disclosure/submission, CSRF-bearing POST forms, blocked pending controls
and horizontal overflow. Form submission is intercepted by the isolated preview;
no browser test sends an action to a managed Mac.

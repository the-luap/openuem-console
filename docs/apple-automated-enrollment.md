# Apple Automated Device Enrollment connections

OpenUEM can connect an organization to an Apple Business Manager or Apple School
Manager device management server, verify and renew its server token, and
synchronize its assigned device inventory. This is the connection and inventory
foundation of APP-02. The public workflow does not yet provide ADE enrollment
profile creation or assignment, signed activation requests, Setup Assistant
enrollment, or re-enrollment. Tested internal protocol primitives described below
prepare that integration. An Apple assignment never creates an enrolled OpenUEM device or
sets supervision evidence.

## Connect an Apple server

Open **Devices → Automated Device Enrollment** as a server administrator or an
administrator of the selected organization. Every ADE route requires
`certificates.manage` for the whole organization; a site URL does not reduce that
scope. The gateway keeps these administrative routes private.

1. Create a named connection. OpenUEM generates a separate RSA-3072 key and a
   ten-year public X.509 certificate. The database encrypts the private key with
   the instance master key and binds it to this organization and connection.
2. Download the public PEM certificate. Upload it to the corresponding device
   management server in Apple Business Manager or Apple School Manager.
3. Download that Apple server's `.p7m` token and import it into this connection.
   Confirm the organization association. OpenUEM decrypts the envelope and calls
   Apple's account endpoint before committing the credential.
4. Confirm the displayed Apple organization and server, expiry and verification
   time. Synchronization starts automatically. Refresh the page to see its result.

Apple describes the certificate, encrypted token and session flow in
[Authenticating for Automated Device Enrollment](https://developer.apple.com/documentation/devicemanagement/authenticating-for-automated-device-enrollment)
and [Examining Server Tokens](https://developer.apple.com/documentation/devicemanagement/examining-server-tokens).
The verified binding comes from
[Account Detail](https://developer.apple.com/documentation/devicemanagement/account-detail).

The upload is bounded to 1 MiB. Raw CMS and Apple's base64 S/MIME envelope are
accepted; plaintext credentials are not an import format. MIME, BER nesting and
node counts, JSON nesting, duplicate keys, credential lengths and expiry are
validated before use, including Unicode case-folded duplicate field aliases. A token must be encrypted for this connection's certificate
and have more than a minute of remaining validity. Certificate private keys and
tokens are never included in page models, downloads, audit events or service error
messages. The certificate download is public material and is audited.

## Renew, pause and recover

Renew the token on the **existing** connection using the **same** Apple server.
The new token cannot expire earlier than the retained token. Verification rejects
a different Apple organization or server. A server UUID can belong to only one
OpenUEM connection across all organizations, including disabled connections.
Failed verification retains the previous credential and published assignments.
Successful renewal schedules a fresh full fetch and retains the previous published
snapshot until that fetch completes.

**Schedule synchronization** makes the current full or incremental operation due.
**Restart full fetch** discards unfinished staging after explicit confirmation.
Neither action bypasses a persisted Apple retry deadline. Token verification also
persists and observes Apple's throttling deadline, including while a connection
is pending. The page displays the deadline and all times in UTC.

**Disable connection** removes the encrypted token and stops further requests,
while retaining the certificate, immutable Apple account binding and assignment
history. It does not disown devices in Apple or remove their MDM enrollment.
Import a current token for the same server to reconnect. Up to 16 connections,
including disabled connections, are retained per organization. Deletion,
organization transfers and recipient-certificate rotation are not available yet;
retain the original master key with protected database backups.

## Synchronization and failure behavior

The client fixes the service origin to `https://mdmenrollment.apple.com`, requires
TLS 1.2 or later, and refuses redirects. Account response URLs are never followed.
OAuth 1.0 HMAC-SHA1 authenticates `/session`; subsequent requests use the returned
`X-ADM-Auth-Session`. Response session replacement is honored and authentication
retries are bounded. Bodies, headers, connection timeouts and response sizes are
bounded; user-facing errors do not include Apple's response body or credentials.

A dedicated maintenance loop checks for due connections every 15 seconds,
selecting at most eight per sweep. Each transaction owns one connection with
`FOR UPDATE SKIP LOCKED`, verifies its Apple account binding again, and commits
one page, its cursor and its audit event together. Network requests have a
15-second combined budget within the bounded transaction. Concurrent replicas
skip an active owner. Credential renewal and disabling wait for that owner and
cannot be overwritten by a late response. This loop is separate from APNs and
native security-command maintenance.

Full fetches call `/server/devices` with a maximum of 1,000 devices per page.
Records are staged until the final page. Only then does the transaction publish
the snapshot and mark absent assignments as removed. Partial pages, unavailable
Apple service or an audit failure cannot remove the last published assignments.
The Apple API is documented in
[Get a List of Devices](https://developer.apple.com/documentation/devicemanagement/fetch-devices).

After completion, hourly incremental synchronization calls `/devices/sync` with
the committed cursor. Duplicate events are ordered by serial number and `op_date`;
older events cannot resurrect a deleted assignment. Deletes retain the previously
reported metadata. Identical events are idempotent. Conflicting events with the
same date, contradictory duplicate full-fetch records, repeated continuation
cursors, rejected cursors and cursors older than six days restart a full fetch
without discarding published assignments. A single fetch is bounded to 10,000
pages. Missing or null device arrays, missing continuation metadata and oversized
pages are errors, never evidence of an empty inventory. Apple's cursor lifetime
and duplicate-event semantics are documented in
[Sync the List of Devices](https://developer.apple.com/documentation/devicemanagement/sync-devices).

Service failures normally retry after five minutes; invalid credentials and
changed account bindings retry after 24 hours. HTTP 429/503 retry deadlines are
persisted without shortening a longer Apple deadline. The assignment table pages
through 100 records at a time, scoped to the selected organization and connection.
It shows both assigned and removed records, Apple profile status and observation
time. Reading the ADE page is audited without storing inventory contents.

## Enrollment protocol primitives

The internal ADE client now supports defining an enrollment profile, reading its
supported options, assigning or clearing a profile for a bounded batch, and
refreshing individual device assignments. These operations are not yet connected
to an administrator action, background enrollment workflow or public activation
route. No existing connection starts assigning profiles because of this change.

Profile definition does not include device assignments. A service error can leave
an unknown creation outcome and is not automatically retried. Assignment and
removal validate every requested device's response and preserve individual
`SUCCESS`, `THROTTLED`, failure and unknown status values. Assignment throttling
retains Apple's full retry duration without integer overflow or shortening the
deadline. Missing device-detail records and any status other than `SUCCESS` are
not affirmative ownership evidence. Profile retrieval rejects unsupported
enrollment behavior instead of silently dropping security-relevant options.
The relevant Apple interfaces are
[Define a Profile](https://developer.apple.com/documentation/devicemanagement/define-profile),
[Get a Profile](https://developer.apple.com/documentation/devicemanagement/fetch-profile),
[Assign a Profile](https://developer.apple.com/documentation/devicemanagement/assign-profile),
[Remove a Profile](https://developer.apple.com/documentation/devicemanagement/clear-device-profile)
and [Get Device Details](https://developer.apple.com/documentation/devicemanagement/device-details).

`ade.VerifyMachineInfo` verifies attached CMS device statements against the
embedded Apple iPhone Device CA. Its SHA-256 fingerprint is
`76f27d00e1333bc88de0e2916c38c9a7f2b75774c25a794c092a80e3c4c66cce`.
Only a non-CA signing leaf directly issued by that exact public key is accepted;
an Apple developer certificate, system trust root, same-name foreign issuer or
caller-supplied production trust override is insufficient. This deliberately
supports the documented device issuer; a different future Apple issuer requires
an explicit reviewed trust update.

Apple's documented exception for device certificate validity dates is confined
to this pinned issuer. Legacy SHA-1 signatures remain supported alongside SHA-256,
SHA-384 and SHA-512; this does not weaken TLS, SCEP or organization CA checks.
The verifier requires one unambiguous signer, matching signature/digest algorithms
and valid signed attributes when present. It rejects duplicate signed attributes,
conflicting certificates, detached content and trailing ASN.1 data. CMS input is
bounded to 128 KiB with bounded BER nesting and node counts. The attached XML or
binary plist is limited to 64 KiB and 64 flat fields, with strict identity types,
duplicate-key rejection and no recursive binary references. Older devices may
omit `OS_VERSION`; a CMS signing timestamp is optional and is returned as evidence
without inventing one. Apple documents the statement in
[MachineInfo](https://developer.apple.com/documentation/devicemanagement/machineinfo)
and publishes the device CA and date exception in its
[OTA profile server documentation](https://developer.apple.com/library/archive/documentation/NetworkingInternet/Conceptual/iPhoneOTAConfiguration/profile-service/profile-service.html).

A verified statement is not hardware attestation, current ADE ownership or an
enrolled MDM identity. The pending integration must still check the live Apple
account/profile assignment, persist bounded admission and replay state, verify
the device-generated SCEP key and subsequent check-in identity, and reconcile
Setup Assistant from authenticated device evidence. The parser alone cannot
authorize enrollment or release Setup Assistant.

## Verification and remaining acceptance

Synthetic protocol tests cover a published OAuth signature vector, real local
TLS session renewal, header replacement, redirects, bounded failures, expired
and invalid cursors, duplicate/incomplete JSON and S/MIME decryption with foreign
recipient rejection. Parser fuzz seeds and the race detector run without an Apple
account or a physical device.

Enrollment protocol tests additionally exercise SHA-1/256/384/512 with RSA and
ECDSA, XML/binary plists, bounded indefinite/chunked CMS, absent signing time,
foreign issuers, invalid leaf purposes, multiple signers, altered statements,
re-signed duplicate attributes and trailing ASN.1 fields. Synthetic HTTPS tests
cover exact definition/assignment/removal/detail routes, partial results,
unknown creation outcomes, omitted devices, malformed responses and overflow-safe
throttling. Local race tests and vet pass; two parser fuzz runs completed 869,945
and 302,482 inputs. An optional local test also verified a public Apple-signed
protocol capture without copying device identifiers into this repository. That
capture is compatibility evidence, not a live enrollment or physical acceptance
test. The CI runs these synthetic protocol tests on Linux and Windows.

PostgreSQL tests exercise migrations, encrypted token binding, failed renewal,
account ownership, audit rollback, atomic full publication, incremental event
ordering, backoff, cursor resets, concurrent owners, disabling, paged inventory
and revoked transaction permissions. Real console router tests exercise scoped
roles, aliases, CSRF, multipart ambiguity, public certificate downloads and fixed
error messages. The native Apple CI includes the ADE package and PostgreSQL tests.
Local PostgreSQL was unavailable during this change. The full
[PostgreSQL race, console and build CI](https://github.com/the-luap/openuem-console/actions/runs/34299243491)
passed for the connection and synchronization implementation. Local parser
regressions also reject case-folded duplicate keys and classify unchanged
continuation cursors as a full-fetch restart; additional fuzzing passed 380,344
inputs. CI repeats the complete suite for subsequent branch updates.

Rendered empty, pending, connected, disabled and throttled states were checked at
390, 768 and 1440 pixels without page overflow. Keyboard submissions were
intercepted locally; disabling required its confirmation checkbox. No credentials
were sent to Apple and no real device or Apple assignment was changed.

APP-02 remains open for the administrator profile definition/assignment/removal
workflow, persisted signed enrollment admission, Setup Assistant handling, re-enrollment,
groups/rings and directory associations. Native managed administrator accounts
require the corresponding ADE setup-time workflow; this inventory foundation
does not provide account creation or password rotation. Apps & Books, production
Apple account acceptance, physical Mac/iPhone/iPad setup, recipient-certificate
rotation and operational-scale acceptance remain outstanding.

# Apple Automated Device Enrollment connections

OpenUEM can connect an organization to an Apple Business Manager or Apple School
Manager device management server, verify and renew its server token, and
synchronize its assigned device inventory. This is the connection and inventory
foundation of APP-02. It does not yet implement ADE enrollment profile creation
or assignment, signed activation requests, Setup Assistant enrollment, or
re-enrollment. An Apple assignment never creates an enrolled OpenUEM device or
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
validated before use. A token must be encrypted for this connection's certificate
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

## Verification and remaining acceptance

Synthetic protocol tests cover a published OAuth signature vector, real local
TLS session renewal, header replacement, redirects, bounded failures, expired
and invalid cursors, duplicate/incomplete JSON and S/MIME decryption with foreign
recipient rejection. Parser fuzz seeds and the race detector run without an Apple
account or a physical device.

PostgreSQL tests exercise migrations, encrypted token binding, failed renewal,
account ownership, audit rollback, atomic full publication, incremental event
ordering, backoff, cursor resets, concurrent owners, disabling, paged inventory
and revoked transaction permissions. Real console router tests exercise scoped
roles, aliases, CSRF, multipart ambiguity, public certificate downloads and fixed
error messages. The native Apple CI includes the ADE package and PostgreSQL tests.
Local PostgreSQL was unavailable during this change; the dedicated CI run is the
authoritative database test, and its result is recorded in the implementation
ledger when complete.

Rendered empty, pending, connected, disabled and throttled states were checked at
390, 768 and 1440 pixels without page overflow. Keyboard submissions were
intercepted locally; disabling required its confirmation checkbox. No credentials
were sent to Apple and no real device or Apple assignment was changed.

APP-02 remains open for enrollment profile definition/assignment and removal,
signed MachineInfo verification, Setup Assistant handling, re-enrollment,
groups/rings and directory associations. Native managed administrator accounts
require the corresponding ADE setup-time workflow; this inventory foundation
does not provide account creation or password rotation. Apps & Books, production
Apple account acceptance, physical Mac/iPhone/iPad setup, recipient-certificate
rotation and operational-scale acceptance remain outstanding.

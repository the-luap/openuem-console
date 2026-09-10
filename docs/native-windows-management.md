# Native Windows management authentication

The Windows backend now has a direct TLS device identity verifier, bounded
OMA DM digest primitives and a [SyncML XML codec](native-windows-syncml.md).
They build on [initial certificate enrollment and
encrypted provisioning](native-windows-enrollment.md). The subsequent
[session service](native-windows-sessions.md) persists authentication, nonces and
a read-only probe. Subsequent [CSP processing](native-windows-csp.md) and
[listener/gateway integration](native-windows-operations.md) use these checks.
These authentication primitives do not report a managed device,
create a session or execute a CSP operation.

## Direct TLS identity

`Store.AuthenticateManagementDevice` accepts a `net/http` request and the exact
operator configuration used for enrollment. It requires POST on the configured
HTTPS host/path, a completed TLS 1.2 or 1.3 handshake and a client leaf certificate.
Queries, encoded path aliases and conflicting absolute request URLs are rejected.
The server must request client certificates and pass its original TLS state;
middleware must never construct this state from request headers. The test server
uses `tls.RequireAnyClientCert`, with application authentication performing the
organization-specific certificate validation before returning an identity.

The verifier reparses the actual leaf DER and looks up its SHA-256 fingerprint.
It locks the live site/organization relationship and the exact device,
certificate, enrollment result and public CA rows in one transaction. The stored
DER must match, as must the original enrollment configuration digest. Changing
the management URL, provider ID or display name requires an explicit future
reprovisioning/migration path; editing configuration cannot silently rebind an
existing enrollment.

Verification checks the stored issuer, certificate/public-key fingerprints,
serial, subject, organization/site units, device URI, RSA key policy, signature,
client-authentication EKU and digital-signature-only usage. A private trust pool
contains only that organization's persisted root. System trust stores,
peer-supplied intermediate chains and middleware `VerifiedChains` do not expand
trust. Database time checks certificate/root validity and stored creation/issuance
times after lock waits and immediately before commit. Device or certificate
revocation denies access, including on a resumed TLS connection. Site reparenting
does not transfer the device to another organization.

[Persisted certificate renewal](native-windows-renewal.md) adds authenticated
replacement membership. A pending candidate requires its encrypted renewal
record and exact old/new-key proof. Only a mutually authenticated SyncML operation
confirms the replacement and retires the source certificate. This public identity
snapshot does not confirm a handoff. Retired keys remain denied on resumed TLS.
The returned identity describes the actual transport certificate; session
encryption retains the immutable initial enrollment certificate as its anchor.

The enrollment invitation's expiry/revocation and its creator's later permissions
do not revoke an already issued device identity. Those are invitation lifecycle
events. Device/certificate revocation is the management authentication boundary.
Authentication needs public CA state and does not decrypt a CA private key or
bootstrap secret. Replacement membership also authenticates its encrypted renewal
record using the master key. It returns public identity only, with no account/device hints,
raw certificate, invitation credential or SyncML secret.

The returned `ManagementDeviceIdentity` is a point-in-time result, not a reusable
authorization token. Session/command operations must call the private
`authorizeManagementDeviceExclusive` inside their own transaction and call
`checkManagementDeviceTime` after any session/audit waits before commit. The
transaction holds scope and revocation locks throughout the operation. No public
route currently exposes this diagnostic identity method.

Microsoft describes certificate transport authentication and an optional separate
message-signing mechanism for TLS bridging in [MS-MDM Transport](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mdm/d9b0c913-b0b1-4ee5-883c-496a7ed1d3f9).
This implementation requires the direct enrolled TLS peer. Forwarded certificate,
organization, bearer-token and `client-request-id` headers cannot supply identity.
CMS `MS-Signature`, Entra tokens and proxy identity delegation are not implemented.

## OMA DM digest primitives

`syncMLDigest` and `verifySyncMLDigest` implement the digest calculation from
[OMA DM Security 1.2.1, section 5.3.2](https://www.openmobilealliance.org/release/DM/V1_2_1-20080617-A/OMA-TS-DM_Security-V1_2_1-20080617-A.pdf).
The wire value is Base64 of the MD5 digest of the inner Base64 username/password
hash, a colon and the decoded nonce bytes. MD5 is confined to the required
`syncml:auth-md5` protocol primitive inside authenticated TLS; it does not replace
SHA-256 certificate pinning, enrollment credential HMAC or AES-GCM storage.

Usernames/secrets are bounded UTF-8 values. Nonces must use canonical padded
Base64 and decode to 16–256 bytes; OpenUEM provisioning creates 32 random bytes
for each direction. Credential values must encode exactly 16 digest bytes.
Whitespace aliases, URL-safe encodings, invalid padding and noncanonical pad bits
are rejected, and digest comparison uses constant-time equality. Errors are fixed
English strings without supplied values.

These primitives do not prove a complete authentication exchange. The
[session service](native-windows-sessions.md) persists per-device nonces, bounded
resynchronization, server authentication and ordered messages with exact retries.
The [Windows OMA DM protocol description](https://learn.microsoft.com/en-us/windows/client-management/oma-dm-protocol-support)
defines the different nonce/credential transitions associated with status 200
and 212. Those transitions are not inferred from a successful digest comparison.

## Verification and open integration

The full local Windows PostgreSQL 17 package passes with race detection in
**27.625 seconds**, at **90.9%** combined statement coverage. All digest functions
have full statement coverage. `go vet`, formatting and whitespace checks pass.
Tests cover both enrollment contexts, separate organization CAs despite identical
reported identifiers, exact configuration binding, signed certificate privilege
and identity changes, real mutual TLS, session resumption after revocation,
concurrent revocation/site updates, retained transaction locks, and actual database
lock waits ending in certificate expiry or request cancellation. Fixed digest
vectors were calculated independently with Python `hashlib` and include UTF-8
credentials and binary nonce octets. The fixture changes only its own random
schema in the reserved loopback test database on port 55440.

The 30-second digest fuzz run passes after **824,941 executions**. CI runs portable
checks on native Windows and database/TLS/race checks on Linux, with a separate
bounded digest fuzz step. Both complete workflows pass for management-authentication
commit `3fa2827`: [push run](https://github.com/the-luap/openuem-console/actions/runs/34400008541)
and [pull-request run](https://github.com/the-luap/openuem-console/actions/runs/34400012109).
These runs precede the separate codec change. No profile or certificate is installed on the host;
no physical Windows enrollment, authenticated device exchange, applied CSP or
hardware acceptance has been performed.

```sh
go test -race -count=1 -timeout=3m ./internal/mdm/windows
go test -run '^$' -fuzz=FuzzSyncMLDigest -fuzztime=30s -parallel=2 ./internal/mdm/windows
```

Set the database environment variable according to the
[reserved fixture instructions](native-windows-mdm.md#scoped-enrollment-credentials).
The [CSP extension](native-windows-csp.md) adds administrative command queues and
correlated results. The [enrollment/device console](native-windows-console.md) adds
scoped inventory and access revocation. Remaining work includes command/result
console views, broader typed workflows, certificate renewal/unenrollment, key rotation,
backup/restore and physical Windows acceptance. WIN-02 remains in progress.

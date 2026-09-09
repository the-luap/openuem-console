# Native Windows certificate enrollment

The initial OnPremise WSTEP backend in [`internal/mdm/windows`](../internal/mdm/windows)
now verifies device CSRs, issues scoped client certificates and persists encrypted
provisioning with exact retries. It builds on the [discovery, credential and CA
services](native-windows-mdm.md). WIN-02 remains in progress: production gateway/UI
wiring, authenticated SyncML sessions, CSP commands/results, update workflows,
renewal/unenrollment and physical Windows acceptance are still open. Issuing a
certificate does not mark a device as successfully managed.

## Request and proof boundaries

`ParseWSTEPRequest` implements the initial MS-MDE2 `RequestSecurityToken` Issue
operation with one WS-Security UsernameToken, a PKCS#10 BinarySecurityToken and
AdditionalContext. The configured HTTPS destination and SOAP action must match.
Renewal/PKCS#7, federated tokens and certificate-authenticated enrollment are
separate flows and cannot become initial password enrollment. The
[OnPremise definition](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mde2/09c69d4c-5315-4226-be5e-4cea54058317)
and [example](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mde2/611febf3-c51c-48c0-9f39-67aa4e705d58)
define this message shape.

OpenUEM bounds the SOAP input to 128 KiB, the decoded DER CSR to 16 KiB, and
AdditionalContext to 64 items and 16 KiB total. Individual names are at most
128 ASCII bytes; values are at most 8 KiB. Required device/OS/version fields have
bounded grammar. MAC and IMEI may repeat, as shown by Microsoft's example;
other duplicate names are rejected. Optional enrollment/vendor/attestation-looking
data remains untrusted. Neither those values, DeviceID, nor account/organization
hints establish authority. The issuing backend currently admits the desktop
`CIMClient_Windows` shape; recognizing historical phone/handheld strings in the
parser does not declare those clients supported.

The parser only decodes the CSR envelope. After invitation authorization, the
issuer verifies its PKCS#10 signature, an RSA key with exponent 65537, the CA's
advertised minimum key length and an OpenUEM maximum of 4096 bits. SHA-256 with
PKCS#1 v1.5 or RSA-PSS is accepted; other key/hash algorithms are rejected.
The certificate uses a fresh server device UUID, organization/site subject values
and a device URI. Requested subjects, SANs, CA constraints and other extensions
are discarded. The client retains its private key. Certificates are signed with
the organization's RSA-3072 CA, have only client-authentication EKU and digital
signature usage, and follow the immutable CA validity policy with five minutes
of backdating for clock skew.

## Atomic issuance and retry

`Store.EnrollWindows` verifies the invitation secret, exact username, original
creator's current permissions and permission revision, live organization/site
ownership, database-clock lifetime and revocation. It holds those permission,
site and invitation locks through issuance. One transaction inserts the device
identity, public certificate, encrypted provisioning, encrypted SyncML bootstrap
credentials, request number and audits, then consumes the invitation. A failure
or expiry before commit returns no response and rolls back all of those changes.

The database keeps immutable scope/identity/certificate/result bindings through
composite foreign keys and update/delete triggers. Device and certificate
revocation timestamps can be set once. These storage transitions are not yet a
console revocation operation or an on-device unenrollment command. Reported device
identifiers and names are retained as initial hints; they never merge or overwrite
another managed identity.

For ten minutes after consumption, the same invitation can retrieve its committed
result if it remains unexpired, unrevoked and authorized. The exact CSR bytes,
canonical context items and server configuration must match their persisted
digests. Context order and the WS-Addressing MessageID may change; the latter only
changes response correlation. The same certificate, request number, secrets and
provisioning are returned after restart. A changed request cannot issue a second
certificate. Revoked devices/certificates and corrupted encrypted state also
prevent retrieval. `CheckPolicyCredential` continues to reject consumed
invitations; this bounded replay is exclusive to the issuance result.

The native Windows master key protects provisioning and SyncML secrets with
versioned AES-GCM envelopes and distinct authenticated purposes. Associated data
binds organization, site, device, CA, certificate fingerprint and request/config
digests. Provisioning is limited to 64 KiB; CA/private-key and bootstrap-secret
envelopes retain their 8 KiB limit. No raw invitation password, CSR or bootstrap
secret is copied into audit events. Losing the master key makes these protected
records unusable. Rotation and backup/restore acceptance remain separate work.

## Provisioning and HTTPS

The WSTEP response contains a base64 XML provisioning document with the public
root and client certificate, an empty required PrivateKeyContainer, the w7
APPLICATION account and DMClient provider. Endpoint, provider ID and display name
come only from operator configuration. Enterprise role 32 and SyncML 1.2 XML
encoding are explicit; no registry fallback or protocol downgrade is configured.
Certificate-store identifiers use Windows' SHA-1 thumbprint format; cryptographic
trust and persisted certificate fingerprints use SHA-256.

Each device receives independent random 256-bit secrets and initial nonces for
both SyncML directions. CLIENT authenticates the server to the device; APPSRV
authenticates the device to the server. Both use the protocol's DIGEST type.
These are SyncML credentials, separate from the enrollment invitation and TLS
client certificate. [Direct TLS identity and digest primitives](native-windows-management.md)
are now implemented; the future SyncML service must integrate them with durable
nonce/session state before this handler is exposed publicly. The required
directions and parameter semantics are specified by the
[w7 APPLICATION CSP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mde2/426201f4-2c7f-4ffe-843d-0deb3fad0a09).

Full enrollment installs the client certificate under My/User; Device enrollment
uses My/System. Certificate selection retains the logical `My\User` search value
specified in both published MDE2 context examples. Actual selection in each
context still requires physical Windows acceptance. The
[MDE2 provisioning schema](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mde2/35e1aca6-1b8a-48ba-bbc0-23af5d46907a)
describes the certificate/account structure. DMClient receives the server UUID
as EntDMID, eight retries at 15-minute intervals, five at 60-minute intervals,
then indefinite 1,560-minute polling and polling on login. Renewal, push and
attestation settings are not advertised before their service implementations exist.

`NewWSTEPHandler` accepts POST only on one configured HTTPS URL and enforces Host,
SOAP destination/action, media type and body bounds. Forwarded headers cannot
replace TLS or select a tenant. Responses and fixed English SOAP faults have
explicit Content-Length, no-store caching headers and no cookies. Wrong, expired, revoked and
conflicting replay credentials share the authentication fault. CSR failures use
CertificateRequest; internal errors expose no database/key/request details.
Discovery owns GET/HEAD availability probes. Production registration, admission
limits and owner timeouts are not supplied implicitly by the handler.

## Automated evidence and remaining acceptance

The final local PostgreSQL 17 race suite passes in **20.581 seconds**, with
**91.1%** combined package statement coverage. `go vet`, formatting, local
documentation links and whitespace checks also pass. Tests use the reserved loopback
`openuem_test` database on port 55440 and remove only their own random schemas.
They cover signed CSR proof and privilege stripping, both provisioning contexts,
independent SOAP/XML namespace checks, spoofed scope hints, encrypted persistence,
restart, ten concurrent identical requests, immutable SQL bindings, CA-preserving
schema upgrade, audit rollback, expiry/cancellation during actual lock waits,
retry limits, revocation and ciphertext tampering. Real local TLS requests exercise
initial issuance, exact body limits, failure privacy and durable replay. No
certificate/profile is installed on the host and no Windows account is changed.

Thirty-second fuzz runs completed **953,311** WSTEP parser executions and
**1,164,556** CSR verifier executions without failure. The CSR corpus contains
only a [public synthetic request](../internal/mdm/windows/testdata/README.md), with
no retained private key. CI includes the portable tests on native Windows, the
PostgreSQL race suite on Linux and separate bounded fuzz steps. Both complete
workflows pass for WSTEP commit `be418e8`: [push run](https://github.com/the-luap/openuem-console/actions/runs/34398356243)
and [pull-request run](https://github.com/the-luap/openuem-console/actions/runs/34398359882).
These runs also include the existing browser, database, gateway and platform-build
regressions. Their success does not establish physical Windows acceptance.

```sh
go test -race -count=1 -timeout=3m ./internal/mdm/windows
go test -run '^$' -fuzz=FuzzWSTEPRequest -fuzztime=30s -parallel=2 ./internal/mdm/windows
go test -run '^$' -fuzz=FuzzEnrollmentCSR -fuzztime=30s -parallel=2 ./internal/mdm/windows
```

Set `WINDOWS_MDM_TEST_DATABASE_URL` as described in the
[database test instructions](native-windows-mdm.md#scoped-enrollment-credentials).
The native Windows job has no PostgreSQL service, so its success does not prove
database execution on Windows. No physical Windows enrollment, SyncML session,
CSP result, Entra/Autopilot flow or complete supported OS/edition/architecture
matrix has been accepted yet.

# Authorized Apple vendor signing

OpenUEM supports an offline signing operation in an authorized MDM vendor's own
infrastructure, and verification, storage and download of the resulting signed
portal request in the customer console. No vendor signing service is contacted
automatically. The customer private key never leaves its OpenUEM instance; the
vendor private key must never enter a customer console, repository, installer,
download or command-line value.

The format follows Apple's current [Setting up push notifications for your
device management customers](https://developer.apple.com/documentation/devicemanagement/setting-up-push-notifications-for-your-device-management-customers).
The older article URL referring to “MDM customers” has moved. The current prose,
Java implementation and .NET example specify SHA-256 with RSA. Some comments in
the Java sample still mention SHA-1; this implementation uses SHA-256 and rejects
SHA-1 signatures.

## Establish vendor authorization

The operator must obtain an authorized MDM Vendor CSR Signing Certificate from
Apple or make an explicit arrangement with an authorized vendor. Apple's
[credential-access instructions](https://developer.apple.com/help/account/certificates/mdm-vendor-csr-signing-certificate/)
describe the permission required. This fork provides no access to Fleet or any
other vendor's signing infrastructure.

Record the vendor's identity, agreement, operational owner, support contact,
renewal procedure and approved certificate SHA-256 fingerprint through a trusted
channel. Confirm that this is the actual MDM Vendor CSR Signing Certificate.
Neither an Apple-issued certificate nor a matching organization name alone
establishes authority to sign for this installation. The verifier requires an
exact approved certificate fingerprint and a valid Apple chain; it does not infer
the vendor's contract or Apple signing permission from a subject name or policy
OID. The fingerprint must come from the verified vendor credential, not from an
untrusted response asking to approve itself.

Set this public configuration on every console replica, then restart the replicas:

```text
APPLE_MDM_VENDOR_CERT_SHA256=<approved 64-character lowercase SHA-256 fingerprint>
```

Up to ten comma-separated fingerprints support an explicit vendor certificate
transition. Duplicate, malformed or empty entries are rejected. No configured
fingerprints means signed-response upload and portal download are disabled.
Invalid configuration produces a fixed server log message and disables those
operations; it does not disable existing device management. All replicas must
use the same approved set. Removing a pin disables future downloads on replicas
using the new configuration, including requests saved before the change. It
cannot recall files that an administrator has already downloaded.

## Sign in vendor infrastructure

Run this operation only where the authorized vendor controls its signing key.
The private key must be a protected PKCS#8 RSA PEM file. Keep its parent directories
and ancestors trusted. The key reader checks the opened regular file's private
access controls, rejects a final symlink and checks its file identity. Public
input files must also be bounded regular files. Output creation is exclusive and
does not replace an existing entry; interrupted writes may leave a protected,
incomplete file that must not be returned as a completed portal request.

Obtain the vendor leaf certificate from Apple. Assemble a PEM chain ordered as
the vendor certificate, its intermediate certificates and the Apple root. Apple's
current guide links [WWDR G3](https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer)
and [Apple Root CA](https://www.apple.com/appleca/AppleIncRootCertificate.cer).
Use the intermediate appropriate to the actual vendor credential. OpenUEM currently
trusts the embedded Apple Root CA identified in [the trust-anchor record](../internal/mdm/apple/certs/README.md).
Other roots require a reviewed implementation update; a response cannot introduce
a root or trigger a network trust download.

Build the standalone tool in the vendor environment:

```sh
go build -o openuem-apple-vendor ./cmd/openuem-apple-vendor
```

With prepared files in trusted directories, run:

```sh
./openuem-apple-vendor \
  -csr /srv/vendor/requests/customer.csr \
  -vendor-chain /srv/vendor/certificates/vendor-chain.pem \
  -vendor-key /srv/vendor/private/vendor-key.pem \
  -vendor-sha256 "$approved_vendor_sha256" \
  -output /srv/vendor/requests/customer-signed.plist
```

`approved_vendor_sha256` is the independently approved public certificate
fingerprint. The tool does not generate, import or enroll a vendor credential,
contact a customer instance, install certificates in an OS trust store, or perform
Apple issuance. It verifies the customer's CSR signature, approved certificate,
matching vendor key, ordered chain and validity, then signs the DER CSR with
SHA-256/RSA PKCS#1 v1.5. The output is a base64-encoded XML plist with exactly
`PushCertRequestCSR`, `PushCertCertificateChain` and `PushCertSignature`. The
certificate chain uses standard 64-character PEM wrapping and includes the root.

Return only the signed public output file to the customer through the agreed
channel. Customer private keys are not inputs to this tool. Vendor private keys
are never outputs. Public CSR and certificate files contain organization metadata
and should follow the vendor's agreed handling and retention procedures.

## Verify and download in the customer console

An organization certificate administrator opens the matching pending request on
**Apple setup & enrollment**, uploads the signed vendor response, and selects
**Verify and save vendor response**. The response must be a base64 XML plist up to
128 KiB. Its DER CSR must match the stored request byte for byte; a valid response
for a different request is rejected. The parser rejects duplicate/unknown keys,
namespaces, nested values, non-string values, custom document types and extra
documents. It never resolves external entities or fetches chain certificates.

Verification checks the approved vendor fingerprint, RSA key bounds, digital
signature usage, ordered complete Apple chain, certificate validity and the
SHA-256/RSA signature over the exact DER CSR. The signature is independent of
XML whitespace or key ordering; verified output is normalized to the documented
portal format. Saved data and an audit event commit together under the existing
organization and request locks. A failed upload leaves active push settings and
the customer key unchanged.

**Download verified request for Apple** rechecks the stored signature, chain,
expiry, current vendor pins and live request state. The download contains the
complete vendor-signed portal application; the separate public CSR download is
still only the vendor's input. Revoked, expired, consumed and superseded requests
cannot be downloaded. The file is not cached by the console response. A removed
or expired vendor certificate requires a new signed response for the same CSR,
or a new local request if that request has expired.

Open the Apple portal using the console's new-tab link. Follow
[the push certificate workflow](apple-push-requests.md) to create a certificate or
renew the existing entry, then import the returned certificate into that same
local request. Saving a vendor response alone does not activate push credentials.

## Evidence and remaining work

Tests construct synthetic roots, intermediates and vendor keys in isolated test
processes. The production constructor always uses the embedded Apple root; there
is no environment or CLI switch for trusting a test root. Tests verify the
documented format independently, check the emitted RSA signature directly, and
cover malformed XML, CSR mismatch, SHA-1 rejection, incomplete/reordered chains,
expired certificates, wrong pins, tampered persistence, changed trust, audit
rollback, concurrent revocation and protected signing files. The XML parser also
has a bounded-input fuzz target. Console route tests cover organization authority,
CSRF and rejection of missing or invalid vendor responses. Positive persistence
tests use the synthetic issuer; they do not establish Apple portal acceptance.
A local 15-second parser fuzz run completed 451,604 cases without a failure.
The expanded setup fixture, including the verified-download control, was checked
at 390, 768 and 1440 pixels in light and dark mode with no horizontal overflow.

Actual vendor permission, agreement and operational availability must still be
established for the deployment. No vendor credential was provisioned, no signing
service was contacted, and no Apple certificate was issued during implementation.
Automatic service transport, revocation checking for vendor certificates, Apple
issuer-chain validation of the final push certificate, APNs connectivity before
activation, complete renewal reminders and actual issuance/renewal continuity
remain open APP-01 work.

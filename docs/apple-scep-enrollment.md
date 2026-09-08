# Apple device-generated enrollment identities

New manual iPhone/iPad enrollment profiles use Apple's SCEP payload. The device
generates an RSA-2048 private key, requests a certificate, and uses that identity
for authenticated MDM check-in. The server does not generate or receive the new
device's private key. The payload requests nonextractable storage and disables
access by all apps. This is not a claim of Secure Enclave storage or hardware
attestation. [Apple's payload properties](https://developer.apple.com/documentation/devicemanagement/scep/payloadcontent-data.dictionary)
define those options; [Apple's certificate guidance](https://developer.apple.com/documentation/devicemanagement/managing-certificates-for-device-management-services-and-devices)
also describes ACME, which remains future work here.

## Enrollment and authorization

1. An authorized administrator creates the existing scoped, one-hour invitation.
   Browser previews do not consume it. The owner confirms management before the
   browser can claim and download a profile.
2. Claim creates a random 256-bit SCEP challenge tied to that device and
   organization. Only its SHA-256 hash is stored in the authorization row. The
   profile contains the challenge and its existing temporary browser retry copy
   remains encrypted with both the browser secret and server master key.
3. During installation, the device discovers the CA/RA through the profile's
   HTTPS URL, generates its key, and sends an encrypted, signed PKCSReq containing
   a separately signed CSR. The challenge expires one hour after claim; reads,
   downloads and retries do not extend it.
4. The server verifies both signatures, the exact invited device subject, and
   the still-active challenge. In one database transaction it consumes the
   challenge, stores the public certificate and request association, pins the
   device certificate, and records `apple.scep.enrollment.issue`.
5. The device authenticates over TLS and registers its push token through the
   existing MDM check-in flow. Only that registration marks it enrolled. The first
   authenticated check-in binds its UDID and stops browser and SCEP retries.

A successful SCEP response alone does not prove that the device installed the
certificate. The server accepts only the exact individually issued certificate
for MDM; an arbitrary self-signed certificate or another CA-issued certificate
does not authenticate a device. Requested SANs, organization names, certificate
usages and CA privileges are not copied from the CSR. The issued leaf has the
invited device UUID, configured organization, signing/key-encipherment usages and
client authentication EKU. Its expiry is the invitation's one-year identity
deadline capped at the issuing CA's expiry.

Lost responses can be retried before the challenge window ends and before the
first authenticated check-in. The same CSR bytes, signer certificate and SCEP
transaction ID return the same public certificate. A new nonce is allowed; a
different key, CSR, signer or transaction cannot reuse the authorization. Eight
concurrent retry requests are covered by the PostgreSQL test. No second private
key or certificate is generated for a retry.

Revocation, checkout and expiry are checked synchronously. A request parsed before
an administrator revokes enrollment is rechecked under the device row lock before
issuance. The background worker clears unused challenge hashes in batches of 100
after expiry or loss of eligibility. It does not physically erase database WAL or
backups. Public certificates and issuance hashes remain as association evidence.

## Authorities and HTTPS

Each organization retains its existing issuing CA and gets a separate RSA SCEP
registration authority (RA) when an authorized browser claim first needs it. The
RA signs CMS responses and decrypts requests; its certificate has signing and key
encipherment usages. The CA key is used to issue certificates. RA keys are encrypted
under the server master key with organization/authority-specific associated data.
Authorities are reused while sufficiently valid and retained for the enrollments
that reference them. Their lifetime is at most five years, capped at CA expiry.

Public discovery neither creates nor decrypts private keys. A request uses the
authority bound to its enrollment. Settings, APNs renewals and browser claims
retain their existing organization serialization. CA/master-key rotation and
authority history retention are not automated by this change.

The URL must use a device-trusted HTTPS origin. TLS authenticates CA discovery and
capabilities. The implementation does not put SHA-256 into Apple's legacy
`CAFingerprint` field: Apple's [deployment guide](https://support.apple.com/guide/deployment/dep495a6d79/web)
documents SHA-1/MD5 fingerprints for HTTP, whereas this endpoint requires HTTPS.
Do not substitute HTTP or disable server certificate validation. For a private
TLS issuer, provision its trust through the existing deployment process.

## Public protocol boundary

The exact route is `/mdm/apple/<canonical device UUID>/scep`:

| Request | Response |
| --- | --- |
| GET `?operation=GetCACaps` | AES, POSTPKIOperation, SHA-256 and SHA-512 |
| GET `?operation=GetCACert` | Public CA and RA in `application/x-x509-ca-ra-cert` |
| POST `?operation=PKIOperation` | Binary request/response, `application/x-pki-message` |
| GET `?operation=PKIOperation&message=<URL-encoded base64>` | Same transaction processing; POST is preferred |

Discovery is available only for an unexpired, claimed enrollment before first
device contact. Unsupported operations, methods, duplicate parameters and malformed
queries are rejected. The gateway exposes only GET/POST on this exact UUID route;
it retains its pinned mutual TLS backend and public/admin route separation.
Check-in/connect still requires the individual device TLS certificate.

Requests are limited to 128 KiB. The listener's 32 KiB header limit further bounds
GET requests. A separate per-listener SCEP limiter allows 100 requests/second with
a burst of 200; each source has two/second and a burst of 30. IPv6 sources share
/64 buckets, with at most 4,096 buckets. Four requests can perform enrollment work
concurrently, each with a 15-second database context. TLS/body timeouts also apply.
Forwarded source addresses are accepted only from the pinned gateway. Limits are
per process, not a distributed denial-of-service guarantee.

All replies use `no-store`. Errors exclude SQL, keys, CSR contents and challenges.
Surrounding access logs must omit request bodies, cookies and SCEP query messages;
GET messages contain the encrypted enrollment request.

## Cryptography and verification boundary

The adapter uses pinned smallstep SCEP/PKCS7 libraries with additional validation:

- Complete definite-length DER, bounded to 24 nesting levels and 4,096 nodes;
  exactly one signer and at most five unambiguous signer certificates.
- RSA 2048–4096 and SHA-256/384/512 for request signatures; CSR signatures are
  independently verified. MD5, SHA-1, DES and 3DES are rejected.
- AES-128/256-CBC request envelopes with bounded RSA transport. Partial CBC blocks
  and constructed ciphertext are rejected before the upstream decoder. RSA v1.5
  padding uses Go's random session-key fallback. Responses use AES-128-CBC and
  SHA-256 and encrypt only to the authenticated signer.
- One value per signed attribute, one challenge attribute, a bounded transaction
  ID and a 16-byte request nonce. Responses echo the recipient nonce and generate
  a fresh sender nonce.

The service does not advertise `SCEPStandard` or `Renewal`. It implements the
initial enrollment subset, not all [RFC 8894](https://www.rfc-editor.org/rfc/rfc8894.html)
operations or BER encodings. RenewalReq parsing is tested but does not authorize
renewal. Automatic profile replacement, candidate-certificate confirmation,
legacy-device migration and safe retirement of the previous identity remain open.

Tests cover real PostgreSQL transactions and rollback, concurrent retries,
scope/challenge/expiry/revocation, CA expiry caps, rejected CSR privileges, corrupt
encrypted keys, HTTPS GET/POST, actual TLS check-in both directly and through the
gateway, route/rate/body limits, malformed messages, nonces and independent OpenSSL
CMS signature/decryption. Fuzz targets exercise structure and request parsing.
Existing PKCS#12 profiles, retry records and individually pinned device identities
continue to work; the legacy profile generator is now a test fixture only.

These are synthetic protocol and persistence tests. Physical iPhone/iPad SCEP
installation, Safari interaction, private-CA trust provisioning, actual APNs and
device continuity are still required acceptance evidence. Until automatic renewal
is implemented and verified, plan fresh enrollment before a device identity expires.

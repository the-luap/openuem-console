# Apple push certificate validation

Both certificate-only request import and the existing certificate/private-key
pair import verify the uploaded certificate before replacing active settings.
The offline trust check is followed by a mandatory
[fresh APNs connection check](apple-apns-connection-check.md) before activation.
Independent revocation checks and real Apple issuance/renewal acceptance remain
open APP-01 work.

## Import checks

- Strict PEM input: at most 64 KiB and eight certificate blocks, leaf first, with
  no private keys, PEM headers, duplicate certificates, preamble or trailing data.
- Exactly one subject UID containing a nonempty `com.apple.mgmt.` topic, bounded
  to 255 ASCII letters, digits, dots and hyphens. Multiple UIDs or control
  characters cannot select an ambiguous topic or become an HTTP header.
- A non-CA leaf with digital-signature key usage, explicit client-authentication
  extended key usage and Apple's production push extension
  `1.2.840.113635.100.6.3.2`. An unrestricted or missing EKU is insufficient.
- RSA keys from 2048 to 8192 bits or ECDSA P-256/P-384/P-521 keys, currently valid
  certificates and a cryptographically verified chain to an embedded Apple root.
  Go's X.509 verifier checks issuer signatures, CA constraints, path length,
  client usage, names and unsupported critical extensions.
- The private key must match the leaf. A renewal must preserve the active topic
  and the request's settings revision. The enrollment CA is preserved.

The production push extension and client usage are documented in section 4.11.2
of Apple's [Application Integration CPS](https://images.apple.com/certificateauthority/pdf/Apple_AAI_Sub-CA_CPS_v9.0.pdf).
That profile table also lists legacy SHA-1 signatures; the implementation uses
Go's current X.509 signature policy and provides no SHA-1 compatibility switch.
Compatibility with an actual currently issued MDM certificate remains an explicit
acceptance requirement; synthetic test certificates cannot establish it.

Only the three public Apple roots listed in the
[Apple PKI repository](https://www.apple.com/certificateauthority/) are trust
anchors. The bundled Application Integration and WWDR G4 intermediates allow a
portal certificate containing just its leaf to be verified offline. Uploaded
intermediates may complete an ordered chain but never become trust anchors.
Every supplied certificate must be part of the selected verified chain.
The stored PEM is normalized to the verified leaf and intermediates, omitting
the root, for later client-certificate presentation.

No certificate AIA, CRL or OCSP URL is fetched. The OS trust store and environment
cannot add an issuer. Public certificates and their SHA-256 fingerprints are
recorded in [the trust bundle README](../internal/mdm/apple/certs/README.md).
Trust updates require a reviewed code change and restart of the console replicas.
Do not bypass verification to work around a missing or expired intermediate.
An uploaded new intermediate can be accepted when it chains to an existing root.

## Replacement and failure behavior

The same validation applies to both import paths. Expiry/chain validation is
repeated after taking the organization lock and generating an enrollment CA,
before the settings write, with another validity check after the APNs probe.
Request consumption, other pending-key invalidation,
settings replacement and audit commit together. A rejected certificate leaves
the existing settings and pending request key intact for a corrected upload.
HTTP request import returns a fixed validation error without certificate content.

Existing stored credentials are not automatically disabled or migrated. Reading
settings and sending existing pushes keep their current behavior. The new checks
apply when credentials are imported or replaced. They do not prove that Apple
currently accepts a certificate, that it has not been revoked, or that a device
receives and acknowledges a management command. The mandatory APNs probe proves
a working TLS/HTTP2 connection using the candidate; deployment acceptance still
needs real issuance and existing-device continuity.

## Test evidence

Package tests generate a synthetic root/intermediate/leaf hierarchy and exercise
the actual verifier, including strict usage, validity, weak keys, malformed input,
ambiguous topics, missing/duplicate/reordered chains and root rejection. The
production constructor does not expose a test-root option. Public-bundle tests
check independently recorded fingerprints and verify issuer chains at the bundle
retrieval date, avoiding failures caused solely by future normal CA expiry.

PostgreSQL tests exercise renewal, concurrent request invalidation, audit rollback
and rejection through fresh production stores without changing active credentials
or consuming a request. Real console route tests reject synthetic uploads and
continue to verify scope and CSRF behavior. Their remaining workflows use seeded
existing settings only in disposable schemas. They do not claim a positive
production Apple import or APNs acceptance test.

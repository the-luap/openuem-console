# Public certificate profiles

The certificate editor imports public X.509 certificates from one PEM or DER
file. It accepts up to 256 KiB and 16 input certificates, removes duplicates and
writes a separate DER certificate payload with an independent identifier and UUID
for each distinct certificate. Private keys, identity archives, PEM metadata and
unrelated leading/trailing content are rejected.

## Scope and lifecycle

System profiles support iPhone/iPad from OS version 4.0 and Mac from macOS 10.7.
User profiles require a managed Mac user channel. Apple's public certificate
payloads do not require user-approved MDM. Uploaded PKCS1/root payloads require
one DER certificate; PEM payloads require public certificate blocks. The root
payload is an alias for PKCS1, so importing a public certificate does not require
it to be a self-signed CA.

Certificate syntax is checked before saving. Catalog entries can retain future
or expired certificates for planned changes and history, but assignment requires
all certificates to be within their validity period. Active System and User
assignments are rechecked when a revision changes or is restored; failure rolls
back the catalog, immutable snapshot and commands. Removal can proceed without
revalidating an expired certificate.

The editor uses the existing encrypted catalog, protected downloads and native
profile inventory verification. Import requires profile-management permission,
CSRF protection, an explicit trust review and exactly one file. Query parameters,
repeated fields, unrelated fields and additional files are rejected. The native
console middleware limits the complete POST body before CSRF parsing; the importer
also bounds the certificate file itself. Certificates are never installed in the
server's or development host's trust store by this workflow.

Installing CA certificates can change device trust. Review the certificate source
and fingerprint before assigning a saved profile. Parsing a certificate does not
validate its issuer against a public trust store, prove issuer possession or
establish the intended application's trust behavior. The device's profile report
confirms delivery, not the final keychain or trust outcome.

## Validation and remaining work

The isolated parser tests pass with unchanged production code and shared helpers.
They cover PEM/DER bundles, duplicate removal, separate payload identities, private
key/malformed input rejection, size/count limits, filename types, platform/channel
limits, non-CA certificates and staged versus assigned validity dates. Template
formatting and generation pass.

Native cases cover supported Mac/iPhone batches, future/expired assignment and
revision rollback, retained history, managed Mac user profiles and verified System
profile removal. Console cases use real scoped multipart requests and check roles,
CSRF, repeated/unrelated fields, query rejection, additional files, safe errors
and persisted System/User certificate data. Full CI and browser checks are pending.

PKCS12 identity and SCEP/ACME templates remain separate work. In particular,
untrusted PKCS12 decoding needs bounded KDF work and allocation before inspecting
an archive on the server. Physical certificate installation, trust behavior,
removal and certificate renewal require device acceptance.

Sources checked 9 September 2026:

- [Apple PKCS1 certificate schema](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.security.pkcs1.yaml)
- [Apple root certificate schema](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.security.root.yaml)
- [Apple PEM certificate schema](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.security.pem.yaml)

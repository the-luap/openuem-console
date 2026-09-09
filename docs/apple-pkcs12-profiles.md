# PKCS12 identity profiles

The identity editor imports one PKCS12/PFX file, up to 256 KiB, into a versioned
`com.apple.security.pkcs12` profile. It preserves the archive bytes and password,
including an explicitly empty password, and uses a fixed payload filename rather
than copying a local path. Supply one private identity with its certificate chain.
The device must accept the password and cryptographic contents during installation.

## Import validation

The server checks a bounded DER-encoded version 3 PFX envelope. It accepts Data
and SignedData outer content; a Data AuthenticatedSafe supports 1–64 Data,
EncryptedData or EnvelopedData sections. Optional MAC metadata is checked for its
basic ASN.1 structure and positive iteration count. Unknown content types,
truncated/trailing bytes, indefinite-length BER and malformed outer fields are
rejected. This is a deliberately limited envelope check, not a full PKCS12 parser.

No uploaded archive is decrypted or passed to the PKCS12 decoder. The existing
decoder accepts attacker-controlled KDF iteration counts and derived-key lengths;
calling it on uploads without additional resource bounds would permit expensive
work or allocation. The envelope path does not perform any KDF, MAC or signature
verification. It does not inspect private keys, match certificates, count encrypted
identities or assess certificate validity dates, trust or revocation. A correctly
structured archive can therefore be saved with an incorrect password or invalid
contents. Review the source before import and verify installation and application
authentication on the target. Test-only decoding uses freshly generated fixtures
with known bounded parameters.

## Scope, protection and lifecycle

System profiles support iPhone/iPad from version 4.0 and Mac from macOS 10.7.
User profiles require a managed Mac user channel. Explicit application key access
requires macOS 10.10; explicit extractability requires macOS 10.15. Both options
are Mac-only, including an explicit `false`: omit them for iPhone and iPad.
These checks apply to uploaded profiles, direct assignment and active System/User
revision changes and restoration. Failed revision checks roll back catalog,
snapshots and queued commands. Removal can proceed despite an incompatible key
option, with fresh native profile inventory providing removal evidence.

The complete profile and retained revisions use existing encrypted storage.
Authorized profile downloads contain the archive and password together; they are
not encrypted merely because the embedded archive has a password. The editor
requires management permission, CSRF and explicit review. Exactly one file is
accepted, with bounded request/file size and rejection of repeated, unrelated and
query fields. Errors, catalog listings and audit details omit archive/password
contents. No identity is installed on the server or development host.

Assigning an imported profile to multiple targets shares the same private
identity. Use [SCEP](apple-scep-profiles.md) when the issuer supports individual
target-generated keys. A profile report confirms delivery rather than final
certificate usability, key access or successful application authentication.

## Validation and remaining acceptance

The isolated core tests pass with unchanged production sources and shared helpers,
alongside the existing public certificate and SCEP tests. Cases cover legacy and
modern synthetic archives, empty and space/Unicode passwords, plist round trips,
byte and certificate-chain preservation, explicit false/default omission, version/channel boundaries,
malformed/oversized envelopes and a huge KDF count that is never executed. A
15-second fuzz run with valid and invalid seeds passes 617,683 executions.

Native cases cover mixed-platform delivery, Mac-only revision and assignment
rejection, older-Mac and managed-user rollback, retained history, encrypted storage,
audit privacy and verified removal. Console cases exercise real scoped multipart
requests, permission/CSRF boundaries, ambiguous forms, extra files, safe errors,
stored System/User settings and escaped display names. Full CI and browser checks
for the identity editor are pending.

Physical acceptance must verify the intended archive/password, certificate chain,
key access/export, application authentication and removal on target OS versions.
Certificate renewal/expiry automation, ACME templates and composite certificate
references remain separate work.

Sources checked 9 September 2026:

- [Apple PKCS12 payload schema](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.security.pkcs12.yaml)
- [RFC 7292: PFX and AuthenticatedSafe structures](https://www.rfc-editor.org/rfc/rfc7292.html#section-4)
- [PKCS12 decoder source](https://github.com/SSLMate/go-pkcs12/tree/v0.7.0)

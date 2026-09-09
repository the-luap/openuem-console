# ACME certificate profiles

The ACME editor creates an encrypted, versioned Apple configuration profile for an
external certificate issuer. Saving and assigning a profile do not contact that
issuer. The target generates its key and requests a certificate after delivery.
This is separate from OpenUEM's SCEP service for MDM enrollment identities.

## Settings and targeting

System scope requires iOS/iPadOS 16 or macOS 13.1 or later. User scope requires a
managed Mac user channel. The required settings are an HTTPS directory URL, an
issuer-approved client identifier, key type and size, explicit hardware binding,
and a subject array. The editor emits an empty subject array when the subject
field is empty; the issuer must accept the requested identity. URLs cannot contain
credentials or fragments. Client identifiers and subject values are preserved.

| Setting | Accepted values |
| --- | --- |
| RSA key | 1024–4096 bits, in multiples of 8; no hardware binding |
| Elliptic curve key | `ECSECPrimeRandom`, 192/256/384/521 bits |
| Hardware-bound key | Elliptic curve, 256/384 bits |
| Subject | One attribute=value per editor line; nested X.500 relative names on the wire |
| Alternative names | At most one scalar string for each email, DNS, URI and NT principal type |
| Extended key usage | Up to 64 numeric OIDs, one per editor line |
| Key usage | Unspecified (0), signature (1), encryption (4), or both (5) |

Optional attestation and key-access switches preserve explicit false. Empty
optional controls omit their keys. The parser rejects noninteger key sizes/usages,
nonboolean switches, malformed names, oversized fields and unsupported combinations.
ACME settings are properties of `com.apple.security.acme`, without a nested SCEP
`PayloadContent` dictionary.

Mac hardware binding requires macOS 14 or later, fresh inventory, and identified
Apple silicon or an exact supported T2 model. The T2 lookup uses Apple's model
identifiers rather than inferring capabilities from an arbitrary model prefix or
generic SecureBoot inventory. T2 Macs ignore `Attest`; older iPhone/iPad hardware
may also ignore it. The issuer must enforce and validate its attestation policy.
`Attest=true` requires hardware binding. `KeyIsExtractable` and
`AllowAllAppsAccess` are Mac-only, including explicit false, so phone/tablet
profiles must omit them. `KeyIsExtractable=false` prevents keychain export as
described in Apple's Developer documentation; the YAML description currently
contains a contradictory sentence about true.

## Durable client ownership

An issuer can treat a client identifier as a one-use credential. A transactionally
reserved identifier belongs to one native device enrollment in its organization.
System and User channels on that enrollment share the namespace. Removal,
cancellation, catalog deletion and enrollment deletion do not release it. A new
enrollment, even on the same physical hardware, needs a new issuer-approved client
identifier. OpenUEM does not promise that an issuer permits repeated requests even
on the same enrollment.

The namespace includes the directory URL. Canonicalization normalizes host case,
the final DNS dot, default port 443, numeric ports, IPv6 spelling, an empty path,
and percent-encoded unreserved path characters. It preserves path case, reserved
path escapes and query semantics. DNS aliases, redirects and issuer-specific
query equivalences cannot be inferred offline. Administrators must use one
consistent directory URL for each issuer; this is not universal CA identity
discovery or proof of all prior use outside OpenUEM.

Client references are encrypted. Lookup hashes use HMAC-SHA256 with a random,
encrypted per-organization key, preventing a database-only offline guess against
a plain client hash. First-writer races re-read the winning key. Composite
profiles acquire client rows in sorted hash order. Claims and assignment commands
commit together. Conflicting multi-device assignments, incompatible revisions and
failed restores roll back catalog, history, claims and commands atomically.

The new encrypted registry keys, references and reviewed archives must be included
in future backup and master-key rotation work. Rewrapping must preserve each
organization's lookup key; regenerating it would lose existing ownership matches.
That broader operational rotation/restore feature remains unfinished.

## Historical archive review

Migration 035 indexes retained revisions referenced by current System/User
assignments, including verified removals, and previously attempted InstallProfile
commands with profile revision metadata, including cancelled commands. It reads
old issuer/client references without applying today's complete key schema.
Decryption failures abort migration. Previously reused identifiers across
enrollments become permanently conflicted; migration does not choose a winner.

A missing or unusable archive becomes an unresolved entry. New ACME assignments
in that organization remain blocked until all such entries are reviewed. Other
profile kinds and profile removal remain available. The ACME history page shows
the enrollment, profile, revision and scope without disclosing client references.
Profile managers can read it; submitting a review additionally requires
organization-wide assignment permission, checked again inside the transaction.

The reviewer supplies the original unsigned XML or binary archive (up to 2 MiB),
the exact expected revision, a source/reason and explicit confirmation. Known
identifier and scope must match. The review reserves any old ACME references and
stores the submitted archive encrypted with actor, timestamp and reason. Repeated
or stale reviews cannot overwrite it. This is attributed administrative
reconstruction, not cryptographic proof of the original bytes or device state.
The original revision remains unchanged and no install command is issued.

Commands that no longer exist or lack historical profile metadata cannot be
recovered by this migration. Issuer-side controls remain necessary. If the
original archive cannot be recovered, the history gap stays unresolved; uploading
a guessed replacement is not a valid operational recovery procedure.

## Access and validation

Creation requires organization profile-management permission, CSRF and review
confirmation. Both forms reject query injection, duplicate fields, unrelated
fields and invalid types; archive review accepts exactly one file. Catalog pages,
history lists and audit events omit client values and archive contents. Authorized
profile downloads contain the client identifier and must be treated accordingly.
Review reasons should describe evidence without including credentials.

The isolated check of unchanged production parsing code and shared helpers passes
wire types, required empty subjects, optional defaults, zero/false, key and name
limits, platform/channel boundaries, exact T2 models, URL canonicalization,
deduplication and legacy reference extraction. Template formatting and generation
pass. The isolated PostgreSQL schema check passes all 35 actual migrations and
304 prepared production SQL statements. This schema check does not execute the
Go history-indexing callback or claim transactions.

Native tests cover concurrent ownership, removal/deletion retention, atomic
shared-revision rollback, System/User ownership, historical migration conflicts,
missing-archive blocking and protected review evidence. Console tests exercise
the actual scoped router, roles, forms, secret-safe failures and history review.
Full CI execution and actual browser acceptance are pending for this change.

Physical iPhone, iPad, Apple silicon Mac and T2 Mac acceptance remains necessary
against the intended issuer. Profile delivery alone does not prove issuance,
renewal, device attestation or application authentication. Certificate composition,
lifecycle reporting and broader PKI operations remain separate roadmap work.

## Primary references

- [Apple ACME payload schema](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.security.acme.yaml)
- [Apple ACME certificate properties](https://developer.apple.com/documentation/devicemanagement/acmecertificate)
- [Apple deployment guide for ACME](https://support.apple.com/guide/deployment/automated-certificate-management-environment-depb95c66a07/web)
- [Macs with the Apple T2 Security Chip](https://support.apple.com/en-ca/103265)
- [MacBook Pro identifiers](https://support.apple.com/en-euro/108052), [MacBook Air identifiers](https://support.apple.com/en-us/102869), [iMac identifiers](https://support.apple.com/en-us/108054), [Mac mini identifiers](https://support.apple.com/en-nz/102852), [Mac Pro identifiers](https://support.apple.com/en-ca/102887)

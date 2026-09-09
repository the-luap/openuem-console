# Certificate references in Apple profiles

Wi-Fi client identities and EAP trust anchors must reference certificate payloads
inside the same configuration profile. An identifier in the catalog, a profile's
root UUID, or a certificate in another installed profile does not satisfy those
references. OpenUEM now checks these bindings during upload, revision changes,
restoration and System/User installation.

`PayloadCertificateUUID` on a Wi-Fi payload must identify exactly one ACME, SCEP,
PKCS12 or Active Directory Certificate identity payload. Public certificates
cannot satisfy a client identity reference. Each entry in the EAP
`PayloadCertificateAnchorUUID` array must identify a public root, PEM or PKCS1
certificate payload. An identity payload cannot serve as a public trust anchor.

References use canonical UUID strings, with case-insensitive matching. Duplicate
payload UUIDs cannot resolve a reference, including duplicates of a different
payload type. Anchor arrays contain 1–64 unique references. Missing references,
wrong types, malformed dictionaries, duplicate anchors, and ambiguous payloads
produce bounded errors without echoing payload values. A Wi-Fi profile without
certificate references does not acquire a new certificate requirement.

System assignments already reparse the stored configuration; User assignments
check references alongside their existing channel and platform validation. This
also covers historical configurations saved before reference validation existed.
Removal does not require a valid reference, so a dangling old identity does not
prevent removing its network profile. Failed revisions retain the old catalog
revision and encrypted history without queuing a replacement.

This checks binding and payload type. Existing certificate and channel validators
retain their own responsibilities. It does not prove private-key possession,
issuer acceptance, successful EAP authentication, or full Active Directory
certificate schema/targeting coverage. A catalog-based editor for composing
certificate and enterprise network payloads, broader Wi-Fi/VPN settings, and
physical network acceptance remain separate roadmap work.

The isolated tests use unchanged production reference-validation code and the
existing map-string helper. They pass identity/anchor types, case normalization,
plist round-tripping, plain Wi-Fi compatibility, missing and ambiguous identities,
wrong credential types, duplicate anchors and secret-safe errors. PostgreSQL
integration tests cover System/User upload and revision rejection, valid local
references, legacy reassignment rejection and removal. Full CI is pending for
this change; there is no new console form or browser behavior.

References: [Apple Wi-Fi payload schema](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.wifi.managed.yaml),
[Apple Active Directory Certificate payload](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.ADCertificate.managed.yaml).

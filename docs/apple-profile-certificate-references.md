# Certificate references in Apple profiles

Wi-Fi client identity UUIDs and explicit EAP trust anchor UUIDs resolve certificate
payloads inside the same configuration profile. An identifier in the catalog, a profile's
root UUID, or a certificate in another installed profile does not satisfy those
references. OpenUEM now checks these bindings during upload, revision changes,
restoration and System/User installation. The device's trust chain can also come
from separately installed certificates or system trust; that does not require
explicit anchor UUIDs pointing into another profile.

Regular `com.apple.vpn.managed` and App-Layer
`com.apple.vpn.managed.applayer` profiles receive the same identity-reference
checks for `PayloadCertificateUUID` inside their `VPN`, `IPSec`, `IKEv2` and
`TransparentProxy` dictionaries. Each present protocol configuration must be a dictionary, and each
present identity reference must identify a local identity payload. A VPN without
such a reference does not acquire a new certificate requirement. This extension
does not validate every VPN setting, require an identity for every authentication
mode, or cover nested Always On tunnel configurations yet. App-Layer VPN's
`VPNUUID` identifies the connection and does not replace a local certificate
payload UUID. The reference check does not establish per-app mapping or provider
installation.

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
issuer acceptance or successful EAP authentication. Active Directory certificate
fields and targets have [separate validation](apple-ad-certificates.md).
The [EAP-TLS composer](apple-enterprise-wifi.md) now
copies selected certificate revisions into one configuration, with local bindings
and target checks. Broader Wi-Fi/VPN settings and physical network acceptance
remain separate roadmap work.

The isolated tests use unchanged production reference-validation code and the
existing map-string helper. They pass identity/anchor types, case normalization,
plist round-tripping, plain Wi-Fi compatibility, missing and ambiguous identities,
wrong credential types, duplicate anchors and secret-safe errors. PostgreSQL
integration tests cover System/User upload and revision rejection, valid local
references, legacy reassignment rejection and removal. Both complete workflows for
`1632e7d` pass: [push](https://github.com/the-luap/openuem-console/actions/runs/34364258266)
and [pull request](https://github.com/the-luap/openuem-console/actions/runs/34364265441).
This includes native protocol/persistence/TLS, scoped console routes, rendering,
gateway/login/CSRF, existing models, desktop authorization/services, Linux/Windows
builds and protected Windows protocol checks. Console handlers, templates and
assets at that commit are unchanged from the 36-case ACME browser check at
`461c235`. Subsequent editor checks are recorded with the EAP-TLS composer.

The VPN extension passes isolated tests for all four protocol dictionaries,
four identity payload types, plist serialization, case normalization, missing or
ambiguous identities, public-certificate rejection and bounded errors. PostgreSQL
tests cover 14 System/User and profile/protocol variants, including upload,
revision and legacy reassignment rejection with removal preserved; execution in
full CI is pending. No VPN client/provider or
physical tunnel authentication has been exercised by these tests.

References: [Apple Wi-Fi payload schema](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.wifi.managed.yaml),
[Apple Active Directory Certificate payload](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.ADCertificate.managed.yaml),
[Apple VPN payload schema](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.vpn.managed.yaml),
[Apple App-Layer VPN schema](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.vpn.managed.applayer.yaml),
[Apple 802.1X deployment guide](https://support.apple.com/en-gb/guide/deployment/depabc994b84/web).

# Active Directory certificate payload validation

Uploaded `com.apple.ADCertificate.managed` profiles and AD identities selected
by the [EAP-TLS composer](apple-enterprise-wifi.md) receive field, scope and target
validation. The typed profile builder accepts `apple-ad-certificate`. A dedicated
console creation form is not yet provided; administrators can upload a prepared
profile and select its retained revision in the Wi-Fi composer.

The payload requires an ASCII fully qualified DNS name for `CertServer` and a
nonempty `CertTemplate` of up to 255 UTF-8 bytes. Punycode DNS labels and a trailing
root dot are accepted; URL syntax, IP literals, wildcards and empty labels are
rejected. Optional descriptions and authority names are bounded text. RPC and
HTTP are the supported acquisition mechanism selections; the server does not
contact either endpoint during profile management.

The renewal notification interval accepts integers from 0 to 3650 days. RSA
`Keysize` accepts integers from 1024 to 8192 bits in multiples of 8. These bounds
are OpenUEM admission limits, not an assertion that every CA template accepts
every value. The certificate authority and template determine issuance policy.
Omitted options remain omitted, and explicit `false` and zero values survive
plist serialization. Notification lead time is separate from automatic renewal.

| Present property | Minimum macOS |
| --- | --- |
| Required server/template, description, renewal notification | 10.7 |
| Certificate authority, acquisition mechanism, credential prompt | 10.8 |
| All-app access or private-key export setting | 10.10 |
| RSA key size | 10.11 |
| Automatic renewal setting | 10.13.4 |

Property presence triggers its version check even for an explicit `false` value.
Automatic renewal can be enabled only for System scope. Interactive credential
prompting is limited by Apple to manually downloaded User profiles: OpenUEM
rejects an enabled prompt for MDM delivery, and requires that computer profiles
omit the prompt key entirely. A disabled User prompt is accepted. Every target
must be a Mac with a known compatible OS version.

Upload, composition, System/User assignment, revision deployment and restoration
apply the checks. Failed revisions roll back catalog changes, historical snapshots
and replacement commands. Removal keeps working when an old profile no longer
satisfies current installation prerequisites. This validates local configuration;
it does not establish directory binding, CA authorization, network connectivity,
private-key export protection, certificate issuance or renewal on physical Macs.

The isolated production payload tests pass for serialized types, absent options,
zero/false values, hostname and value limits, prompt/renewal scope restrictions
and exact version boundaries. Database regression and full CI for this validation
change are pending. Physical AD/CA and Mac acceptance remain required.

Source: [Apple Active Directory Certificate schema](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.ADCertificate.managed.yaml).

# Enterprise Wi-Fi with EAP-TLS

The Apple profiles catalog can create a configuration containing an EAP-TLS Wi-Fi
payload, one copied client identity payload, and optional copied public trust
certificates. Organization profile administrators select exact certificate
revisions with the same System or User scope. User scope targets a managed Mac
user channel. Saving creates a profile; assignment is a separate operation.

## Certificate selection and revision history

The identity source must contain exactly one SCEP, ACME, PKCS12 or Active
Directory Certificate payload. The optional trust source contains only public
root, PEM or PKCS1 certificate payloads, up to 16 payloads. Existing certificate
validators check the copied contents. The final configuration must fit within
the existing 2 MiB profile limit, including XML encoding and metadata.

Selections include the catalog UUID and revision number. Creation loads the
retained encrypted revision inside an authorized transaction, even if the source
catalog was updated or deleted during review. It never substitutes the latest
revision. Copied payloads receive new UUIDs and identifiers; the Wi-Fi identity
and trust references resolve inside the new configuration. Source names and
revision numbers appear in the saved description. The atomic `apple.profile.compose`
audit records source profile and immutable revision IDs without credential values.
The new catalog entry and historical snapshot use the normal encrypted storage.

The copy is independent. Updating, assigning or deleting the source profile does
not update the saved Wi-Fi configuration. Change the composed configuration
through the existing revision upload and restoration controls. These operations
retain encrypted history and check currently assigned targets before committing
replacement commands. The composition form currently creates new configurations;
it does not repopulate an existing composition for editing.

SCEP and ACME copy issuance settings; the target contacts the issuer when it
processes the payload. The server does not request a certificate while composing
or assigning the profile. The issuer controls challenge acceptance, certificate
issuance and reuse. ACME's existing durable client ownership also applies across
copies with new payload UUIDs: one issuer/client identity can serve only one
enrollment. PKCS12 copies preserve the same imported private key and password.
Private-key possession and password correctness remain device/issuer checks.

Active Directory identities require macOS. Composition applies the
[AD Certificate field and target checks](apple-ad-certificates.md), including
credential prompting and automatic renewal restrictions. Directory binding and
CA authorization remain external prerequisites.

## Network and trust settings

The SSID preserves case and spaces and accepts 1–32 UTF-8 bytes without NUL or line
breaks. Auto-join and hidden-network choices are explicit booleans. The editor
selects only EAP type 13, requires a client certificate and requires 1–64 trusted
RADIUS certificate names. Wildcards occupy a whole component, for example
`*.example.com` or `wpa.*.example.com`. A bare wildcard is rejected.

Choose public CA certificates or intended RADIUS leaf certificates as explicit
anchors, or explicitly use trust already present on the device. In both cases the
RADIUS certificate must satisfy the configured names. The editor emits no user
password or trust-exception key. `TLSAllowTrustExceptions` was removed on
iOS/iPadOS 8; uploaded configurations containing that key, including `false`, are
rejected for those targets. Changing scope clears incompatible certificate
selections and confirmation. It does not silently replace selected anchors with
existing device trust; the operator must choose again.

The EAP response identity is optional. An empty selection leaves the certificate
identity's common name as the default. A TLS 1.3 minimum requires an outer identity
accepted by the RADIUS server, following Apple's EAP configuration property
requirement. The server must support the selected TLS range.

| Setting | iOS/iPadOS minimum | macOS minimum |
| --- | --- | --- |
| Explicit TLS 1.2 bounds | 11 | 10.13 |
| EAP-TLS 1.3 selected, including a 1.2–1.3 range | 17 | 14 |
| WPA3-only network | 16 | 13 |

The editor defaults to TLS 1.2 for both bounds and WPA2/WPA3 compatibility. The
minimum cannot exceed the maximum. On older iPhone/iPad versions, Apple's WPA2
setting may also permit older WPA networks; WPA3-only has an explicit modern OS
gate. Certificate-specific options can raise these minimums. Device and User
assignment, revision deployment and restoration retain those checks. Removal does
not require the target to meet installation prerequisites.

## Validation and acceptance

Payload tests cover all four identity sources, System/User scope, retained secret
bytes, new local UUID bindings, explicit booleans, existing trust, malformed
inputs and TLS/WPA3 platform boundaries. Database tests cover retained revisions
after source update/deletion, organization isolation, encrypted copies, atomic
audit failure rollback, mixed-device and User revision rollback, removal, ACME
ownership across copies and rejection of AD identities on iPhone. Scoped route
tests cover permissions, CSRF, confirmation, duplicate/query/unexpected fields,
exact revision selection, trust scope, bounded errors and protected downloads.

The isolated payload check and preparation of 306 production SQL statements
against all 35 migrations pass. All 39 actual Chrome cases pass using the CI
renderings at `b0e5134`: System/User scope, existing/explicit trust, three TLS
ranges and three viewport widths, plus reader views. These cover scope reset,
UTF-8 limits, required outer identity, exact revision form data, keyboard review
and submission, reset behavior and page overflow. Native OS select menus are not
part of this automated check. Both complete workflows for `e2e076c` pass:
[push](https://github.com/the-luap/openuem-console/actions/runs/34370058579) and
[pull request](https://github.com/the-luap/openuem-console/actions/runs/34370059657).
They cover native protocol/persistence/TLS, scoped console routes, rendering,
gateway/login/CSRF, models, desktop services, Linux/Windows builds and protected
Windows protocol tests. The initial run exposed a missing foreign-organization
Apple-settings fixture; the corrected fixture retains cross-organization checks.
Profile installation or a synthetic protocol test does not establish
successful certificate issuance or 802.1X authentication. Physical Mac, iPhone and
iPad acceptance must verify issuance, RADIUS name/trust enforcement, rejected
server certificates, selected TLS versions, roaming, renewal and removal.

Sources: [Apple Wi-Fi payload schema](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.wifi.managed.yaml),
[Apple EAP client configuration](https://developer.apple.com/documentation/devicemanagement/wifi/eapclientconfiguration-data.dictionary),
[Apple 802.1X deployment guide](https://support.apple.com/en-gb/guide/deployment/depabc994b84/web),
[Apple certificate trust for 802.1X](https://support.apple.com/en-gb/guide/deployment/depb59c050ef/web),
[Apple AD Certificate payload](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.ADCertificate.managed.yaml).

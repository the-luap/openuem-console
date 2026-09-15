# Apple certificate and network acceptance

Status: **not executed on physical devices or external providers**. This is the
test procedure for the implemented certificate, enterprise Wi-Fi and IKEv2 paths.
The [browser regression](../tests/browser/README.md) and protocol/database CI
provide separate automated evidence; neither establishes network acceptance.

## Record the environment

Use a designated test organization, enrolled test devices, and controlled CA,
RADIUS and VPN endpoints. Record the console commit, device model and OS/build,
enrollment method, reported supervision, inventory timestamp and System/User
channel. User means a [managed Mac user channel](macos-user-channels.md), not
account-driven User Enrollment. Test iPhone and iPad separately.

Record each source profile UUID/revision, composed profile UUID/revision,
assignment and resulting command ID. For provider evidence, retain timestamps,
certificate fingerprints, issuer/template identifiers, negotiated TLS/IKE
parameters and relevant sanitized outcomes. Keep private keys, passwords,
challenges, bearer tokens and full protected profiles out of shared test reports.

For each case, record **passed**, **failed** or **not run**, the observation time,
expected and observed behavior, and evidence location. A missing platform or
provider remains **not run**. Do not infer its result from another platform.

## Separate the observable stages

| Stage | Evidence to collect |
| --- | --- |
| Saved | Exact composed revision, local payload bindings and source lineage; no assignment implied |
| Delivered | Target/channel, command status and any device error chain |
| Installed | Device-reported profile inventory matching the intended configuration |
| Identity available | Issuer/client evidence of the resulting identity and usable private key; AD template/binding where applicable |
| Authenticated | RADIUS or VPN service accepted the intended client identity and authentication mode |
| Network behavior | Selected protocol, routes, DNS, rule/exception behavior and accessible test resources |
| Removed | Device reports removal and subsequent observations match the intended unmanaged state |

An acknowledged install is not a substitute for later observations. A connection
that still succeeds after removal may use existing credentials, device trust,
another profile or a manually configured network; identify the cause before
recording a result.

## Certificate composition

1. Create identity and optional public-trust source profiles using the intended
   scope. Run applicable issuance checks from the [SCEP](apple-scep-profiles.md),
   [ACME](apple-acme-profiles.md), [PKCS12](apple-pkcs12-profiles.md) or
   [AD Certificate](apple-ad-certificates.md) guide.
2. Create Wi-Fi or IKEv2 configurations from explicitly selected revisions.
   Record the copied payload UUIDs and certificate references through an
   authorized download. Verify that all references resolve within that profile.
3. Update a source profile. Confirm that the existing composed revision remains
   unchanged and still refers to the selected source revision in its provenance.
   Create a separate composition to exercise the new source revision.
4. Assign one composition to its intended test device/channel. Collect installation,
   issuer and network evidence separately. ACME client ownership remains bound to
   one enrollment across copies; PKCS12 copies reuse the imported private key.
5. Exercise a rejected identity or issuer configuration using controlled test
   credentials, and record the device/provider error. The profile must not be
   reported as successfully authenticating based only on delivery.

## Enterprise Wi-Fi

Run the supported combinations from [enterprise Wi-Fi](apple-enterprise-wifi.md)
on iPhone, iPad, Mac System and Mac User channels. Include the intended identity
provider, existing/explicit trust and supported TLS ranges. Record the RADIUS
server certificate names and negotiated TLS version.

| Case | Required observation |
| --- | --- |
| Valid identity and server | Successful EAP-TLS authentication and access to the designated test resource |
| Wrong server name or untrusted server certificate | Authentication rejected; no acceptance based on profile installation alone |
| Incompatible TLS configuration | Connection does not negotiate outside the configured range |
| SSID with spaces or non-ASCII characters | Exact network selection without normalization |
| Network loss and return | Actual reconnect behavior agrees with auto-join selection |
| Certificate renewal/replacement | New identity is observed at the issuer and used for a subsequent authentication |
| Revision replacement and removal | Installed revision and resulting connection behavior are recorded separately |

## IKEv2 certificate authentication

Run machine-certificate and EAP-TLS modes using supported identity algorithms,
the intended server issuer/common-name settings and existing/explicit trust.
Follow the platform limits in [VPN validation](apple-vpn-profiles.md).

| Case | Required observation |
| --- | --- |
| Machine authentication | VPN service accepts the selected client certificate and records the expected IKE parameters |
| EAP-TLS | VPN service records EAP-TLS with the intended client identity and configured TLS 1.2 bounds |
| Incorrect issuer, server identity or trust | Record rejection and the device/provider cause; do not silently broaden trust to make the case pass |
| Wrong PKCS12 password or identity algorithm | Device/provider rejects the unusable identity; bounded catalog admission alone is insufficient |
| Reconnect, sleep/wake and network change | Record actual tunnel recovery and any user interaction |
| Revision replacement and removal | Device and VPN service observations identify which configuration/identity remains active |

## Uploaded rules and Always On exceptions

The current certificate editor creates regular IKEv2 profiles. On-demand and
Always On cases require separately prepared, reviewed uploads; the editor does
not generate these settings. Perform Always On cases only on eligible supervised
test iPhones/iPads and retain the platform/version evidence.

For on-demand rules, use controlled networks, domains, DNS servers and probe URLs.
Exercise Connect, Disconnect and Ignore, then ordered EvaluateConnection rules
with NeverConnect and ConnectIfNeeded. Record which rule should match and the
actual connection outcome after changing networks or making a new request.
Test overlapping rules in both orders. Distinguish a successful outer URL probe
from the failed required probe that can trigger ConnectIfNeeded. Keep the original
profile bytes and sanitized observations; the server does not simulate matching.

For Always On, verify the selected Wi-Fi/cellular interfaces and baseline tunnel
traffic first. Exercise service Allow/Drop exceptions individually, and app
exceptions with and without the UDP limit using a controlled test app/server.
Record observed UDP and TCP behavior separately. Test specified captive-network
plugins and the allow-all switch separately; a configured specific list does not
narrow Apple's allow-all behavior. Do not infer exception routing from the
presence of a key in installed profile inventory.

Apple defines the ordered-rule, probe and exception behavior in its
[VPN payload schema](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.vpn.managed.yaml).
Provider configuration and real traffic evidence remain necessary for each case.

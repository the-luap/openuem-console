# Apple VPN configuration validation

Uploaded regular and App-Layer VPN payloads now validate the connection name,
selected protocol dictionary, provider subtype and configuration dictionary types.
App-Layer profiles require a canonical nonzero connection UUID and support VPN,
IPSec or IKEv2. A managed Mac User channel remains distinct from User Enrollment:
regular VPN profiles reject a reported User Enrollment, while App-Layer profiles
can use that enrollment type.

The validator applies during upload, System/User assignment, revision changes
and restoration. Failed revisions retain the catalog, encrypted history and queued
commands. Removal remains available when installation prerequisites are no longer
satisfied. This is partial schema validation; broader protocol authentication,
provider configuration, app mapping, routes, additional property versions and VPN
editors remain separate implementation work.
The [certificate and network acceptance procedure](apple-network-acceptance.md)
records the outstanding device/provider checks and the evidence needed for each.

## DNS settings

The VPN `DNS` dictionary accepts Cleartext, HTTPS and TLS protocol selections.
HTTPS requires an HTTPS resolver URL without credentials or a fragment; URI
templates in the path/query are retained. TLS requires an ASCII/Punycode fully
qualified resolver name. A present address list accepts IPv4 and IPv6 literals.
DNS lists contain 1–64 bounded entries; a supplemental match domain can be empty
to select the default domain. Search behavior uses integer 0/1, preserving explicit
zero. Connection names and DNS list limits are OpenUEM admission bounds.

The DNS protocol can remain omitted in uploaded legacy resolver configurations.
No identity requirement is added when the DNS certificate reference is absent.
A present reference must resolve a unique local identity payload, independently
of the tunnel's identity, as described in
[certificate reference validation](apple-profile-certificate-references.md).

| Present DNS property | Minimum macOS | Minimum iOS/iPadOS |
| --- | --- | --- |
| Server addresses, search/supplemental domains, primary domain, search switch | 10.12 | 10.0 |
| Explicit protocol, HTTPS URL or TLS server name | 11.0 | 14.0 |
| Client identity certificate reference | 13.0 | 16.0 |

Version checks use property presence, including an explicit Cleartext selection
or integer zero. DNS server certificate trust, mutual TLS authentication and actual
resolver selection require device and server acceptance.

## Target and Always On checks

Regular VPN payloads use the base macOS 10.7/iOS 4.0 capability; App-Layer payloads
require macOS 10.9/iOS 7.0. IKEv2 configurations require macOS 10.11/iOS 8.0.
These base limits are not a compatibility guarantee for
every protocol or nested setting. Transparent proxy configuration is restricted
to macOS 14 or later. Known target platform and OS inventory are required.

Always On configuration requires a System profile targeting an iPhone or iPad
with iOS/iPadOS 8 or later and reported supervision. OpenUEM additionally requires
device inventory from the preceding 24 hours and rejects future timestamps.
Tunnel configuration arrays contain 1–64 dictionaries selecting IKEv2. Optional
interfaces select WiFi, Cellular or both, without duplicate entries. The count is
an OpenUEM admission bound. IKEv2 fields reside directly in each tunnel, alongside
`ProtocolType` and `Interfaces`; a nested `IKEv2` dictionary cannot replace the
required flat fields. Each tunnel now receives IKEv2 authentication, type, version
and certificate-reference checks. On iOS/iPadOS 14.2 or later, both IKE and child
security association Diffie-Hellman groups must be 14 or greater. Omitted child
settings retain their documented inheritance. The UI-toggle and captive-network
switches use integer 0/1. Routing and a complete Always On editor remain open;
this does not establish a working Always On connection.

Always On service exceptions accept VoiceMail, AirPrint, CellularServices and
DeviceCommunication with an explicit Allow/Drop action. CellularServices requires
iOS/iPadOS 11.3; DeviceCommunication requires 17.4. Application exceptions require
13.6, including an explicitly empty list. Their optional protocol limit supports
UDP only. Omitting that limit retains Apple's unrestricted app exception.
Captive-network plugin entries name an exact app bundle identifier. A specific
plugin list is validated even when the allow-all switch makes Apple ignore it;
validation preserves both fields as supplied.

Exception arrays allow zero to 64 dictionaries. OpenUEM requires unique services,
unique bundle identifiers ignoring case, reverse-DNS bundle identifiers of at
most 255 bytes, and exactly one UDP entry when a protocol limit is supplied.
These size, uniqueness and nonempty-limit rules are admission policies. Unsupported
fields inside exception entries are rejected to catch misspelled routing limits.
No wildcard identifier, conflicting service action or invalid ignored list is
accepted, and errors do not echo submitted values. Real traffic exclusions still
require device testing.

## IKEv2 authentication and cryptography

The regular `IKEv2` dictionary, including in App-Layer profiles, now requires a
server hostname/IP address, local/remote identifiers and the authentication
selection None, SharedSecret or Certificate. Optional account and secret values
remain omitted unless supplied, and retained strings preserve whitespace. Names,
identifiers and secrets have OpenUEM size bounds. An uploaded profile without a
certificate UUID does not acquire one; a present UUID still resolves locally.
The server does not infer issuer acceptance, client identity matching or
possession of the private key from these fields.

Explicit certificate types accept RSA, ECDSA256/384/521 or RSA-PSS and require a
server certificate issuer name. This follows the stricter requirement in Apple's
`CertificateType` description; the issuer property's description also mentions
extended authentication. Issuer selection is not a trust anchor. A server-name
override remains optional; otherwise Apple uses the remote identifier.

IKEv2 TLS bounds accept 1.0, 1.1 and 1.2, with minimum no greater than maximum.
These are IKEv2 EAP-TLS settings; the Wi-Fi composer's TLS 1.3 option does not
apply. Present bounds require macOS 10.13/iOS 11. Integer 0/1 checks cover EAP,
on-demand, idle, mobility, redirect, PFS, revocation, routing and post-quantum
switches. Property versions apply even when a switch is zero. Fallback and
on-demand user override restrictions are unavailable on Mac, including User
profiles. Provider signature requirements are Mac-only. MTU accepts 1280–1400
bytes from macOS 11/iOS 14; NAT keepalive intervals start at 20 seconds. Timer
values have an OpenUEM signed 32-bit upper bound.

Security association dictionaries validate encryption/integrity selections,
Diffie-Hellman groups and 10–1440 minute lifetimes. An omitted child dictionary
inherits the IKE dictionary; a present dictionary uses its own property defaults.
DES, 3DES, SHA-1 integrity and Diffie-Hellman groups below 14 are rejected on OS 26.
Strict algorithm selection additionally rejects DES/3DES or small groups on older
supported versions and requires the IKE encryption strength to be at least the
child encryption strength. Its property requires macOS 15.5/iOS 18.5.

Post-quantum pre-shared keys require data and a key identifier together, from
macOS 15/iOS 18. The key admission bound is 1–4096 bytes and does not prove the
server's key policy. Additional key exchange arrays accept 1–7 integer methods
0, 36 or 37 from OS 26; the fallback switch has the same version requirement.
No cryptographic exchange is performed by saving a profile. Provider schemas,
further protocol options and additional console editors remain open.

## IKEv2 on-demand rules

Regular and App-Layer IKEv2 dictionaries, and flat IKEv2 settings in Always On
tunnels, validate `OnDemandRules` even when `OnDemandEnabled` is zero. Rules accept
Allow (deprecated but retained), Connect, Disconnect, EvaluateConnection and Ignore.
`ActionParameters` is accepted only for EvaluateConnection, and each evaluation
requires a nonempty domain list and ConnectIfNeeded or NeverConnect. Required DNS
servers and URL probes are restricted to ConnectIfNeeded. DNS servers must be IP
literals; probes use HTTP/HTTPS URLs without credentials or fragments.

Rule order, duplicate match strings, wildcard text, optional omissions and
explicit empty optional arrays are preserved. Domain and DNS-match patterns are
bounded strings interpreted by the device; the server does not simulate wildcard
matching, reachability or rule selection. Interface choices are Ethernet, WiFi or
Cellular. SSIDs preserve whitespace and accept 1–32 UTF-8 bytes. Unknown rule or
evaluation fields are rejected to catch misspelled conditions. List limits of 64,
domain/match text limits of 254 bytes, probe URL limits of 2048 bytes and nonempty
required domain/DNS lists are OpenUEM admission rules.

These checks use the existing IKEv2 platform floor. They do not yet extend to the
separate provider VPN, IPSec or TransparentProxy dictionaries, supply an on-demand
editor or establish real connection behavior. Always On tunnel fields remain
subject to the existing supervised mobile target checks.

## Certificate profile generator

The typed `BuildProfile` generator accepts `vpn-ikev2-certificate` with machine
certificate or EAP-TLS authentication. It copies one SCEP, ACME, PKCS12 or AD
identity configuration into a regular VPN profile, assigns new local payload
identifiers/UUIDs and preserves source credentials. Optional public trust
certificate payloads are copied separately. IKEv2 has no Wi-Fi anchor UUID array;
the generator does not emit one. Sources and VPN use the same System/User scope.

The caller supplies connection/server details, local/remote identifiers, the
certificate algorithm and server issuer name. An optional server-name override
is preserved. SCEP/AD RSA and ACME RSA/EC settings must match the selected
algorithm; a PKCS12 archive's actual identity algorithm remains unverified by the
bounded envelope parser. EAP-TLS emits explicit TLS 1.2 bounds and integer extended
authentication `1`; machine authentication emits `0` and omits EAP TLS bounds.
Neither mode emits passwords, shared secrets, on-demand rules or routing changes.
Unexpected builder settings are rejected.

The store's `CreateIKEv2CertificateProfile` method composes exact retained
certificate revisions with organization profile permission checked inside the
transaction. Source updates and catalog deletion do not substitute a newer
revision. A shared transaction implementation with EAP-TLS Wi-Fi saves the
encrypted profile, retained snapshot and `apple.profile.compose` audit together.
The audit records source profile/revision identifiers without credentials, and
the profile description records copy provenance. The dedicated console form
exposes this workflow to organization profile administrators. Existing save/assignment paths preserve ACME client
ownership and AD Mac-only target checks. Generation alone does not assign the
profile, contact an issuer or establish a VPN connection.

The form requires explicit certificate algorithm selection and review confirmation.
Changing scope clears incompatible identity/trust selections and confirmation;
it does not silently switch a selected trust profile to existing device trust.
Selecting SCEP or AD disables EC algorithms and clears a previously selected EC
algorithm. ACME and PKCS12 retain explicit algorithm choices, with backend checks
for known ACME key parameters. Switching authentication updates the OS/TLS
guidance. Strict single-value forms, CSRF and organization authorization apply;
catalog rows omit credentials, and protected downloads require profile rights.

## Validation evidence

Isolated tests run unchanged production code and pass plist types, integer zero,
empty default domains, resolver validation, DNS certificate bindings, protocol and
dictionary checks, Mac/mobile version boundaries, User scope and supervision
freshness. PostgreSQL tests cover System/User revision rollback without command
or history changes, DNS certificate OS limits, supervised mobile assignment and
removal after prerequisite changes. Both complete workflows for the target/DNS
change at `f311fc2` pass:
[push](https://github.com/the-luap/openuem-console/actions/runs/34374982861) and
[pull request](https://github.com/the-luap/openuem-console/actions/runs/34374986708).
Console forms and assets are unchanged from the preceding 54 browser
cases for AD certificates and EAP-TLS composition. No tunnel, DNS request or
provider installation is performed by these tests.

The subsequent IKEv2 extension passes isolated unchanged-source tests for
authentication, serialized values, malformed input, TLS and property boundaries,
post-quantum parameters, strict selection, child inheritance and removed
algorithms. PostgreSQL regression cases add eight System/User property upgrades,
failed revision rollback, modern replacements and rejected legacy restoration.
Both complete workflows for this IKEv2 validation at `d5f7ec5` pass:
[push](https://github.com/the-luap/openuem-console/actions/runs/34375938850) and
[pull request](https://github.com/the-luap/openuem-console/actions/runs/34375944694).

The Always On extension also passes isolated tests for multiple flat tunnels,
identity types and ambiguity, malformed structures, integer switches, nested TLS
versions and the iOS 14.2 group boundary. PostgreSQL cases cover a retained
legacy group, its modern replacement, rejected restoration without command or
history changes, and removal after an invalid historical reference. Both complete
workflows at `babeb2d` pass:
[push](https://github.com/the-luap/openuem-console/actions/runs/34376612081) and
[pull request](https://github.com/the-luap/openuem-console/actions/runs/34376620726).

The generator passes isolated tests for both scopes, four identity kinds, machine
and EAP-TLS modes, unchanged source credentials, new local bindings, omitted
settings and invalid input. PostgreSQL tests cover encrypted persistence,
System/User assignment, ACME ownership across copied profiles and AD target
restrictions. Both complete workflows at `0b2e60c` pass:
[push](https://github.com/the-luap/openuem-console/actions/runs/34377321097) and
[pull request](https://github.com/the-luap/openuem-console/actions/runs/34377327909).

The store composition tests cover both scopes, source update/deletion, exact
retained credentials, permission denial, cross-organization and malformed-source
rejection, typed option mapping, encrypted storage and audit-failure rollback.
The existing Wi-Fi composition regression tests cover the shared transaction.
Production SQL text is unchanged; extraction still identifies 306 statements.
Both complete workflows at `04fe0cd` pass:
[push](https://github.com/the-luap/openuem-console/actions/runs/34377717017) and
[pull request](https://github.com/the-luap/openuem-console/actions/runs/34377722460).

Scoped console tests add permission and CSRF denial, strict form parsing, exact
retained revision selection, scope/algorithm checks, System/User and machine/EAP
modes, trust selection and credential/download privacy. Template generation
passes. Both complete workflows at `e20074e` pass:
[push](https://github.com/the-luap/openuem-console/actions/runs/34378307726) and
[pull request](https://github.com/the-luap/openuem-console/actions/runs/34378312007).

The rendered CI artifact at `e20074e` passes 27 actual Chrome cases: System/User,
machine/EAP-TLS, existing/copied trust and reader states at 390/768/1440 pixels.
Checks include required algorithm/review, clearing incompatible selections,
exact revision and form values, keyboard confirmation/submission, repeated
initialization, reset and horizontal overflow. The narrow IKEv2 view was also
visually inspected. The same artifact passes the existing 39 Wi-Fi and 15 AD
certificate browser cases, giving 81 passing cases across the three editors.
Select values use change events; these checks do not exercise operating-system
select menus, Safari or physical devices. Form submissions are captured locally.

The [repository browser runner](../tests/browser/README.md) now retains all three
suites with shared lifecycle, request isolation, time limits and machine-readable
results. Its local run passes all 81 cases against the same `e20074e` artifact.
A disposable fixture with the required VPN algorithm attribute removed fails at
the expected assertion, returns exit status 1 and saves a failure screenshot.
Both complete CI workflows, including the new browser steps, at `b41e647` pass:
[push](https://github.com/the-luap/openuem-console/actions/runs/34380299127) and
[pull request](https://github.com/the-luap/openuem-console/actions/runs/34380304160).
The downloaded push artifact records all 81 cases passing on Linux with Node
24.20.0 and Chrome 152.0.7977.82. All three narrow screenshots were visually
inspected. Local success and intentional-failure runs left no owned browser
processes or temporary browser profiles behind.
A further local isolation check inserted a request to a second owned loopback
server: the browser runner rejected it, and that server observed zero requests.

The subsequent Always On exception validator passes isolated tests using 25
unchanged production/test files (0.454 seconds), including plist preservation,
iPhone/iPad version boundaries, empty arrays, ambiguous/oversized lists, unsupported
fields and invalid ignored captive lists. PostgreSQL regression cases cover three
exception-version upgrades across two assigned devices, atomic rejected revisions
and restoration, and removal after a malformed encrypted historical payload.
Both complete workflows at `c9e0c93` pass:
[push](https://github.com/the-luap/openuem-console/actions/runs/34380904751) and
[pull request](https://github.com/the-luap/openuem-console/actions/runs/34380910735).
They also rerun the 81 browser cases against their own rendered templates.

The IKEv2 on-demand extension passes an isolated run of 27 unchanged
production/test files (0.443 seconds). Cases cover plist order/value preservation,
explicit disabled/empty rules, all actions, field placement, required DNS/probe
conditions, malformed types, UTF-8 SSID byte limits and error redaction.
PostgreSQL cases cover five System/User, regular/App-Layer and Always On paths:
upload, rejected revision without catalog/history/command changes, valid replacement
and encrypted legacy assignment rejection with removal retained. Both complete
workflows at `abc5ecd` pass:
[push](https://github.com/the-luap/openuem-console/actions/runs/34381626280) and
[pull request](https://github.com/the-luap/openuem-console/actions/runs/34381631621).
Both also pass the 81 automatic browser cases; the console templates and browser
suites are unchanged.

The tunnel field layout is recorded in Apple's *Configuration Profile Reference*,
2019-03-25, page 103, preserved as an
[archived Apple PDF](https://raw.githubusercontent.com/ProfileCreator/Configuration-Profile-Reference/8f17394e05c3e58282ed5197e8fc230215b756c4/pdf/Configuration-Profile-Reference-2019-03-25.pdf).
The current Apple schema lists the tunnel protocol/interfaces but omits the
inherited IKEv2 fields; the historical primary document provides that detail.

Sources: [Apple VPN schema](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.vpn.managed.yaml),
[Apple App-Layer schema](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.vpn.managed.applayer.yaml),
[Apple IKEv2 deployment settings](https://support.apple.com/en-au/guide/deployment/dep4ce9487d/web),
[strongSwan's Apple interoperability documentation](https://docs.strongswan.org/docs/latest/interop/ios.html).

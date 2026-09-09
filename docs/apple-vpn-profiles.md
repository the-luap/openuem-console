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
satisfied. This is partial schema validation; protocol authentication settings,
provider configuration, app mapping, routes, broader property versions and VPN
editors remain separate implementation work.

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
require macOS 10.9/iOS 7.0. These base limits are not a compatibility guarantee for
every protocol or nested setting. Transparent proxy configuration is restricted
to macOS 14 or later. Known target platform and OS inventory are required.

Always On configuration requires a System profile targeting an iPhone or iPad
with iOS/iPadOS 8 or later and reported supervision. OpenUEM additionally requires
device inventory from the preceding 24 hours and rejects future timestamps.
Tunnel configuration arrays contain 1–64 dictionaries selecting IKEv2. Optional
interfaces select WiFi, Cellular or both, without duplicate entries. The count is
an OpenUEM admission bound. Nested tunnel authentication and certificate references,
exceptions, routing, captive networking and a complete Always On editor remain
open; this change does not establish a working Always On connection.

## Validation evidence

Isolated tests run unchanged production code and pass plist types, integer zero,
empty default domains, resolver validation, DNS certificate bindings, protocol and
dictionary checks, Mac/mobile version boundaries, User scope and supervision
freshness. PostgreSQL tests cover System/User revision rollback without command
or history changes, DNS certificate OS limits, supervised mobile assignment and
removal after prerequisite changes. Full regression CI for these additions is
pending. Console forms and assets are unchanged from the preceding 54 browser
cases for AD certificates and EAP-TLS composition. No tunnel, DNS request or
provider installation is performed by these tests.

Sources: [Apple VPN schema](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.vpn.managed.yaml),
[Apple App-Layer schema](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.vpn.managed.applayer.yaml),
[Apple IKEv2 deployment settings](https://support.apple.com/en-au/guide/deployment/dep4ce9487d/web).

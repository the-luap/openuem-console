# Native Windows MDM implementation

WIN-02 is in progress. The first native protocol component is discovery in
[`internal/mdm/windows`](../internal/mdm/windows). It is separate from the existing
OpenUEM agent. The package currently contains a bounded SOAP/XML decoder, a
discovery response builder, an immutable HTTPS discovery handler and an OnPremise
XCEP request decoder. It is not registered in a production listener or gateway.

This does not yet enroll Windows, issue a device certificate or apply a CSP.
Authenticated XCEP/WSTEP enrollment, durable scoped identities, provisioning,
SyncML commands and results, policy/update workflows, certificate renewal,
unenrollment, console integration and physical Windows acceptance remain open.
Entra/Autopilot require separate implementation and acceptance.

## Discovery behavior

`NewDiscoveryHandler` accepts one configured HTTPS discovery URL with the exact
`/EnrollmentServer/Discovery.svc` path and configured enrollment service options.
GET and HEAD return an empty availability response. POST accepts a bounded
SOAP 1.2 discovery request and returns the configured enrollment endpoints with
the original WS-Addressing message ID in `RelatesTo`.

The request's email/domain-user name, OS edition, device type and application
version are unauthenticated hints. They never select organization/site authority,
issue a certificate, allocate a device record or consume an invitation. The
response does not echo these hints. The body `To` and HTTP Host must match the
configured discovery endpoint; forwarded headers do not change TLS requirements,
authority or response URLs. Policy and enrollment URLs must share a hostname.

The codec recognizes the published discovery versions 1–9 and authentication
policy names `OnPremise`, `Federated` and `Certificate`. A response may select
version 3–9, no newer than the request, and only a policy the request offered.
This is message grammar, not a claim that any authentication provider or those
versions' complete enrollment capabilities are implemented. No attestation or
Device Provisioning Gateway endpoints are advertised. Likewise, parsing the
historical `WindowsPhone` device-type value or a numeric OS-edition hint does not
declare that platform/edition supported. The supported OS/edition/architecture
matrix remains to be implemented and verified.

## Protocol boundaries

- Requests are UTF-8 XML 1.0, at most 128 KiB, with at most 4,096 elements,
  depth 32, 32 attributes per element and 64 in-scope namespace bindings. These
  are OpenUEM resource limits, not Microsoft limits.
- Namespace aliases resolve explicitly. Unknown prefixes, duplicate expanded
  attributes, conflicting known fields, multiple roots/bodies, malformed XML
  declarations, DTDs and external entities are rejected. Unknown required SOAP
  headers are rejected; optional extension headers cannot establish authority.
- The canonical enrollment namespace and the trailing-slash form used in
  Microsoft's discovery examples are accepted consistently within the body.
  Both ordinary UUID URNs and the published example's space after `urn:uuid:`
  are accepted; the complete validated ID is preserved for correlation.
- Discovery service configuration requires canonical HTTPS URLs without user
  information, query strings, fragments, encoded/dot/duplicate-slash paths or
  invalid ports/hosts. Host case and explicit default port 443 are equivalent;
  paths remain case-sensitive. Automatic DNS discovery and case/alias behavior
  still require real Windows acceptance.
- POST requires `application/soap+xml`, optional UTF-8 charset and, if present,
  the matching SOAP 1.2 media-type action. SOAP 1.1 `SOAPAction`, compressed input,
  conflicting content types and other media parameters are rejected.
- Responses, including faults, have an explicit `Content-Length`, no chunked
  transfer and `Cache-Control: no-store`. Faults use fixed English text and do
  not reflect account hints, submitted XML or parser errors.
- The handler requires a TLS connection. Its future server owner must add bounded
  headers, read/write timeouts, admission limits and the trusted gateway boundary.
  TLS termination and public routing have not been integrated in this step.

## Automated evidence

Run the self-contained package without a database or device:

```sh
go test -race -count=1 ./internal/mdm/windows
go test -run '^$' -fuzz=FuzzDiscovery -fuzztime=30s -parallel=2 ./internal/mdm/windows
go test -run '^$' -fuzz=FuzzPolicyRequest -fuzztime=30s -parallel=2 ./internal/mdm/windows
```

Tests use synthetic accounts and local TLS servers. They cover wire namespaces,
version and policy negotiation, endpoint binding, parser/HTTP rejection cases,
exact body limits, complete HTTP/1.1 responses, SOAP faults, read-only probes and
24 concurrent request correlations. Response XML is decoded independently with
Go's standard namespace resolver. No certificate is issued or installed, no
Windows account/settings are changed and no external enrollment service is used.

The discovery-only local race baseline passes with 97.0% statement coverage.
An initial 30-second parser
fuzz run completed 1,380,623 executions without a failure; the subsequent final
race run also covers literal whitespace outside the root and bracketed-host
rejections added during review. The existing CI workflow now includes this package on
Linux with race detection and on native Windows, plus a bounded Linux fuzz run.
Those added workflow steps are not remote execution evidence until their runs
complete. Physical Windows enrollment has not been tested.

## OnPremise certificate policy request

`ParsePolicyRequest` parses the MS-MDE2 variant of XCEP `GetPolicies`. It checks
the SOAP action and configured destination, the `client` fields `lastUpdate` and
`preferredLanguage`, and `requestFilter`. All three fields must carry a true
`xsi:nil` marker as specified for this enrollment flow. General XCEP policy
queries are not accepted through this decoder.

Exactly one WS-Security `UsernameToken` is accepted. It requires one username,
one `PasswordText` password and a bounded XML-name `u:Id` label. The published
fixed token label is accepted; an alternative label cannot establish authority
or replay protection. Both qualified `wsse:Type` from Microsoft's examples and
unqualified `Type` are recognized, while duplicate or conflicting attributes
are rejected. Additional authentication mechanisms, signatures and timestamps
are rejected by this OnPremise decoder; they cannot silently become password
authentication. Federated and certificate-authentication flows remain separate
unfinished work.

Passwords retain their exact decoded XML text, including leading and trailing
whitespace. XML entity and line-ending processing still applies. Usernames are
bounded to 512 bytes and passwords to 1,024 bytes; these are OpenUEM admission
limits. Returned credential objects redact their default Go formatting and omit
their username/password fields from JSON/XML/YAML serialization. Callers must
still never log individual fields or the original SOAP request.

This decoder does not validate a password or return an enrollment policy.
A durable organization/site-scoped credential store must authorize policy
retrieval. Certificate issuance must recheck the credential, current permissions,
expiry/revocation and CSR binding in its own transaction; a previously parsed
request or successful policy lookup must not authorize later issuance.

Synthetic tests cover the published message shape, namespace variants, nil
markers, credential ambiguity, unsupported authentication, field/body limits,
exact password handling and formatting privacy. The combined local package race
run passes with 97.6% statement coverage; a 30-second policy parser fuzz run
completed 155,226 executions without a failure. The CI
package test includes these cases and has an additional bounded policy fuzz step;
execution evidence is recorded separately from merely editing the workflow.

## Sources

The protocol grammar is based on Microsoft's
[MS-MDE2 specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mde2/4d7eadd5-3951-4f1c-8159-c39e07cbe692),
current PDF version **20260811**, released **August 11, 2026**, sections
3.1.4.1, 3.3.4.1.1.1.3, 4.1 and 4.2.1.3. The downloaded PDF SHA-256 is
`2beb94ede0ad88d1f15df7cd1f9065cfd263acb4d7773d408e7bd07ccece0660`.
Do not confuse this release with the older date shown by cached landing-page
tables. Microsoft's
[on-premises enrollment documentation](https://learn.microsoft.com/en-us/windows/client-management/on-premise-authentication-device-enrollment)
also describes availability probes, fixed-length responses and service hostname
requirements. Its old sample cryptography is not a configuration recommendation.
XML namespace checks follow
[Namespaces in XML 1.0](https://www.w3.org/TR/REC-xml-names/) and
[XML 1.0](https://www.w3.org/TR/xml/).

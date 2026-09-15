# Native Windows MDM implementation

WIN-02 is in progress. The first native protocol component is discovery in
[`internal/mdm/windows`](../internal/mdm/windows). It is separate from the existing
OpenUEM agent. The package currently contains a bounded SOAP/XML decoder, a
discovery response builder, an immutable HTTPS discovery handler, an OnPremise
XCEP request decoder, a PostgreSQL enrollment credential store, protected
organization CAs, an authenticated XCEP policy handler and the [initial WSTEP
issuance/provisioning service](native-windows-enrollment.md), plus [direct TLS
device identity and OMA DM digest verification](native-windows-management.md), and
the [bounded SyncML XML codec](native-windows-syncml.md) and
[durable authenticated sessions with a read-only identity probe](native-windows-sessions.md),
plus [scoped CSP command delivery and results](native-windows-csp.md) and
[typed update policy runs with effective-value verification](native-windows-updates.md),
[versioned rings](native-windows-update-rings.md) and
[scheduled cohorts](native-windows-update-schedules.md). The optional
[listener and gateway integration](native-windows-operations.md) registers the
four device endpoints and schedule worker. The [enrollment/device console](native-windows-console.md)
adds CA setup, one-time invitations, scoped inventory and device access revocation.

Initial certificate issuance and bootstrap provisioning are implemented and
tested synthetically. A real Windows management session and applied CSP are
not yet demonstrated on hardware. Administrative command/result views,
broader typed policies, automatic ring promotion, certificate renewal,
unenrollment, command/update console integration and physical Windows acceptance remain open.
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
- The handler requires a TLS connection. The optional
  [production listener](native-windows-operations.md) supplies bounded headers,
  read/write timeouts, admission limits and pinned gateway identity.

## Automated evidence

Run the parser, TLS and password grammar tests without a database or device.
The PostgreSQL tests explicitly skip when their dedicated variable is unset:

```sh
go test -race -count=1 ./internal/mdm/windows
go test -run '^$' -fuzz=FuzzDiscovery -fuzztime=30s -parallel=2 ./internal/mdm/windows
go test -run '^$' -fuzz=FuzzPolicyRequest -fuzztime=30s -parallel=2 ./internal/mdm/windows
```

Tests use synthetic accounts and local TLS servers. They cover wire namespaces,
version and policy negotiation, endpoint binding, parser/HTTP rejection cases,
exact body limits, complete HTTP/1.1 responses, SOAP faults, read-only probes and
24 concurrent request correlations. Response XML is decoded independently with
Go's standard namespace resolver. These discovery/policy cases do not issue or
install a device certificate, change Windows settings or call an external service.
The subsequent WSTEP tests issue certificates only inside isolated fixtures.

The discovery-only local race baseline passes with 97.0% statement coverage.
An initial 30-second parser
fuzz run completed 1,380,623 executions without a failure; the subsequent final
race run also covers literal whitespace outside the root and bracketed-host
rejections added during review. The existing CI workflow now includes this package on
Linux with race detection and on native Windows, plus a bounded Linux fuzz run.
Both complete workflows now pass for discovery at `79eeac3`
([push](https://github.com/the-luap/openuem-console/actions/runs/34386162922),
[pull request](https://github.com/the-luap/openuem-console/actions/runs/34386167551))
and policy request parsing at `2dd103a`
([push](https://github.com/the-luap/openuem-console/actions/runs/34387097933),
[pull request](https://github.com/the-luap/openuem-console/actions/runs/34387105197)).
These runs include native Windows protocol checks, Linux race/fuzz tests,
the existing PostgreSQL/console/browser regressions and both platform builds.
Both complete workflows also pass for the credential store at `72f2535`
([push](https://github.com/the-luap/openuem-console/actions/runs/34389496218),
[pull request](https://github.com/the-luap/openuem-console/actions/runs/34389505923)).
Physical Windows enrollment has not been tested. The subsequent CA/policy service
change has separate evidence below; earlier CI runs do not cover that change.

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

The decoder does not validate a password or return an enrollment policy.
`Store.CheckPolicyCredential` provides the separate durable credential check
described below. `Store.EnrollmentPolicyResponse` and `NewPolicyHandler` now
perform the credential and CA checks together before returning a policy.
Certificate issuance must recheck the credential, current permissions,
expiry/revocation and CSR binding in its own transaction; a previously parsed
request or successful policy lookup must not authorize later issuance.

Synthetic tests cover the published message shape, namespace variants, nil
markers, credential ambiguity, unsupported authentication, field/body limits,
exact password handling and formatting privacy. The combined local package race
run passes with 97.6% statement coverage; a 30-second policy parser fuzz run
completed 155,226 executions without a failure. The CI
package test includes these cases and has an additional bounded policy fuzz step;
execution evidence is recorded separately from merely editing the workflow.

## Scoped enrollment credentials

`Store.CreateEnrollmentInvitation` creates an invitation for one existing
organization/site pair. It rechecks the authenticated console actor's
`devices.enroll` permission while holding the shared permission lock, locks the
live site/organization relationship and inserts the invitation and audit event
in one transaction. Metadata reads and revocation use the same scoped permission
boundary. Console routes and views for these operations are still to be connected.

Each invitation returns one generated credential with a 256-bit random secret.
Its password has an `owin1` version prefix and a public UUID locator. PostgreSQL
stores an HMAC verifier bound to the invitation ID, organization, site, username,
creator and creator permission revision. The random secret is the HMAC key; the
plaintext password is never stored or included in audit events. These credentials
are independent of console and directory account passwords.

Invitation usernames match exactly and are limited to 320 UTF-8 bytes, consistent
with the discovery account-hint limit. They cannot contain controls or leading/
trailing whitespace. The wider 512-byte XCEP parser bound does not expand this
backend admission limit. Validity is an integral number of seconds from one
minute to 24 hours. Timestamps come from the database clock.

`CheckPolicyCredential` verifies the secret, exact username, current creator
permissions, original permission revision, live site ownership, creation time,
expiry, revocation and consumption. It returns scope only for an active credential
and never consumes it. Any permission revision change invalidates pending
credentials from that creator; removing and later restoring access does not
reactivate them. A new invitation must be issued. Unknown, malformed, mismatched,
expired, revoked and already consumed credentials share one credential error.

The private `withEnrollmentCredential` transaction helper locks an active
invitation for update, holds its permission and site locks through the supplied
issuance work, rechecks database time, records one consumption and audits it.
Its original tests use a synthetic issuance row. The subsequent `EnrollWindows`
service now performs verified CSR processing, scoped certificate issuance and
encrypted provisioning in a transaction using the same authorization/consumption
boundaries. It adds durable, exact retries of the completed result; see
[initial certificate enrollment](native-windows-enrollment.md).

Concurrent consumption admits one callback. Issuer errors, audit errors,
cancellation and expiry during the callback roll back all work and consumption.
Expiry is also checked after waiting for the invitation row lock. PostgreSQL
constraints and a trigger prevent invitation reassignment, lifetime extension,
secret/issuer replacement and rearming after consumption or revocation. Revoking
an invitation closes enrollment access. Later extensions add
[device access revocation](native-windows-console.md),
[certificate renewal](native-windows-renewal.md) and
[authenticated disconnection reports](native-windows-unenrollment.md).
Server-requested unenrollment remains separate lifecycle work.

The additive migration uses its own ledger and advisory lock. Upstream
organization/site/user tables and console access migrations must already exist.
There is no production startup migration registration in this step.

The local PostgreSQL 17 race suite passes in 6.601 seconds, with 93.1% combined
package statement coverage. It verifies restart persistence, scoped denial,
secret/audit privacy, current permission revisions, permanent revocation,
12-way single consumption, live database lock waits, expiry before/after waiting
and during issuance, issuer/audit/cancellation rollback and valid lifetime/name
boundaries. The issuance fixture never signs or installs a certificate.

To run the database suite, set `WINDOWS_MDM_TEST_DATABASE_URL` for the reserved
`openuem_test` PostgreSQL 17 database and role on `127.0.0.1:55440`, then run:

```sh
go test -race -count=1 -timeout=3m ./internal/mdm/windows
```

Each test creates and removes its own random schema. It rejects other endpoints;
GitHub Actions uses its declared disposable PostgreSQL service on port 5432.
The Linux CI step now supplies this variable. The native Windows job runs the
portable protocol tests without PostgreSQL, so it does not prove database
execution on Windows. Physical enrollment, credential UI integration and
public-route admission limits remain open. Initial certificate issuance is now
covered separately in the [WSTEP implementation](native-windows-enrollment.md).

## Protected organization CA and authenticated policy service

`NewStoreWithMasterKey` accepts a canonical base64 encoding of 32 random bytes.
It enables the native Windows CA backend with a separate cryptographic context
from Apple and agent credentials. No environment variable or production startup
configuration is connected implicitly. Losing this key makes the stored CA
unusable; a different key never creates a replacement automatically.

`InitializeAuthority` requires `certificates.manage` over the whole organization
inside the transaction. The organization row serializes concurrent initialization.
Exactly one immutable CA is created per organization, with a separate UUID,
RSA-3072 key and SHA-256 self-signed root. The root has a 1,825-day lifetime,
five minutes of clock skew allowance, CA signing/CRL key usage and no subordinate
CA path. Its subject and key identifiers bind the stored organization and key.
These are OpenUEM choices, not Microsoft enrollment requirements.

The PKCS#8 private key is encrypted with AES-256-GCM, a fresh nonce and a versioned
envelope. A purpose-specific HMAC-SHA-256 derivation separates the encryption key.
Authenticated associated data binds the CA UUID, organization ID/name, exact root
certificate and device key/lifetime/renewal options. Copied, altered or incorrectly
keyed records cannot yield a signer. Public CA metadata and scoped audit events
contain no private key or encrypted-key field. Metadata reads require the same
whole-organization capability and commit their audit before returning data.

Initial device key floors are RSA 2,048, 3,072 or 4,096 bits. Certificate validity
is 1–365 days; the configured renewal period is at least one hour and shorter
than validity. Configuration and initial CA rows reject update/deletion. Root
rotation, master-key rotation, import, backup/restore acceptance and device
certificate renewal are still unfinished lifecycle operations; they must preserve
existing issuer/device bindings rather than replacing this row silently.

`EnrollmentPolicyResponse` holds the current invitation's permission, scope and
row locks while authenticating its organization's CA. It checks the root's
identity, signature, constraints and remaining issuance window, authenticates
the encrypted private key and verifies its public-key match. Only then does it
build and audit a complete XCEP policy. A final database-clock check suppresses
the response and rolls back its event if the invitation expires while waiting.
No policy read consumes the invitation or authorizes a later certificate request.

The response uses policy schema 3, explicit required nil elements, immutable
policy revision 1.0, the configured key/lifetime values and distinct references
for the enrollment object, SHA-256 hash and RSA public key. Their XCEP OID groups
are 9, 1 and 3. The enrollment object uses the CA UUID's unsigned integer under
ITU-T's `2.25` arc. CA collections remain nil for the MDE2 flow; discovery supplies
the enrollment endpoint. No private key, account hint, auto-enrollment permission,
key archival or attestation requirement is advertised. The issuance/provisioning
phase must enforce this policy and supply the certificate chain.

`NewPolicyHandler` binds POST to one configured HTTPS URL, validates HTTP Host,
SOAP destination/action and the bounded UsernameToken request, then calls this
transactional service. GET/HEAD return 405 with `Allow: POST`; discovery owns the
availability probes. SOAP responses and faults use explicit lengths. All invalid,
expired, revoked and consumed credentials receive the same MDE2 authentication
fault. Internal failures use a fixed enrollment-server fault without database,
key, account or request details. The optional
[listener/gateway integration](native-windows-operations.md) now supplies
admission, timeouts and public routing. Console configuration forms remain open.

Synthetic tests cover encrypted-key tampering/context substitution, root/key
validation and issuance windows, scoped CA creation/read, restart, eight concurrent
initializations, immutable SQL constraints, upgrade from the credential schema,
audit rollback, credential expiry while policy audit waits, complete XCEP element
order/namespaces/OID references, bounded HTTP rejection and real loopback HTTPS
policy requests against PostgreSQL. Parallel requests preserve their individual
correlations and produce read audits without consuming an invitation. The CA/policy
baseline generated only test roots and installed no certificates. Its final local
PostgreSQL 17 race suite passed in 11.614 seconds with 91.9% package coverage.
Both complete workflows now pass for CA/policy commit `a1f6353`
([push](https://github.com/the-luap/openuem-console/actions/runs/34393147636),
[pull request](https://github.com/the-luap/openuem-console/actions/runs/34393152518)).
They include native Windows checks, Linux PostgreSQL/race/fuzz tests, the existing
console/browser regressions and both platform builds. The subsequent
[WSTEP implementation](native-windows-enrollment.md) records its own local
issuance/replay/provisioning evidence. The subsequent session and CSP extensions
record their synthetic evidence separately. Physical Windows acceptance remains open.

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

The authenticated response follows Microsoft's
[MS-XCEP schema](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/b34957ab-54c0-4b23-bebc-92ee150cf5ee),
[MDE2 GetPoliciesResponse requirements](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mde2/6e74dcdb-c3d9-4044-af10-536224904e72),
[OID groups](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/161aab9f-d159-4df3-85c9-f732ed2a8445)
and [enrollment fault codes](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mde2/0a78f419-5fd7-4ddb-bc76-1c0f7e11da23).
UUID-derived OIDs follow [ITU-T X.667](https://www.itu.int/en/ITU-T/asn1/Pages/UUID/uuids.aspx).

# Native Windows certificate renewal

Cryptographic verification, persistent issuance/handoff and certificate-authenticated
SOAP renewal are implemented. The registered WSTEP endpoint distinguishes initial
Issue from Renew and requires the actual device TLS certificate for renewal,
directly or through the pinned gateway. Scoped console history, certificate
details and pending cancellation are also implemented. Account/federated renewal
and scheduling remain implementation work. No automatic renewal
setting is enabled. Calling the pure proof verifier does not issue a certificate
or modify a device.

## Protocol requirements

Microsoft describes renewal as a signed request using the existing certificate
and a PKCS#10 request for the requested key. The service must also check the
existing enrollment, renewal period and blocked state. Renewal provisioning
returns the replacement certificate. Microsoft documents ROBO automatic renewal
as requiring client TLS and being supported only with Microsoft PKI; successful
cryptographic tests with this application's organization CA do not establish
Windows ROBO interoperability.
[Windows certificate renewal](https://learn.microsoft.com/en-us/windows/client-management/certificate-renewal-windows-mdm)

For the CMS/PKCS#10 form, MS-WCCE specifies attached `id-data` content and the
existing certificate as the signer. The CSR's `1.3.6.1.4.1.311.13.1` attribute
identifies that same certificate. Its value is the DER certificate itself.
[CMS/PKCS#10 renewal format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/aaece8de-0e59-453e-8697-f39e8295bdac),
[renewal certificate attribute](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/de82f94d-3f25-4963-8173-18d9681ea3e9)

## Verify key continuity

`VerifyWindowsRenewalProof` receives the CMS bytes, the exact existing certificate
DER selected by the caller and the issuer's configured minimum new-key size.
It returns a protected `WindowsRenewalProof` containing the verified CSR and the
existing certificate's SHA-256 fingerprint. Generic JSON/XML/YAML serialization
and formatted logging omit its payload.

The verifier performs these checks before returning a proof:

1. Bound the CMS, certificate and embedded CSR before interpreting them. Constructed
   ASN.1 values have explicit depth and node limits; indefinite lengths and
   nonminimal length encodings are rejected. Interpreted CMS and request-info
   structures must round-trip exactly, rejecting ignored extra fields.
2. Require one attached SignedData signer, one matching SHA-2 digest and the
   supported RSA signature algorithm. Detached data, CMC, SHA-1/MD5, CRLs and
   unsigned attributes do not enter this verification path.
3. Match the signer issuer/serial and embedded certificate against the caller's
   exact DER pin. Extra certificates cannot supply a trust anchor or replace the
   signer. Duplicate or ambiguous certificates are rejected.
4. Verify signed content-type/message-digest attributes when present, require
   unique attribute identifiers, and verify the CMS signature with the old key.
5. Independently verify the CSR signature and configured new-key policy using the
   existing enrollment CSR verifier. The CSR renewal attribute must contain
   exactly the old certificate, without duplicate values, octet wrapping or
   another certificate. Both key reuse and a newly generated key are supported.

| Boundary | Limit |
| --- | --- |
| CMS proof | 64 KiB |
| Existing certificate / embedded CSR | 16 KiB each |
| Constructed ASN.1 depth / nodes | 16 / 2,048 per checked document |
| Embedded certificates | 8 |
| Signers / digest algorithms | Exactly 1 each |
| Signed attributes / CSR attributes | 16 / 32 |
| Existing RSA key | 2,048–4,096 bits; exponent 65,537 |
| New RSA key | Configured 2,048/3,072/4,096-bit minimum through 4,096 bits |
| CMS signature | RSA PKCS#1 v1.5 with SHA-256, SHA-384 or SHA-512 |
| CSR signature | Existing SHA-256 RSA or RSA-PSS policy |

This proof conveys no certificate trust, live authority or scope. It does not
validate dates, revocation, the renewal window, administrative permission or
enrollment membership. A caller must enforce those inside the issuing transaction
and must never derive the device identity from requested subjects, SANs, hardware
hints or embedded certificate chains. The verified CSR preserves those untrusted
fields; the existing certificate issuer assigns names from server-owned scope.

## Verification

Tests use ephemeral RSA keys and an independent PKCS#7 encoder. Positive cases
cover all three supported CMS digests, signed attributes and direct content
signatures, key reuse, a larger replacement key and bounded certificate bags.
Negative cases alter signer identity, certificate pin, bag size, content,
algorithms, signatures and signed/CSR attributes, including a valid old-key
signature around an invalid new-key proof. Resource tests cover depth, node and
length limits. A PostgreSQL fixture verifies a proof against an actually issued
synthetic enrollment certificate while preserving its device, certificate and
encrypted bootstrap records.

The focused PostgreSQL/race tests pass in 2.715 seconds. CI includes the complete
Windows suites plus a bounded proof-fuzz target. Fuzz minimization is limited to
one second per input so its short run can exercise more mutations.

The complete Windows PostgreSQL/race suite passes in **87.008 seconds**; the
protocol package passes in **1.406 seconds**. Proof fuzzing passes **118,432
executions** in **31.414 seconds**. Vet and Linux/Windows builds pass. The
[push workflow](https://github.com/the-luap/openuem-console/actions/runs/34436411706)
and [PR workflow](https://github.com/the-luap/openuem-console/actions/runs/34436413803)
pass for verifier commit `7d4e771`. These verifier checks do not establish
renewal HTTP admission, certificate handoff or Windows client acceptance.

## Persistent issuance and handoff

`Store.RenewWindowsCertificate` receives the actual transport leaf, the CMS proof
and the existing enrollment configuration. It derives the device and exact
organization/site from the stored certificate fingerprint, locks live scope and
the device, and checks current certificate membership, dates, revocation,
configuration and issuer renewal window. The issuing authority must remain the
same. Requested subjects and SANs cannot alter the existing device identity.

One pending replacement is allowed per device. The canonical CSR bytes identify
an intent; changing the SOAP message identifier or signing the same CSR again
reuses the stored certificate, provisioning and request identifier. A different
CSR conflicts while the candidate is pending. Canceled intents cannot be revived.
Retries require the source certificate to remain current, unrevoked and inside
its renewal window. Once the new key confirms receipt, the retired key is denied
for both renewal requests and SyncML, including exact retries and resumed TLS.

Migration `011_certificate_renewal.sql` adds a scoped certificate history and an
append-only audit. The encrypted record contains the accepted proof, minimal
provisioning, configuration and cancellation note. AEAD binds its device, scope,
source/replacement certificates, request/configuration digests, revision, phase
and timestamps. A confirmed record additionally binds the exact stored SyncML
session, message and request digest. History reads authenticate the record and
its proof/certificate/provisioning relationship before returning metadata.

The minimal provisioning document installs the replacement in `My/User` for
`Full` enrollment or `My/System` for `Device` enrollment and identifies the
existing `w7` provider. It does not replace bootstrap credentials, nonces, polling
settings, issuer trust or provider identity.

| State | Transport and lifecycle behavior |
| --- | --- |
| Pending | The original key remains current. The candidate can participate in SyncML authentication, but cannot renew itself. |
| Confirmed | A mutually authenticated SyncML message using the candidate commits its packet, protocol state, confirmation and old-certificate revocation together. Exact packet replay can confirm without advancing nonce/session/command state. |
| Canceled | A current scoped certificate administrator can cancel a pending revision with a protected reason. Only the candidate is revoked; the original key remains current. Confirmed handoffs cannot be canceled. |

The immutable initial enrollment certificate remains the encryption/state anchor.
Its certificate reference, bootstrap ciphertext, nonce identity, session history
and command associations are not rewritten. Each operation separately checks the
actual current TLS certificate. New sessions use that certificate's expiry,
allowing continued management after the original anchor expires. Existing session
deadlines retain their original values. Unknown CSP outcomes continue to block
queued work until the existing explicit resolution workflow completes.

`CertificateRenewals` and `CancelCertificateRenewal` require a current
`certificates.manage` grant in the exact device scope. Reads are bounded and
audited; revoked devices retain history. Generic serialization omits protected
metadata and payloads. Device listings report the original certificate while a
candidate is pending and the replacement's expiry/fingerprint after confirmation.
Issuance, confirmation, cancellation and replay return no successful result when
their audit or final validity checks fail.

Persistence tests cover new-key and same-key issuance, restart/re-signing retries,
eight concurrent requests, active-command handoff, uncertain/queued work,
unauthenticated candidate messages, audit rollback, permission/revocation waits,
scope/configuration/proof rejection, protected history and migration preservation.
A short-lived synthetic anchor exercises two replacement generations and new
sessions after the original certificate expires. An owned loopback TLS server
checks real new-key presentation and denial of the retired key on resumed TLS.
These tests use ephemeral keys and randomly named PostgreSQL schemas; no host
certificate store, device enrollment or physical client is involved.

The complete Windows PostgreSQL/race suite for this persistence extension passes
in **99.851 seconds**, with the protocol package in **1.407 seconds**. Scoped
Windows handler and view regressions pass in **2.094/2.525 seconds**. Vet and
Linux/Windows builds pass. Both the
[push workflow](https://github.com/the-luap/openuem-console/actions/runs/34438407740)
and [PR workflow](https://github.com/the-luap/openuem-console/actions/runs/34438409922)
pass for persistence commit `e68fa65`. The following extension adds SOAP admission; physical Windows acceptance remains
unverified.

## Certificate-authenticated SOAP admission

`ParseWSTEPRenewalRequest` decodes the separate Renew operation at the configured
enrollment URL. The shared SOAP envelope validator checks namespaces, destination,
action, request identifier and required headers before selecting exactly one
operation. Initial Issue keeps its existing UsernameToken/PKCS#10 requirements;
an invalid Renew never falls back to initial enrollment.

Renew requires the device enrollment TokenType and a WS-Security BinarySecurityToken
with `ValueType` equal to the security namespace plus `#PKCS7`. Its canonical
Base64 contains up to 64 KiB of CMS. SOAP remains bounded to 128 KiB. The optional
AdditionalContext uses the existing 64-item/16-KiB aggregate hint validation
without requiring initial-enrollment identity fields. Hints are discarded and
cannot select the device, tenant, site or issuer.

The Security header can be absent or contain an optional Timestamp and an
optional UsernameToken with an empty password, matching Microsoft's published
certificate-authenticated shape. An account name is only a bounded hint. A
nonempty password, federated token, unknown security child, duplicate identifier
or ambiguous field is rejected. This is not corporate account authentication;
initial one-time enrollment credentials do not become reusable renewal passwords.

If supplied, Created and Expires must be UTC RFC 3339 timestamps, ordered within
ten minutes of each other. The store checks them against database time before
issuance/replay and again after audit waits: Expires must remain in the future
and Created permits at most five minutes of clock skew. These unsigned timestamp
fields constrain freshness; they do not establish identity or replace CMS proof.
Resigned/retried requests can supply fresh timestamps without issuing another key.

The HTTP handler resolves the actual TLS/RFC 9440 leaf at the enrollment endpoint
without changing the immutable management URL used for store authorization.
Direct mode ignores certificate headers. Gateway mode requires the configured
gateway TLS pin and its canonical forwarded client certificate. The production
handler supplies the same gateway policy to both WSTEP and SyncML. Responses and
fixed English faults have explicit Content-Length and no-store headers. Faults
omit supplied credentials, certificate bytes and SQL details; only a validated
request identifier can appear as RelatesTo. No redirect, cookie or chunked
response is emitted.

Tests exercise initial HTTP enrollment, CMS renewal, service-instance restart and
exact retry, new-key SyncML confirmation and retired-key denial on resumed TLS.
They run through both a direct loopback TLS listener and the actual gateway with
its separate pinned backend TLS connection. Forged identity headers, mixed
Issue/Renew credentials, wrong destinations and unsupported password requests do
not issue certificates. Separate database tests expire timestamps while issuance
or replay waits on the audit table and verify complete rollback. Parser tests
cover namespace/field ambiguity, UTC intervals, context and CMS bounds, privacy
and disjoint initial/renewal grammars. CI includes a bounded renewal SOAP fuzz
target.

The focused PostgreSQL/race tests pass in **9.579 seconds**. The full Windows
PostgreSQL/race suite passes in **107.712 seconds**, with protocol in **1.430
seconds**. Separate client-identity/gateway regressions pass in **1.333/3.037
seconds**. SOAP parser fuzzing passes **298,640 executions** in **30.813 seconds**.
Vet and Linux/Windows builds pass. Both the
[push workflow](https://github.com/the-luap/openuem-console/actions/runs/34439425052)
and [PR workflow](https://github.com/the-luap/openuem-console/actions/runs/34439427708)
pass for SOAP commit `2a5b139`; synthetic TLS/protocol evidence does not establish
physical Windows acceptance.

## Review and cancel a replacement in the console

Open a native Windows device at a concrete organization/site and select
**Certificate renewals**. This entry and all history, detail and cancellation
routes require `certificates.manage` in the device scope. Device readers and CSP
operators do not inherit certificate authority. An all-sites selection must be
narrowed to a concrete site before opening this history.

History shows ten replacements per page, newest first. Each row identifies its
issuance time, phase and completion time. Open a row to review the previous and
replacement certificate IDs, SHA-256 fingerprints, issuance/expiry times and
recorded revocations. All times are explicitly UTC. The current device access
status is separate from a historical replacement's outcome. A confirmed record
shows the authenticating SyncML session/message and explains that later renewals
may have replaced its certificate again.

For a pending, unrevoked replacement, enter a short single-line cancellation
reason, check **Cancel this replacement certificate**, then select
**Confirm replacement cancellation**. The reviewed revision is submitted with
body CSRF protection. The store rechecks current permission, scope, revision and
phase atomically. A stale form conflicts; it cannot cancel a confirmed handoff.
Successful cancellation redirects to the retained history and removes the form.
The reason is protected in storage and displayed as escaped text. Cancellation
revokes only the pending certificate and preserves the source certificate's
existing access, expiry, protocol sessions and queued commands. It does not
restore access previously revoked for another reason.

`CertificateRenewalDetails` authenticates the sealed record, proof, provisioning,
certificate identity and confirmation evidence under the scoped device locks.
It checks that confirmed source revocation or canceled replacement revocation
matches the sealed completion timestamp, and commits a read audit before returning
metadata. It returns no CSR, CMS proof, provisioning, bootstrap credential or raw
certificate document. Generic formatting and serialization remain protected.

Database tests cover pending/canceled/confirmed details, scoped access, protected
resolution, revoked-device history, failed read-audit rollback and inconsistent
revocation metadata. Full-router tests create a separate synthetic organization
with a supported short-lifetime issuer and eleven genuinely issued renewal
intents. They check role/sibling/foreign-scope boundaries, strict query/form
parsing, CSRF, stale revisions, escaped output and ten-row pagination. After
console cancellation, the original transport identity remains admitted and the
canceled candidate is denied. View tests distinguish later revocation from
historical confirmation and suppress actions for readers and terminal states.

The complete Windows PostgreSQL/race suite passes in **114.820 seconds**, with
protocol tests in **1.427 seconds**. Full console integration plus focused route
boundaries pass under the race detector in **10.772 seconds**; Windows view tests
pass in **3.523 seconds**. Vet and Linux/Windows builds pass. An owned loopback
browser fixture verifies history paging, required confirmation, the actual
CSRF-protected cancellation/redirect and escaped long reasons at 390, 768 and
1440 pixels. The document does not overflow horizontally; the history table has
its own keyboard-focusable scrolling region. The fixture and its isolated schema
are removed after verification. Both complete workflows pass for `04f2b34`
([push](https://github.com/the-luap/openuem-console/actions/runs/34441003508),
[PR](https://github.com/the-luap/openuem-console/actions/runs/34441007033)).

## Remaining lifecycle work

The full renewal path must preserve device identity, pending commands, settings
and history. It requires:

- Configured account-authenticated renewal, including its distinct request
  content encoding and expired-certificate recovery rules, and any required
  additional CMS/CMC compatibility.
- Renewal scheduling configuration and broader expiry reporting.
- Actual supported Windows client/PKI acceptance, including the documented
  Microsoft PKI constraint before enabling automatic ROBO configuration.

The existing enrollment record and bootstrap ciphertext are immutable. An
implementation must not update their certificate reference or erase them to make
a replacement authenticate. The persistent service preserves this requirement;
complete renewal operations and unenrollment remain open in WIN-02.

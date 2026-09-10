# Native Windows certificate renewal

Cryptographic verification and the persistent issuance/handoff service are
implemented. The registered WSTEP endpoint still accepts initial Issue requests
only and rejects Renew; renewal SOAP admission and its operator interface remain
implementation work. No automatic renewal setting is enabled. Calling the pure
proof verifier does not issue a certificate or modify a device.

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
Linux/Windows builds pass. Full CI for this extension is pending. The registered
SOAP renewal endpoint and physical Windows acceptance remain unverified.

## Remaining lifecycle work

The full renewal path must preserve device identity, pending commands, settings
and history. It requires:

- Renewal SOAP parsing and authenticated direct/gateway certificate admission,
  with the automatic and account-authenticated flows handled explicitly.
- Renewal scheduling configuration and an operator interface for protected
  lifecycle history/cancellation and expiry reporting.
- End-to-end renewal SOAP/TLS admission tests and actual supported Windows
  client/PKI acceptance, including the documented Microsoft PKI constraint.

The existing enrollment record and bootstrap ciphertext are immutable. An
implementation must not update their certificate reference or erase them to make
a replacement authenticate. The persistent service preserves this requirement;
registered renewal and unenrollment remain open in WIN-02.

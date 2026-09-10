# Native Windows certificate renewal

The cryptographic verification component is implemented. Certificate replacement,
its persistent handoff and renewal HTTP admission remain implementation work.
The registered WSTEP endpoint still accepts initial Issue requests only and rejects
Renew. No automatic renewal setting is enabled, and verifying a proof does not
issue a certificate or modify a device.

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
executions** in **31.414 seconds**. Vet and Linux/Windows builds pass. Full CI for
this verifier extension is pending. These checks do not establish renewal HTTP
admission, certificate handoff or Windows client acceptance.

## Remaining lifecycle work

The full renewal path must preserve device identity, pending commands, settings
and history. It requires:

- Renewal SOAP parsing and authenticated direct/gateway certificate admission,
  with the automatic and account-authenticated flows handled explicitly.
- Scoped issuance-window and current-certificate checks under transaction locks,
  durable exact retries, immutable issuance/audit records and cancellation rules.
- A certificate handoff that preserves the working identity until replacement
  use is established and prevents repeated issuance or a stale-key rollback.
- Continued SyncML credentials and nonce state across the handoff, including
  active-session, pending-command and uncertain-outcome handling. Current state
  encryption is bound to certificate identity and cannot simply be reassigned.
- Minimal renewal provisioning, scheduling configuration, protected lifecycle
  history and expiry reporting, together with TLS/database/restart/concurrency
  tests and actual supported Windows client/PKI acceptance.

The existing enrollment record and bootstrap ciphertext are immutable. An
implementation must not update their certificate reference or erase them to make
a replacement authenticate. Renewal and unenrollment remain open in WIN-02.

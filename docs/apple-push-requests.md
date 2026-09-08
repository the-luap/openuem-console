# Apple push certificate requests

The Apple setup page supports an administrator-assisted external vendor workflow.
An organization certificate administrator can create a PKCS#10 CSR in the console,
download its public bytes for an authorized vendor, and later import the resulting
PEM certificate without uploading or downloading the private key.

This is partial APP-01 implementation. [Authorized vendor signing](apple-vendor-signing.md)
now supports offline vendor infrastructure, signed-response verification and
complete portal-request download. Automatic signing-service transport, Apple
issuer-chain validation of the final push certificate and a pre-activation APNs
connectivity test are not implemented. Local import checks do not prove that
Apple issued or accepts a certificate. Actual Apple issuance and renewal remain
acceptance requirements. The console explicitly describes the available checks.

## Administrator workflow

1. Open **Apple setup & enrollment** in the intended organization. Confirm its
   name and public HTTPS management origin. Renewal requests use the existing
   origin. Record the responsible Apple account as administrative metadata; never
   enter a password or recovery code.
2. Arrange signing with an authorized MDM vendor, then confirm this arrangement
   and generate a request. Each request has its own key and UUID. Only certificate
   administrators for the entire organization can create, view, download, revoke
   or import requests; a site URL does not narrow the required authority.
3. Download that request's **public CSR for vendor signing** and provide it to the
   authorized vendor. It is a raw PEM PKCS#10 CSR, **not** the completed request
   accepted by Apple's Push Certificates Portal. This fork has no implicit right
   to use another vendor's signing service. Apple describes vendor credential
   access in its [MDM Vendor CSR Signing Certificate documentation](https://developer.apple.com/help/account/certificates/mdm-vendor-csr-signing-certificate/).
4. Obtain the signed response from that vendor. Upload it to the same request in
   OpenUEM for verification against its public CSR and the operator-approved vendor
   certificate. Download the verified portal request. Open the Apple Push
   Certificates Portal using the console link, which opens a new tab. For renewal,
   use the responsible account and renew the existing portal entry. Creating a
   different entry changes the topic and cannot replace an existing enrollment.
5. Upload the certificate Apple returns to the **same request** in OpenUEM. Upload
   certificates only, in PEM format, up to 64 KiB and eight certificates. No key
   upload is needed. Import checks the selected stored key, current validity and
   an MDM topic; renewal must preserve the existing topic. A successful local
   import immediately replaces active push credentials. Because a connectivity
   test is still absent, this workflow does not satisfy the full APP-01 activation
   gate and must not be described as a fully verified Apple setup wizard.

The existing certificate/private-key pair import remains in a separate expandable
section. Both import paths preserve the enrollment CA. Successful replacement
through either path supersedes all other pending requests for that organization.
The setup page warns certificate administrators when the active certificate
expires within 30 days or has already expired. Notifications outside this page
are not implemented.

## Storage and concurrency

Migration `006_push_requests.sql` adds request records and a monotonic revision
for active push settings. A request snapshots that revision and, for renewals,
the topic. Creation and replacement use the same organization advisory lock.
Import also locks the exact request row and compares the revision. Two competing
requests cannot both replace the same generation. A stale request is not selected
by creation time, and a certificate cannot fall back to another request's key.

The instance generates a fresh RSA-2048 key and SHA-256 PKCS#10 signature for each
request. AES-GCM storage binds the key ciphertext to organization, request UUID
and field using the existing instance secret box. The key is never placed in the
CSR, download response, view model or audit details. The Apple account is not
included in the CSR or settings JSON. Setup summaries no longer decrypt either
the push key or enrollment CA key.

There can be at most five unexpired pending requests per organization. A request
expires after seven days. Expired, revoked, consumed and superseded requests are
unusable; terminal records have no encrypted key value. When the Apple listener
and worker are enabled, the maintenance loop clears expired keys in batches of up to 100 and audits expiry. Expiry is
checked by the database during access and again before import commits, even if
maintenance has not yet run. Revocation affects the pending request and leaves
the active certificate intact. Administrators can also revoke expired pending
requests to remove their keys while the background worker is disabled. Removing a
database value does not erase earlier backups, WAL or replicas; their retention remains an operator responsibility.

Active credentials, request consumption, invalidation of competing keys and audit
events commit together. A failed validation, scope mismatch, stale generation,
expired request or audit failure leaves active credentials unchanged. Events
record actor, organization and request ID, not CSR contents, account metadata or
keys. The UI shows at most 25 recent requests. New request routes return fixed
errors instead of displaying underlying database or cryptographic errors.

## Verification and remaining acceptance

PostgreSQL race tests cover public CSR signature verification, encrypted-key
association, cross-organization isolation, wrong-request certificates, expired
certificates and requests, topic changes, revocation, pending limits, concurrent
renewals, legacy import invalidation, CA preservation and rollback after a failed
final audit insert. Console integration uses the actual router, Ent schema,
permissions, CSRF middleware, public CSR download and certificate-only multipart
upload. The certificate issuers in these tests are synthetic local fixtures.
The rendered setup fixture was also checked in headless Chrome at 390, 768 and
1440 pixels in light and dark mode. All six views had no horizontal overflow;
the required confirmation checkbox blocked submission until selected. This is
rendering and browser-form evidence, not a live Apple portal or issuance test.

Remaining APP-01 work includes deployment-specific vendor permission and
operational ownership; automatic signing-service transport; trusted Apple
certificate-chain checks for the final push certificate and a meaningful APNs
connection test before activation; full guided error recovery and renewal reminders; and actual Apple
issuance/renewal with enrolled-device continuity. The full roadmap stays open.

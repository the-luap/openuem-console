# Certificate-account email confirmation

An administrator creates a certificate account and sends its confirmation link
from the configured console origin. Opening the link displays the recipient
address and a **Confirm email address** button. GET requests do not change the
account, including repeated visits by a link scanner.

The button submits a POST with the browser's CSRF token. The server accepts one
URL-encoded form field, rejects query parameters and bounds the form to 8 KiB.
Missing, duplicate or incorrect CSRF values and foreign browser origins fail.
Other HTTP methods cannot perform confirmation. Preview, success and error
responses use `Cache-Control: no-store` and `Referrer-Policy: no-referrer`.

Confirmation tokens require the generated HS512 signature, OpenUEM issuer,
email-confirmation subject, issue time and an expiry within 24 hours. Their
signed binding covers the account ID, exact recipient address and stored account
creation time. A changed address or newly created account with the same ID cannot
use the earlier link to preview or confirm its details. **Older links without this
binding require a new confirmation email from an administrator.**

Only an unverified certificate account awaiting email confirmation can proceed.
The transaction checks the account, recipient and creation time again before
marking the address verified and the certificate request ready for processing.
Password/OpenID accounts, revoked or already approved accounts, and repeated
confirmation are rejected. A request that expires while waiting for a database
lock rolls back; it does not leave a delayed autocommit update behind.

Resending currently leaves earlier matching links usable until expiry or
successful confirmation. An address change followed by restoration of the
original address is not yet a permanent revocation event. Durable issued-token
replacement and revocation history remain outstanding.

Automated evidence covers the registered HTTP routes and CSRF middleware,
recipient/account replacement, PostgreSQL row-lock commit/rollback/deadline and
address-change races, and isolated Chrome rendering and keyboard activation at
390, 768 and 1440 px. The tests use owned fixtures and do not establish real email
delivery or certificate issuance to a physical administrator workstation.

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
use the earlier link to preview or confirm its details. The exact issued token is
stored in the account's invitation field, encrypted when a master key is
configured. Both preview and confirmation require this current token. **Older
links without the binding or stored invitation require a new confirmation email
from an administrator.**

Only an unverified certificate account awaiting email confirmation can proceed.
The transaction checks the account, recipient, creation time and stored token
again before marking the address verified, consuming the invitation and making
the certificate request ready for processing.
Password/OpenID accounts, revoked or already approved accounts, and repeated
confirmation are rejected. A request that expires while waiting for a database
lock rolls back; it does not leave a delayed autocommit update behind.

Each resend has a random nonce, so even invitations generated in the same second
differ. Issuance replaces the stored token before publishing the notification;
the earlier link immediately becomes invalid. Competing issuance and confirmation
use the same guarded transaction. Loading and storing the confirmation invitation
share a five-second request deadline. A broker publication failure can leave the
new invitation stored without delivery; an administrator must resend it.

Session-schema migration 4 installs a PostgreSQL trigger that clears invitations
when the account ID, creation time, email, password hash, authentication mode,
email-verification state or registration status changes. It covers ordinary
database writes from other components as well as console actions. Restoring these
account fields does not restore a cleared invitation. Name, phone and modification
time changes preserve it, as do migration and repeated startup. This protection
does not cover privileged reinsertion of old credential data or schema tampering.
Startup fails if the installed revocation trigger is missing or disabled.

The invitation field is also used for initial-password links. Those links require
their separate HS512/OpenUEM **New password** purpose, issue time and expiry within
one hour, preventing an email-confirmation proof from entering password setup.

Automated evidence covers the registered HTTP routes and CSRF middleware,
recipient/account replacement, plaintext/encrypted invitation replacement,
account-field restoration, migration health, PostgreSQL row-lock
commit/rollback/deadline, address-change and resend races, and isolated Chrome
rendering and keyboard activation at
390, 768 and 1440 px. The tests use owned fixtures and do not establish real email
delivery or certificate issuance to a physical administrator workstation.

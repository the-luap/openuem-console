# Apple push certificate expiry reminders

The console now sends persistent email reminders for each organization's active
Apple MDM push certificate. They run independently of NATS and the public Apple
listener, after Apple and access-control migrations have completed. At least one
console process with a working Apple store must remain running. No additional
worker, environment flag or signing credential is needed.

## Timing and recipients

Warning stages begin at 30, 14, 7 and 1 day before expiry, plus an expired stage.
A day means 24 hours. The actual public leaf certificate supplies both expiry and
its SHA-256 identity; older installations do not need a historical APNs check
record. Reminder processing never decrypts Apple private keys. After downtime,
only the currently most urgent stage is created. Earlier pending stages are
cancelled, rather than delivered as a backlog.

Each eligible OpenUEM user receives at most one committed successful delivery per
organization, certificate fingerprint and stage. Eligibility requires:

- A global `administrator` grant, or `organization_admin` for this organization,
  with no site restriction, matching the `ManageCertificates` capability.
- An existing account whose `email_verified` flag is true and registration state
  is `users.completed` or `users.approved`.
- A valid bare email address in the current user record.

The responsible Apple account field is never used as a recipient. Operators,
viewers, administrators for other organizations, revoked accounts and unverified
accounts are excluded. Newly eligible administrators are added while the stage
remains active. Reinstating a previously cancelled recipient permits another
attempt; an already successful delivery is not repeated. A subsequent address
change alone does not resend a successful stage.

The console reconciles immediately on startup and normally every minute. Each
cycle visits all configured organizations and then processes up to 100 due
deliveries. Slow SMTP servers or lock contention can lengthen the interval.
Failed sends retry after 5, 10, 20, 40, 80, 160, 320 and 640 minutes, then every
24 hours until success, supersession or loss of recipient eligibility. A restart
retains the schedule. Correcting SMTP settings does not discard the existing
backoff; the next due attempt reads the corrected configuration.

## SMTP configuration

Configure the organization's SMTP settings in the console. The sender uses that
organization's settings row, even when it is incomplete; it falls back to global
settings only if no organization row exists. Ambiguous global settings fail
closed. Reading configuration never creates or clones settings. Saving SMTP
settings now also persists the selected authentication mechanism.

The sender supports the existing LOGIN, PLAIN, XOAUTH2 and SCRAM-SHA-256 choices.
Empty username and password select anonymous delivery; a stored `NOAUTH` value
also does so. Authentication requires TLS. STARTTLS is mandatory when selected,
and SMTPS establishes TLS before the SMTP greeting. Both preserve the configured
port, require TLS 1.2 or newer and verify the server hostname and chain against
the operating system trust store. There is no skip-verification option. Explicit
`none` permits anonymous plaintext relay but never transmits authentication
credentials. XOAUTH2 uses the configured token; automatic token refresh is not
part of this sender.

Existing hex-encoded AES-GCM SMTP passwords are decrypted into a local value.
Well-formed encrypted values with a bad authentication tag or wrong master key
are rejected. The legacy storage format has no version marker: non-hex and short
values remain compatible as plaintext, while long plaintext values consisting
entirely of hexadecimal characters are treated as encrypted and must be saved
again through the settings form. No settings object is decrypted in place.

One SMTP connection has a ten-second deadline covering dialing, TLS, greeting,
authentication and DATA acceptance. Cancellation closes its underlying socket.
Authentication challenges are limited to eight exchanges and 8 KiB each; SCRAM
iterations are limited to 100,000. Higher-cost configurations require changing
the server policy rather than holding console permission locks indefinitely.
Messages have both plain-text and escaped HTML bodies, with no remote images,
tracking assets, private keys, responsible Apple account or enrollment links.

## Persistence, authorization and delivery semantics

Migration `009_push_expiry_reminders.sql` adds reminder and recipient-delivery
tables. A reminder is unique by organization, leaf fingerprint and stage; its
delivery row is unique by user. Recipient addresses and SMTP credentials are not
stored in these tables. Delivery records survive user removal for history and
are rechecked against the current user table before any send.

All console replicas may run the job. Reconciliation and sending acquire the
same organization advisory lock used for certificate replacement. Sending then
takes the access store's global advisory lock, locks the delivery row and takes
a shared lock on the current recipient user row. The current certificate, stage,
account and grants are checked again before contacting SMTP. Supported renewal,
permission and user-update operations therefore serialize with delivery: an
already completed revocation or renewal prevents a stale send; a change that
waits behind a send commits after that send finishes. Delivery transactions have
a fifteen-second context including lock waits. Shutdown cancels and joins the
worker instead of abandoning a socket or holding these locks.

The final successful SMTP DATA response records acceptance, then delivery state
and an `apple.push_expiry.smtp_accepted` audit event commit together. Creating a
stage records `apple.push_expiry.create`. The audit resource is the reminder or
delivery UUID, with no message body or SMTP response. Fixed failure codes are
`smtp_unavailable` and `smtp_failed`; cancellation reasons are
`recipient_unavailable` and `superseded`.

SMTP acceptance does not prove inbox delivery. SMTP and PostgreSQL do not share
a transaction: a crash or database/audit failure after SMTP acceptance can cause
a duplicate retry. The stable Message-ID, derived from the delivery UUID, is
preserved across attempts, but receiving servers need not deduplicate it. A lost
DATA acknowledgement has the same ambiguity. Failures after confirmed DATA
acceptance do not depend on a subsequent QUIT exchange.

Renewal stops stale delivery immediately through the final certificate check;
the next reconciliation marks older history resolved and cancels its remaining
pending deliveries. History is retained in the database, with the latest 25
stages shown under **Apple setup → Certificate expiry reminders** only to
certificate administrators. It shows SMTP acceptance, pending/cancelled counts,
failed attempts awaiting retry and the earliest scheduled retry. No eligible
recipient and missing SMTP configuration remain visible rather than being
silently reported as success. A future common audit-retention policy may also
cover these records; this change does not delete them automatically.

## Verification and remaining scope

Automated tests use disposable PostgreSQL schemas and loopback SMTP peers only:

- Threshold boundaries, downgrade-free backlog selection, persistent retries,
  current-address lookup, new administrators and legacy public certificates.
- Permission/account changes, invalid addresses, user removal, certificate
  renewal, cross-organization history and forbidden console readers.
- Concurrent replicas, access-lock serialization, an audit failure after SMTP
  acceptance and stable Message-ID reuse, cancellation and restart recovery.
- Actual anonymous, STARTTLS and SMTPS exchanges, LOGIN/PLAIN/XOAUTH2/SCRAM,
  MIME/envelope headers, DATA rejection, bad server trust/hostname, missing
  STARTTLS, excessive SCRAM cost and stalled SMTP cancellation.
- Organization/global configuration precedence, saved authentication selection,
  and startup/shutdown while the Apple public listener is disabled.
- Expanded reminder history in headless Chrome at 390, 768 and 1440 pixels in
  light and dark mode, with no horizontal overflow in all six views.

This implements push-certificate reminders, not automatic certificate renewal or
Apple issuance. Real deployment SMTP/inbox delivery, Apple vendor operations,
independent certificate revocation checks and enrolled-device continuity remain
acceptance work. PKI-01 also still includes device-certificate renewal,
CA/master-key rotation and encrypted backup/restore. The complete expanded
roadmap remains open.

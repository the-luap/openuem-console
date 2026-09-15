# SMTP settings, secrets and test delivery

Current server administrators can manage global SMTP settings at `/admin/smtp`
and organization settings at `/tenant/{id}/admin/smtp`. Organization and site
administrators do not inherit this capability. The store rechecks and holds the
current permission grant and exact organization/settings row during each
operation. It never creates settings or falls back to another scope while
rendering or saving an editor.

The account notification worker reads a fresh, bounded global snapshot before
each message. Certificate expiry reminders in the console use organization
settings, falling back to global settings only when no organization row exists.
An incomplete organization configuration does not fall back. A worker restart or
broker reload message is no longer required for an SMTP edit to take effect.
Other general settings and their existing clone/reset flows are separate from
this editor; the SMTP revision trigger also detects changes made by those flows.

## Editing and secret storage

The editor returns only connection metadata and a password-presence boolean. It
never reads a stored password into a review. Every save has an explicit action:

- **Keep** requires an empty password input and leaves the stored column unread
  and unchanged.
- **Replace** requires a new, nonempty literal value and encrypts it before the
  database write. A ciphertext-looking input is still a literal replacement.
- **Clear** requires an empty input and stores an empty password.

The configured raw master key remains compatible with the historical AES-GCM
hex format. Console, account worker and console reminder delivery use the shared,
immutable `github.com/open-uem/nats/legacysecret` reader. It bounds plaintext to
16 KiB and storage to 32,824 bytes, checks UTF-8 and rejects NUL. Short legacy hex
strings remain plaintext. Hex strings large enough to contain a nonce and GCM
tag must authenticate; corrupt ciphertext, an incorrect key and ambiguous long
hex plaintext fail closed. This compatibility format does not authenticate the
settings ID or scope and does not implement key rotation.

Metadata has explicit bounds, and the sender must be a bare email address. SMTP
servers must be hostnames or IP addresses, with a port between 1 and 65,535. Saves
require the reviewed settings ID and UUID revision. A database trigger advances
the revision when SMTP values or ownership change, including writes outside the
editor. Concurrent edits cannot overwrite an intervening SMTP change. Unrelated
settings changes do not invalidate the SMTP review. A partial unique index
prevents concurrent creation of multiple global settings rows.

Read and update audit events contain actor, scope, settings ID, action and
outcome. They contain no connection configuration, credentials or provider
errors. A save and its audit event commit together. A broker failure cannot turn
a committed save into an apparent failure. Native forms redirect after success;
HTMX receives a successful redirect instruction. Sensitive responses use
`Cache-Control: no-store`, and browser history snapshots are disabled.

## Test delivery and uncertainty

The separate test form requires an unchecked, explicit confirmation. It sends
one fixed message to the **saved sender address**, using only saved settings.
Unsaved fields and passwords are not accepted in a test request. Tests require
current server administration, the exact scope, settings ID, revision and a UUID
attempt ID. CSRF validation and request bounds apply before form processing:
64 KiB for edits and 8 KiB for tests, including URL encoding.

Before contacting SMTP, an independent transaction commits the attempt and its
audit event. The operation holds the current source and authorization while
sending. Concurrent requests with the same attempt ID share one outcome. A lost
HTTP response, canceled operation, terminal audit failure or process restart
cannot make that attempt send again. One new attempt per settings row per minute
is allowed. The SQL pool must allow at least two connections; saturated pools
can fail an operation before sending.

Successful SMTP submission means **server acceptance**, not inbox delivery. An
attempt whose result cannot be committed or whose delivery reports an error is
shown as unconfirmed. The page shows the current administrator's latest attempt
and warns when settings have changed since that attempt. Provider error text is
not returned. Retries of the same attempt return its recorded outcome; the
console never automatically retries a test.

The editor offers required STARTTLS and TLS from connection start, both with
certificate verification and TLS 1.2 or newer. Custom ports are preserved. The
account worker and test sender treat legacy `none` as required STARTTLS, matching
the account worker's historical default. Console reminders retain their existing
unauthenticated legacy `none` behavior until the configuration is explicitly
changed. No authenticated plaintext connection is enabled by the editor.

A cancelable socket lifecycle bounds the complete account/test SMTP operation,
including greeting, STARTTLS, authentication, message data and QUIT. The test
send limit is 15 seconds inside a 20-second operation; account notification
processing is limited to 30 seconds. Reminder delivery retains its independently
bounded transport. Worker configuration/delivery logs use neutral messages.

## Migration, retention and deployment

Deploy the matching worker before the console so that fresh snapshots and the
shared reader are available. Keep the same master key in both services. This
release does not provide automatic worker version negotiation.

After access/audit migrations and before starting console HTTP, startup adds the
SMTP schema protections and migrates nonempty secrets in transactions of at most
64 rows. Plaintext encryption and maintenance audit events commit together in
the row's actual scope. Existing ciphertext is authenticated and preserved;
NULL/empty values remain unchanged. Completed batches survive a later failure
and are safe to process again. Representation changes advance the SMTP revision.
Startup shares the existing 30-second initialization deadline; a large migration
may need another restart to finish its remaining batches.

Duplicate legacy global rows, missing schema guards, an unreadable secret or an
audit failure stop console startup. Secret errors identify only the settings ID.
Restore the correct original key or repair the identified configuration from a
trusted backup through restricted database maintenance before restarting. The
editor cannot repair data while startup is blocked. Oversized legacy connection
metadata is rejected rather than silently truncated and also requires repair
before it can be edited. Do not reinterpret unauthenticated long hex as plaintext.

The shared audit viewer/export includes the `settings` source. Global and
organization retention policies prune their own old SMTP audit events after
preview and confirmation. `uem_smtp_test_attempts` is separate permanent attempt
evidence, with no settings/account foreign key: audit retention or deletion of
an account/settings row cannot erase a send's deduplication record.

Owned PostgreSQL tests cover scope, live roles, stale/concurrent edits, schema
guards, bounded migration, restart, audit rollback, hidden secrets, concurrent
replay and retention. Registered console routes cover CSRF, malformed/oversized
forms, native and HTMX responses and saved-only delivery. Browser fixtures cover
14 states at three widths plus pending controls. Owned TLS SMTP peers exercise
authentication without mutating ciphertext, custom STARTTLS ports and cancellation
through all SMTP phases. No production mailbox or physical-device delivery is
claimed. Account notification queue reliability, broader provider/user secret
migration, master-key rotation/recovery and production delivery acceptance remain
separate work.

## Verification record

The completed change passes the full inventory and audit PostgreSQL race suites
(109.005 and 10.707 seconds), the owned console reminder suite (2.126 seconds),
registered Apple/OIDC console routes, all affected view suites, and the focused
SMTP model suite. All 48 focused SMTP browser cases and all 2,055 cases in the
full browser matrix pass. The affected Linux common/router/webserver/handler and
task-execution race suites and full console Linux build pass. Worker model/common
PostgreSQL suites pass (2.696/3.544 seconds), as do notification/command race
suites (3.601/1.024 seconds) and full Linux/Windows builds.

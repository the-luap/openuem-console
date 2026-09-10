# Native Windows certificate expiry reminders

The configured native Windows service runs persistent certificate reminders
alongside its update scheduler. **Certificate health → Expiry reminder history**
shows delivery history for certificate administrators. This does not configure
client renewal, enable ROBO or perform a device operation.

## Deadlines and recipients

Reminders cover three independent deadlines:

- Expiry of each active device's original or latest confirmed certificate.
- Expiry of the organization CA certificate.
- The earlier end of full-lifetime issuance: CA expiry minus the configured
  device certificate lifetime and a five-minute margin.

Each deadline has stages at 30, 14, 7 and 1 day before the deadline and at the
deadline itself. Comparisons are inclusive and use database time. Reconciliation
creates only the current stage, rather than replaying every missed stage after
downtime. A valid pending replacement does not hide the current certificate's
expiry; the email states that its confirmation is still pending. A confirmed
replacement, retired device access, revoked current certificate or moved site
prevents stale delivery. Reconciliation cancels superseded pending work even when
it is waiting in SMTP backoff. Prior accepted and canceled history remains.

Recipients must have a current global administrator or matching organization
administrator grant, a verified email address and an approved or completed
registration. Operators, viewers, foreign administrators, unverified accounts and
invalid addresses are excluded. Recipients are selected from console accounts,
not enrollment usernames or device-reported names. Newly eligible administrators
are added to an existing stage. An eligibility cancellation can resume when the
account becomes eligible again; invalid addresses are not repeatedly requeued.
Accepted stages are not resent merely because an email address changes.

## Delivery and persistence

Migration 015 adds immutable reminder identities authenticated through encrypted
envelopes, protected per-user delivery state and append-only audit events. A reminder is
unique by kind, certificate/authority resource and stage. A delivery is unique by
reminder and user. Stored delivery state binds its identity, user, phase,
revision, attempts and timing to the encrypted envelope. The outbox retains user IDs without copying their current email addresses,
message bodies, reported device names or SMTP credentials.
Generic serialization and formatted output omit protected message/history data.

The worker runs immediately and then normally every minute. It scans source IDs
in bounded keyset pages, with an upper bound captured for each source kind, then
processes up to 100 due deliveries. Slow or large deployments can lengthen a
cycle. A rotating due cursor prevents a corrupt first batch from permanently
starving later deliveries. Each source or delivery transaction has a 15-second
context; cancellation interrupts the worker and its SMTP socket. Native Windows
shutdown joins both the scheduler and reminder worker.

Source reconciliation and delivery serialize by source advisory lock. The shared
permission lock remains held through delivery. Live site ownership, device
access, current confirmed generation, issuer policy, certificate fingerprint,
deadline, stage, recipient eligibility and current email address are rechecked.
Device/scope and recipient locks prevent supported concurrent confirmation,
retirement, permission and account changes from invalidating the send decision.
Database time is checked again after recipient lock waits, immediately before
SMTP. Internal assessment verifies renewal proof without creating a new console
read audit on every poll; reminder creation and delivery events audit the actual
notification lifecycle. Console history reads remain separately audited.

The shared SMTP sender uses the organization's configured settings, with global
fallback only when no organization settings row exists. It retains its existing
TLS validation, authenticated-password handling and ten-second connection
deadline. See [SMTP configuration](apple-push-expiry-reminders.md#smtp-configuration).
Emails contain plain text and escaped HTML, a concrete organization/device
reference, the certificate fingerprint and assessment/deadline times. They have
no tracking assets, private keys, enrollment passwords or provisioning content.

Missing/invalid configuration records `smtp_unavailable`; other delivery errors
record `smtp_failed`. Errors never persist raw SMTP responses. Retries wait 5,
10, 20, 40, 80, 160, 320 and 640 minutes, then 24 hours. Restart preserves this
schedule. Each retry resolves the current address and configuration. Successful
SMTP DATA acceptance commits with its audit event and suppresses further sends
for that delivery. SMTP and PostgreSQL cannot commit atomically: a lost DATA
response, crash or database/audit failure after acceptance can cause a duplicate
retry. The stable delivery-derived Message-ID is retained, but inbox delivery
and receiver deduplication are not guaranteed.

## Console and verification

`GET /windows/certificate-reminders` has default, organization and concrete-site
route variants. It requires current `devices.read` and `certificates.manage`
permission. A site view includes that site's device events and its organization's
CA events. Moved device histories are excluded from both organizations rather
than transferred. Pages contain 25 events, with SMTP-accepted, pending,
retrying and canceled delivery counts, next retry, missing-configuration and
no-eligible-recipient states. No recipient addresses are exposed. Every stored
identity and included delivery envelope is authenticated before returning history;
failed final audit returns no result. The gateway keeps these routes private.

Synthetic tests cover deadline boundaries, separate CA deadlines, persistence,
current-address lookup, eligibility loss/resumption, concurrent replicas,
confirmation/retirement/site changes, migration preservation, corrupted outboxes,
fair processing after a corrupt batch, audit rollback and ambiguous SMTP retries.
Observed database lock waits exercise permission removal and a deadline crossed
while waiting for the recipient row. Local SMTP peers verify actual MIME/envelope
delivery, stable Message-ID, DATA acceptance and cancellation of a stalled socket.
Worker lifecycle tests cover concurrent startup and joined shutdown. Router tests
exercise all scope variants, roles, bounded queries, cache headers and retry
history without contacting external SMTP.

The complete Windows PostgreSQL/race suite passes in **161.199 seconds**, with
the protocol package also passing. Final console/handler checks pass in
**16.646 seconds**, views in **4.434 seconds**, runtime/SMTP integration in
**1.962 seconds** and gateway checks in **1.948 seconds**. Vet and Linux/Windows
builds pass. Full CI for this extension is pending.

Browser checks cover mixed, empty and actual synthetic retry history at 390, 768
and 1440 pixels. All nine views remain contained; keyboard expansion, paging links
and concrete device links work. Physical Windows renewal continuity, production
SMTP/inbox acceptance, automatic renewal configuration, CA/master-key rotation
and the remaining PKI-01/WIN-02 requirements stay open.

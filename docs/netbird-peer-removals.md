# Reviewed removal of an associated NetBird peer

Open a managed registration receipt or its retained provider association and
select **Review provider peer removal**. Removal requires a previously confirmed
[provider peer association](netbird-peer-bindings.md). The page shows the original
provider, exact peer ID, registration event, retained creation time and a fresh
peer observation. An unchecked confirmation authorizes one removal attempt.

Removing a provider peer can interrupt its network access. It sends no device
command, uninstalls no software and erases no local credentials. The retained
association identifies the peer registered with this request's setup key; it
does not establish the endpoint's current local WireGuard identity. Peer absence
does not change the original registration outcome or release its command barrier.

## Current authority and exact identity

Review, removal and an external absence check require current
`ManageDeviceSecurity` authority for the recorded scope and current actual device
membership, platform, installation generation, enrollment mode, certificate and
consumer identity. These source rows and the original request are locked against
concurrent changes. Renewed valid identity requires a fresh review. Revocation,
expiry, disabled consumers, device removal and scope changes prevent new provider
access. Requests using individual enrollment are also bounded by current
certificate expiry.

The original authenticated encrypted snapshot supplies the provider origin and
token. Current provider settings cannot replace either. Before a DELETE, an
exact-ID GET must match the retained peer ID, creation time, user identity and
non-ephemeral policy. A renamed peer can be removed after a fresh review; its name
is display metadata, never identity evidence. A changed creation identity,
unavailable provider or missing association prevents deletion. No name or IP
lookup is used, and the account event feed need not retain the older event.

The review fingerprint includes the original registration and command digest,
immutable association, current target generation, latest attempt, absence
evidence and current provider metadata. Submission repeats the observation and
rejects stale fingerprints. Forms cannot choose a provider, peer ID or credential.
Strict scalar validation, exact-site route capabilities, CSRF, explicit
confirmation and no-store responses apply to the registered routes.

## Permanent attempts and independent absence

Migration `022_netbird_peer_removals.sql` adds two permanent records without
device foreign keys or cascades:

- Each removal attempt stores its form UUID, original registration, exact
  association ID and fingerprint, peer ID, actor, fresh review, sequence and
  recording time. The attempt and audit commit independently **before** one
  fixed-ID DELETE, so later request rollback cannot erase permission already used.
- Separate absence evidence records the exact associated peer and actor after a
  successful exact-ID GET returns 404. It commits with its audit independently
  before the outer request can finish. DELETE success alone is insufficient.

The [shared client](https://github.com/the-luap/openuem-nats/blob/34aa75035f14d95fc4da0eb5f78e06a7726a3aed/netbirdapi/client.go) uses
HTTPS, bounded five-second requests, bounded responses and no redirects or
application retries. A failed or lost DELETE response may still follow removal;
a fresh exact-ID read distinguishes positive absence from an unknown outcome.

Replaying a form returns retained state under its original actor and fingerprint
without another provider call, including after restart. Concurrent confirmations
serialize on the registration. A different form based on the same old review is
stale after the first attempt. Another DELETE requires a new review and separately
confirmed UUID; earlier attempts remain intact. Startup verifies enabled guard
functions, and database guards prohibit mutation or deletion of attempts and
absence evidence, mismatched association identities and attempts after absence.

**Check peer removal** only reads the exact peer. It can retain later absence
after a lost reply, an interrupted request, an audit failure or external removal.
It never repeats DELETE. If the peer remains present, another removal attempt
requires fresh confirmation. If the provider is unavailable or contradicts the
association, evidence remains unconfirmed. Stored absence is historical evidence;
viewing it performs no new provider read. Recorded-scope readers can inspect the
original receipt and retained attempt/absence after device removal.

## Verification and remaining work

Owned TLS/PostgreSQL fixtures verify attempt and audit visibility before DELETE,
lost request/response and follow-up read, independently committed evidence after
final audit rollback, restart/form replay, concurrent forms, explicit retries,
external removal, unchanged command barriers, provider settings replacement,
current authority and target identity, certificate deadlines and database/startup
guards. The focused inventory race suite passes in 18.459 seconds. View race tests
pass in 1.964 seconds. All 36 new browser cases pass at 390, 768 and 1,440 pixels,
including long content, confirmation, read-only checks, reader permissions and
duplicate submissions while requests are pending. The complete 2,442-case
browser matrix and actual registered console route fixtures pass.
The complete inventory PostgreSQL race suite passes in 273.509 seconds and the
audit race suite in 9.138 seconds. The full Linux arm64 console build passes.

This flow applies to retained managed registration associations. Missing
key-creation responses, unassociated legacy peers, trusted installers, remaining
credential lifecycle and real provider/native/physical acceptance remain separate
work. Verification uses owned fixtures, with no installed NetBird executable,
real provider account or physical endpoint.

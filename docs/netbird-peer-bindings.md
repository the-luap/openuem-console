# Retained NetBird provider peer associations

A completed or unconfirmed managed registration can retain the provider peer
created with its exact setup key. Open its receipt and select **Review provider
peer association**. The review requires current `ManageDeviceSecurity` authority,
the original key identity, a retained delivery attempt and positive key-removal
evidence. Association requires a separate, unchecked confirmation. It sends no
agent command and makes no provider mutation.

## Evidence and limits

The NetBird provider emits `peer.setupkey.add` with the setup-key ID as
`initiator_id` and the new peer ID as `target_id`. These assignments were inspected
at upstream revision
[`791401060d2b95e5f51e3439c0649729132f571e`](https://github.com/netbirdio/netbird/blob/791401060d2b95e5f51e3439c0649729132f571e/management/server/peer.go#L710).
The [event endpoint](https://docs.netbird.io/api/resources/events) exposes that
evidence. The shared reader selects exactly one matching event within the
registration's time window and independently reads that exact peer through the
[peer endpoint](https://docs.netbird.io/api/resources/peers).

Both reads use the registration's original authenticated, encrypted provider
snapshot. Changed current settings cannot substitute another account or token.
The peer must have the event's exact ID, an empty user ID, a non-ephemeral policy
and a creation time between registration admission (with five minutes of clock
tolerance) and key expiry, no later than the event. Event time is bounded by key
expiry plus five minutes and the current time plus five minutes. Names and IP
addresses are never used to infer identity. The stored name is display metadata
at association time.

The upstream [event store](https://github.com/netbirdio/netbird/blob/791401060d2b95e5f51e3439c0649729132f571e/management/server/event.go)
can be disabled, saves events asynchronously and returns at most 10,000 recent
events. A missing event therefore cannot prove that registration never happened.
Missing, ambiguous, malformed, unavailable or contradictory evidence cannot be
associated. An exact peer GET returning 404 reports absence for that read; it
does not retrospectively disprove registration. Provider errors expose neither
response bodies nor credentials.

The association establishes that this provider peer was registered with the key
issued for this request. It does **not** establish the endpoint's current local
WireGuard identity, successful command completion, lasting connectivity or current
group membership. Ordinary peer API metadata does not expose the local WireGuard
public key. The original registration outcome and any command admission barrier
remain unchanged. Setup-key removal does not disconnect an existing peer.

## Authority, review and persistence

Review and submission lock the recorded request and current permission state.
Before provider reads, a new association also verifies the actual device scope,
platform, installation generation, enrollment mode and current certificate and
consumer identity. Renewed valid identity can be used; moved, removed, disabled,
revoked or expired targets cannot establish a new association.

The review fingerprint binds the original request, command digest, key and absence
evidence, current target generation, captured provider URL and exact event and
peer projections. Submission repeats the reads and rejects stale evidence,
including changed display metadata. Provider inputs cannot be supplied through
the form. Strict scalar fields, route authorization and CSRF checks apply.

Migration `021_netbird_peer_bindings.sql` stores one immutable association per
registration with a separate form UUID, actor, review fingerprint, provider URL,
event ID, setup-key ID, peer ID, relevant timestamps and bounded peer metadata.
Insert guards enforce retained registration prerequisites and the restricted
evidence shape; startup rejects missing or disabled guards. Update and deletion
are forbidden. No device foreign key can cascade into this history.

Association and its audit event commit atomically. Concurrent forms can create
only one record. Replaying the same form under the same actor and fingerprint
returns retained evidence without another provider read. Recorded-scope readers
can inspect the receipt after device removal; management links require management
authority. Stored reviews do not re-query current provider state.

## Verification and remaining lifecycle

Owned TLS, PostgreSQL and NATS fixtures cover original credentials after settings
changes, exact IDs and timestamps, multiple or missing events, user/ephemeral
peers, provider absence and failures, current authority and identity changes,
freshness, concurrent forms, audit rollback, SQL guards and permanent history.
The registered console routes exercise real authorization, CSRF, strict fields,
confirmation, replay and stored receipts. Views and 39 new browser cases cover
all review states, reader permissions, pending forms and long content at 390,
768 and 1,440 pixels. All 2,406 browser cases pass. The complete inventory
PostgreSQL race suite passes in 250.578 seconds, the audit race suite in 9.334
seconds and view race tests in 1.931 seconds.

The shared reader has independent race tests for bounded responses, strict JSON,
duplicate fields and IDs, exact request paths, rejected redirects and time
windows. Console, agent and worker use immutable shared revision
`34aa75035f14d95fc4da0eb5f78e06a7726a3aed`.
Agent command/journal race tests pass on macOS; complete worker model/common race
tests pass with owned PostgreSQL on Linux. Full builds pass for the Linux console,
Linux/macOS/Windows agent and Linux/Windows worker.

[Reviewed peer removal](netbird-peer-removals.md) now provides separate durable
attempts and positive absence recovery for retained associations. Missing
key-creation responses, trusted installers,
remaining credential lifecycle work and real provider/native/physical acceptance
remain separate work. These tests use owned fixtures; no installed NetBird
executable, real provider account or physical endpoint is exercised.

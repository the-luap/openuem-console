# NetBird settings and provider request boundaries

Current server administrators can manage NetBird configuration at
`/tenant/{id}/admin/netbird`. Each review and save holds the current permission
grant and exact organization. Global/site URLs and inherited organization/site
administration do not authorize this editor. GET never creates configuration or
contacts NetBird. Inventory, SFTP and remote-assistance navigation read only a
token-presence boolean, without loading provider credentials.

## Explicit editing

Reviews expose the management URL, configuration identity, revision and token
presence. Stored tokens never appear in HTML or browser history snapshots.
Sensitive responses use `Cache-Control: no-store`. Saving requires the reviewed
identity/revision and an explicit choice:

- **Keep** requires an empty new-token field and preserves the original token
  inside SQL, without reading or decrypting it in the application.
- **Replace** encrypts a nonempty literal token before writing. A value that looks
  like ciphertext is still treated as the newly supplied literal value.
- **Clear** stores an empty token, stopping new provider requests. Existing peers
  and device connections are not removed.

Only an explicit save creates missing configuration. Changing the management URL
while keeping a token uses that token with the new URL. The page states this
before submission. URLs must use HTTPS and may include a path prefix. Credentials,
query strings, fragments and traversal segments are rejected. Tokens are bounded
to 16 KiB and cannot contain invalid UTF-8, NUL or header line breaks. Forms are
strict, single-valued URL-encoded requests with a 64 KiB encoded limit; CSRF and
request bounds apply before form processing. Native submission redirects after a
save; HTMX receives a successful redirect instruction.

Two database triggers version the provider configuration and the organization's
reference independently. A review hashes both versions. Repointing an
organization away and back cannot revive an old review. Direct legacy writes to
provider fields also invalidate reviews; unrelated edits do not. Concurrent
saves cannot overwrite an intervening change.

Some legacy rows are shared by several organizations. The page identifies this
condition, and saving copies the settings for only the selected organization.
Keeping the token copies ciphertext entirely inside SQL. Other organizations keep
their original row and values. A save holds an update lock on the provider row,
including against new foreign-key attachments, before deciding whether to copy.
It never deletes the original row: the legacy foreign key can cascade deletion
from provider settings to organizations.

Read/update audit events use the shared `settings` source. They contain actor,
organization, settings identities, action and result, without URLs, tokens or
provider responses. The save, optional copy, organization link and audit event
commit together. Audit failure rolls back all of them. Organization retention
covers its own NetBird settings events; orphan migration events use global scope.

## Secret migration and deployment

Console startup installs the revision guards and migrates NetBird tokens after
the access/audit migrations and before starting console HTTP. The shared
`github.com/open-uem/nats/legacysecret` reader supports historical AES-GCM hex
ciphertext and short/plain legacy tokens. Plausible encrypted hex must authenticate
with the correct raw master key. Corrupt ciphertext, incorrect or missing keys
and ambiguous long hex plaintext fail closed. This format preserves compatibility;
it does not authenticate the provider URL or settings ID and is not key rotation.

Migration locks at most 64 nonempty token rows per transaction. Each plaintext
replacement commits with audit events for every currently linked organization;
orphans produce a global maintenance event. Existing ciphertext is authenticated
and preserved. NULL and empty values remain unchanged. A later failure leaves
previous completed batches committed and safe to revisit after restart. Migration
errors identify only a settings ID. The existing 30-second startup deadline also
bounds this work, so large migrations may need another restart to finish.

Use matching console/worker master keys and compatible workers. Configure HTTPS
for self-hosted management before upgrading a deployment that still uses HTTP.
Install its CA in the services' trust stores when necessary. Stop old console
writers during the coordinated console upgrade: older editors can expose tokens
or introduce plaintext again. There is no automatic component-version handshake.
Unreadable tokens or missing revision protection stop startup; restore the
original key or repair the identified row from a trusted backup through restricted
database maintenance. Oversized legacy URLs cannot be edited until repaired.

## Shared provider requests

The later [managed operation migration](netbird-operations.md) disables legacy
registration/key creation and peer deletion routes, and workers no longer
generate active NetBird profile steps. The mutation client contracts below
describe retained implementation and owned tests, not enabled user workflows.
Console group lookups remain available. Staged admission and authoritative peer
ownership are required before re-enabling provider mutations.

Console group lookups, registration-key creation/cleanup and peer deletion, plus
worker registration tasks, use `github.com/open-uem/nats/netbirdapi`. It verifies
HTTPS certificates, requires TLS 1.2 or newer with its default transport, refuses
redirects, encodes query values, checks success status codes and bounds each
request to five seconds and each response to one MiB. Invalid responses and
provider error bodies become a neutral error. Group/peer lists have a 1,000-item
limit. Credential snapshots are bounded and do not mutate stored ciphertext.

Peer deletion requires exactly one provider result whose address matches the
requested IP. Two matches are an error. Names are checked when testing for an
existing peer, and returned IDs cannot inject URL paths. These requests use the
published [peer API](https://docs.netbird.io/api/resources/peers).
This matching check does not prove ownership: agent-reported IP addresses are
mutable metadata, and shared provider accounts can contain another organization's
peer. These legacy matching helpers are not sufficient for scoped deletion.
Managed registration now offers a separate
[retained peer association](netbird-peer-bindings.md) using the exact setup-key
event and peer creation metadata. Its bounded event reader allows at most 10,000
events within the same one-MiB response limit; a missing event never proves
non-registration. Reviewed deletion of an associated peer remains separate work.

Setup-key creation uses structured JSON for a one-off key, a one-day lifetime and
usage limit one, following the published
[setup-key API](https://docs.netbird.io/api/resources/setup-keys). Both numeric and
string IDs are supported; revoked, masked or reusable responses are rejected.
Changing POST bodies cannot be replayed by the transport after an ambiguous reused
connection failure, and the client has no application retry. Cleanup after console
registration has a separate five-second deadline. Worker generation has a
30-second overall bound and preserves its input task order.

A timeout or invalid response can still follow a remote mutation. Durable NetBird
command admission/recovery, current source/authority held throughout legacy device
operations and immutable provider outcome history remain separate work. Earlier
setup-key side effects are not rolled back when a later worker task fails. These
changes do not claim exactly-once registration or complete NetBird lifecycle
security. Production provider and physical-device acceptance are also outstanding.

## Verification

Owned PostgreSQL tests cover hidden/explicit secrets, missing configuration,
current roles, concurrent/stale saves, ownership ABA, shared-row copies, audit
rollback, bounded/restartable migration, shared/orphan audit scope, NULL values and
bounded navigation/credential projections. Actual registered console routes cover
CSRF, malformed/oversized forms, native and HTMX responses and save/render without
provider calls. Six browser states at three widths plus pending controls exercise
21 cases, including missing/shared configuration and long URLs; mobile views were
inspected. Owned TLS provider tests cover protocol encoding, identity ambiguity,
fixed key policy, redirects, status/response limits and canceled unretried creation.
The worker also tests full registration plus following tasks without modifying
stored ciphertext. No real provider account or device was used.

The full inventory and audit PostgreSQL race suites pass in 112.862 and 10.510
seconds. All affected view suites and the existing owned group-reader tests pass.
Registered Apple/OIDC console routes pass, as do affected Linux common/router,
webserver/handler and task-execution race suites and the full Linux console build.
All 21 focused and 2,076 total browser cases pass; the full matrix takes 104.879
seconds. Worker model/common PostgreSQL race suites pass in 2.763/3.924 seconds,
and full worker Linux/Windows builds pass. The shared API/legacy-secret/task-secret
and SMTP-transport race suites also pass.

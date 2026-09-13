# Profile-bound task form lookups

Task type, subtype and definition lookups now use the destination profile's
scoped `/tasks/:profile/new/:stage` URL. Each read holds current server
administrator authority and the exact profile audience through an
`inventory.tasks.wizard_read` audit commit. A profile that has moved, disappeared
or gained an ambiguous audience cannot be used through a stale form. The lookup
does not select existing task definitions, scripts or task credentials.

Only the `types`, `subtypes` and `definition` stages and implemented form choices
are accepted. GET queries are limited to 512 wire bytes and exactly one expected
selector value. Duplicate, unknown or unrelated fields, request bodies and
alternate content encodings are rejected. Generated selectors retain the scoped
profile URL across replacements. Script categories still target the definition
region directly. Lookup responses use `Cache-Control: no-store`.

The three old global `/profiles/task-*` endpoints return 410 with an English
instruction to reopen the task form. They no longer render definitions or call a
provider. Existing edit selectors remain disabled; editing itself remains a
separate authorization boundary.

## NetBird groups

A registration definition requires an organization destination and uses that
organization's current settings. The read holds both the tenant/settings
association and referenced settings row until the provider read and audit commit
finish. Missing settings return an error without creating a settings row. Rotation,
profile changes and authority revocation cannot race the in-flight read.

The new read-only NetBird client accepts a configured HTTPS management URL and
requests its `/api/groups` endpoint. It rejects URL credentials, queries and
fragments, follows no redirects, limits the request to five seconds and reads at
most 1 MiB. It accepts a JSON array of at most 1,000 groups, with distinct nonempty
IDs of at most 128 UTF-8 bytes, bounded names and nonnegative peer counts. Invalid,
oversized, redirected and unsuccessful responses return a generic error; provider
response bodies and tokens are never exposed in the form or error message.

Stored encrypted tokens are decrypted only inside the authorized operation.
Legacy encryption has no format marker: long hexadecimal values are treated as
possible ciphertext and rejected if they cannot be decrypted, including when the
key is missing or wrong. Short hexadecimal plaintext tokens are handled without
calling the legacy helper that can panic on a short decoded nonce. A versioned
secret format and wider legacy token migration remain separate work.

The complete operation has a ten-second deadline. Returned groups become
available to the handler only after the scoped audit commit; a failed provider
read, audit or cancellation publishes no groups. Audit resources contain only the
profile ID and stage, without provider configuration, credentials or group names.
Holding database locks during bounded provider reads is deliberate; production
contention still needs measurement.

## Verification

PostgreSQL/race tests cover all scopes, current roles, wrong audiences, supported
stages, audit browsing/export, missing settings without writes, encrypted tokens,
missing/wrong keys, short hexadecimal tokens, provider failures, audit failure and
cancellation. A two-phase test pauses first inside the provider lookup and then
inside the audit insert. Provider rotation, tenant settings reassignment, profile
changes and grant revocation remain blocked in both phases. Groups are returned
only after commit, and a subsequently revoked actor cannot call the provider.

The actual registered Apple/OIDC routes use an owned HTTPS provider fixture to
verify exact paths and token headers, escaped group labels, hidden credentials,
all scopes and roles, strict queries, preserved scoped selector URLs, direct
script targeting, no-store headers and retired global endpoints. Denied and
wrong-scope requests make no provider call. NetBird client tests use owned HTTPS
fixtures for success, malformed/oversized responses, duplicates, status errors,
redirect refusal, URL restrictions and cancellation.

The 45 task-form browser cases now verify that all three lookup stages retain the
destination scope and omit unrelated form values at 390, 768 and 1440 pixels.

The full inventory PostgreSQL/race suite passes in 85.060 seconds and the full
audit suite in 14.887 seconds. Registered Apple/OIDC routes, affected macOS/Linux
race checks and the full Linux build pass. The final complete 1,647-case Chrome
matrix passes in 92.814 seconds. The provider tests contact only owned fixtures.

Task editing, package search and other legacy provider/settings routes, the wider
secret lifecycle, immutable revisions, delegated access and physical/provider
acceptance remain open in the expanded roadmap.

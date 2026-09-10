# Native Windows CSP evidence export

The [CSP console](native-windows-csp-console.md) now provides an audited JSON
attachment for one command, including its original intent, current result and
all stored observations. Each historical observation can also be downloaded
individually. The export reads stored evidence; it does not send a command or
contact a Windows device.

## Download and interpret evidence

Open **Windows CSP commands**, select a command and use **Download command
evidence (JSON)**. From **Observation history**, open a message and use
**Download this observation (JSON)** for a smaller, explicitly selected record.
Both native POST forms include the current command revision and the console's
CSRF token. If the command changes while the page is open, refresh the page and
review its new state before downloading. Downloads preserve exact organization,
site and device scope.

Files contain plaintext configuration intent and complete device result values,
which can include passwords or other protected CSP content. Keep downloaded files
in an access-controlled location. Partial Get objects remain withheld.

The JSON object uses `schema: "openuem.windows.csp-evidence"` and
`schema_version: 1`. Its fields are deliberately separate from private storage
and SyncML transport structures:

| Field | Meaning |
| --- | --- |
| `audit_id`, `exported_at` | Committed Windows CSP audit record and its database UTC timestamp |
| `command` | Command/device IDs, organization/site, request ID, creator and permission revision, current command revision/phase, lifecycle timestamps and optional owning update/disconnection references |
| `request` | Original operation tree: operation ID, kind, target, format/MIME, data and ordered children |
| `current_result` | Latest stored reason, administrative resolution and operation evidence at the exported revision |
| `observations` | Immutable cumulative snapshots in ascending device message order; selected-message downloads contain exactly one |
| `observation_count` | Number of snapshots actually included |
| `history_complete` | True only for a command download containing all stored snapshots; false for an individual selection |
| `selected_message` | Present only for an individual observation download |

An observation's `outcome` and values describe that historical message, even when
`command.phase` and `current_result` describe a later outcome. An empty historical
outcome means evidence was incomplete at that point. Administrative resolution
does not rewrite historical snapshots. An empty observation array means no stored
observations; it does not prove that the device had no effects.

Operations use `status: null` for no received status. `incomplete: true` always
has `data: null`; absent results also use `data: null`. A complete empty text
result is `{"representation":"text","value":""}`. XML is stored as an ordinary
JSON string with `representation: "xml"`. The reported format/MIME remains
separate, including base64 values. Whitespace, Unicode, tree ordering, parent
relationships and original device diagnostics are preserved. JSON escapes HTML
characters; consumers must continue treating values as untrusted data.

Acknowledgment is protocol evidence, not proof of effective configuration,
current compliance, successful updates or local disconnection cleanup. This is
an evidence download format, not a desired-state import or a public management
API. It excludes enrollment credentials, session secrets/nonces, private keys,
raw packet bodies, request salts, digests and encrypted storage envelopes.

## Authorization, integrity and resource bounds

The two private console actions are:

- `POST /windows/:id/commands/:command/export`
- `POST /windows/:id/commands/:command/observations/:message/export`

Both also exist under `/tenant/:tenant` and `/tenant/:tenant/site/:site`. They
require `windows.csp.manage`, a concrete current site and an exact canonical
`expected_revision`. Only `csrf` and `expected_revision` body fields are accepted;
query parameters, repeated fields and noncanonical message/revision values fail.
These actions remain unavailable through the public device gateway boundary.

The store locks current permissions, organization/site ownership, the device and
command while authenticating the request, latest result and every included
observation. Historical snapshots reuse the same packet-digest, timestamp,
request/dispatch and operation-tree verification as protected console reads.
Only the untouched initial queued revision may lack an encrypted result;
subsequent lifecycle metadata without its bound result proof is rejected by all
shared result readers and before dispatch. Dispatch keeps the stored timestamp
until proof and eligibility checks finish, so repeated blocking retains its
existing authenticated revision and eligible resumption still works. Current grants and revisions are reread after lock waits.
Device access retirement preserves administrator-authorized history; changing
site ownership cannot transfer historical scope to another organization.

Preparation admits one export per PostgreSQL database across replicas using a
nonblocking advisory lock. An occupied slot returns HTTP 429 with `Retry-After: 5`.
The existing console request deadline is 30 seconds. A command has at most 64
session message numbers; observations are decoded one at a time into a buffer
capped at 32 MiB. HTTP 422 recommends individual observations if the complete
history exceeds this bound. The preparation lock does not cover later network
transmission. There is no silent truncation or partial response on failure.

Migration 016 adds `command.exported` and `command.observation_exported` audit
actions without rewriting enrollments or stored protocol state. Each completed
export records its actor, exact command/device/scope, action kind and timestamp;
the JSON `audit_id` references that event. The audit action distinguishes whole
history from selected-observation downloads, but does not store the exported
payload or selected message number. All encoding and integrity checks finish
before the transaction commits and attachment bytes become available. Errors,
cancellation, capacity rejection and audit failure release no attachment and
roll back the attempted export audit. The event proves preparation, not that a
browser finished saving a file. An explicitly confirmed [Windows audit retention
policy](native-windows-audit.md) can later remove that original audit event; its
source ID remains in the permanent deletion batch. This does not change the
exported file or protected command/observation evidence.

Responses use JSON with attachment disposition, a fixed UUID/revision-based
filename, `no-store`, `nosniff`, a restrictive sandbox content policy, exact byte
length and an `X-Content-SHA256` checksum of the file. The checksum detects byte
changes; it is not an independent signature or a trust anchor. Normal DTO
serialization and formatted diagnostics remain redacted, and the handler clears
its byte buffer after writing.

## Verification and remaining work

Synthetic PostgreSQL/race tests cover complete and selected exports, partial
versus complete values, restart, replay, revoked devices, role/scope rejection,
audit rollback, corruption of every observation binding, current-result integrity,
missing lifecycle proof, cancellation, output limits, concurrency admission and
permission/revision changes during observed lock waits. Route tests exercise real
forms, current administrator roles, CSRF, strict request grammar, attachment
headers/checksum and fixed error responses. Portable encoding tests preserve
Unicode, whitespace, XML, empty values and nested operation relationships.

The complete Windows PostgreSQL/race suite passes in **166.014 seconds**, with
the protocol package passing in **1.377 seconds**. The focused PostgreSQL/race
regression checks pass in **12.166 seconds**.
The final console route and Windows handler checks pass in **15.303 seconds**,
Windows views in **4.429 seconds**, and private gateway route checks in **1.847 seconds**.
Vet and complete Linux/Windows builds pass. The full PR workflow for `d3bec86`
passes. Its push workflow exposed a timing-sensitive test size comparison: a new
export timestamp can have fewer fractional digits than the previous timestamp.
The transactional overflow test now accounts for variable audit metadata; exact
buffer boundary checks remain. Twenty PostgreSQL/race repetitions pass in 12.077
seconds. The next complete CI run remains pending. The opt-in live console fixture
passes its complete handler/race run in **162.499 seconds**, including browser
inspection. All tests use the isolated PostgreSQL service on loopback port 55440.

Browser checks exercise the production forms with real cookie/Origin CSRF. A
keyboard Enter submits each whole-command, partial-observation and complete-
observation download. Their files contain twelve, one and one snapshots,
respectively, with distinct committed audit IDs and no partial value exposure.
All three pages remain contained at 390/768/1440 pixels; the mobile download view
passes visual inspection. The final page reports no console warnings or errors.
The fixture's initial navigation reports only its missing favicon. Its owned
listener and database schema are cleaned up after the test.

Command/observation/packet retention, bulk cross-command exports, broader typed
policies and physical Windows acceptance remain separate work. Shared Windows
audit retention now has its own explicit organization opt-in; CSP evidence exports
themselves do not delete history.

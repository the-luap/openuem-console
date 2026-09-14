# Independent current NetBird absence verification

The shared [version-six verification protocol](https://github.com/the-luap/openuem-nats/blob/517b4fe927dc134a0aea3f9ac1c005d3b6c4f028/docs/netbird-removal-absence.md)
and [agent native/journal integration](https://github.com/the-luap/openuem-agent/blob/acc9fa2039384e232bf510f874a982040b69bff1/docs/netbird-removal-current-absence.md)
now support a separate current-state observation after an original unconfirmed
uninstall has been explicitly released. The original receipt remains unchanged.

`verify-removal-absence` binds a new UUID, current individual identity, console
review, ready-journal revision and current native fingerprint. Its original
reference contains only the uninstall UUID, command hash, revision and owned
release UUID. It carries no fabricated native descriptor or manifest. The fixed
profile is `macos-official-pkg-v1`. Native verification is read-only; it cannot
remove a retained empty/incomplete stage or a replacement package.

The agent requires the same original released proof and current journal before
and after acquisition. It persists a separate attempt before verification, joins
the acquired owner before recording its result, and serves exact replay without
another native query. Concurrent native commands share the journal barrier.
Completed means only that this new verification confirmed current absence of the
supported layout; it does not turn the original uncertain removal into success.

## Console transport

`PublishNetbirdRemovalAbsence` accepts only the new independent command version
and sends one direct request outside the retrying command stream. It enforces
the command deadline and requires an exact correlated receipt, preserving every
completed/unconfirmed/busy/rejected/withdrawn outcome. Expired, legacy or reused
original UUIDs fail before transport. Existing connection, installation,
removal and manifest-continuation publishers cannot carry the new operation.

The existing `RequestNetbirdControl` transports strict version-five
`removal-absence-state` reviews and rejects changed original references,
release IDs, journal revisions, current certificates, hashes and old-version
responses. Inspection is separate from execution evidence.

## Console admission and durable evidence

`NetbirdRemovalAbsenceStore` implements the complete separate request, delivery,
observation, resolution and history lifecycle. It reconstructs the exact original
version-four command and verifies its owned, retained **unconfirmed** release
proof before requesting current inspection. Withdrawn, completed, missing,
corrupted or foreign original evidence cannot authorize a check. No current
native removal descriptor is fabricated from historical package metadata.

Review and admission require current `software.assign` authority for the exact
organization, site and individual macOS device. The current identity, certificate
expiry, broker, reconciled consumer, report binding generation and native/journal
fingerprint all contribute to the console revision. Permission and identity locks
survive until admission commits. The descriptor's journal revision remains
separate from the console revision.

Requests expire within two minutes, bounded by the current certificate. Reusing
an exact admitted UUID reads its immutable intent; changing the actor, scope,
original reference or reviewed values conflicts. A fresh request is rechecked at
admission and again before dispatch. Cancellation is possible only before the
permanent delivery attempt. The original uninstall's result and release remain
unchanged throughout this lifecycle.

Migration `037_netbird_removal_absences.sql` extends device exclusion and the
permanent request UUID namespace across all six connection, registration,
installation, removal, manifest-continuation and absence families. Direct SQL
admission has the same cross-family guards. Expiry and preflight failure retain
the device barrier until explicit cancellation. Completed, cancelled and resolved
requests retain their UUID permanently. Original release IDs cannot become new
verification or resolution IDs.

The store commits the exact version-six command hash, current certificate,
command times and audit before its sole direct delivery. The delivery deadline
is at most two minutes. Committed pending or uncertain attempts survive restart
and are never automatically resent. The first result remains immutable; a later
matching receipt can separately establish completion. Historical reads reconstruct
stored evidence without current identity queries or agent/native calls.

Missing delivery evidence offers a reviewed permanent withdrawal only when the
current journal permits it. An exact unconfirmed journal entry may instead allow
explicit release after execution has ended. Each control needs a fresh retained
two-minute review; replaying a consumed review reads its existing result. Lost
control replies can be reconciled through exact owned receipt evidence. Neither
release nor withdrawal claims current absence or changes the original uninstall.
Current authority is required for all evidence requests and resolution controls.

Startup validates the request, attempt, result, observation, resolution, proof
and dispatch guards. It constructs the dedicated store and publisher, runs four
bounded dispatcher workers and cancels and joins every worker on shutdown.

## Scoped console workflow

An eligible original uninstall receipt exposes **Review current package absence**
to software operators. The review describes the read-only check and requires an
unchecked confirmation. Its form carries only original ID, new request ID,
absence digest, console revision, confirmation and CSRF token. The receipt shows
queued, stopped, pending, uncertain, completed, cancelled and resolved states.
**Current package absence verified** refers only to the new check at its recorded
time. Later device changes require another independently reviewed check.

All routes use `/tenant/:tenant/site/:site/computers/:uuid/netbird/removal-absences`:

| Method | Suffix | Permission | Purpose |
| --- | --- | --- | --- |
| GET | empty | `software.read` | Retained scoped history, 20 requests per page |
| GET | `/review?original_id=…` | `software.assign` | Fresh current absence review |
| POST | empty | `software.assign` | Queue the exact reviewed independent request |
| GET | `/:request` | `software.read` | Coherent retained receipt |
| POST | `/:request/cancel` | `software.assign` | Cancel before the permanent attempt |
| POST | `/:request/observe` | `software.assign` | Query the retained receipt |
| GET | `/:request/resolution` | `software.assign` | Review eligible withdrawal or release |
| POST | `/:request/resolution` | `software.assign` | Commit one explicitly reviewed control |
| POST | `/:request/resolution/reconcile` | `software.assign` | Retain exact owned resolution evidence |

Native forms return scoped 303 redirects; HTMX forms return 204 with their scoped
location. All mutations use the production CSRF checks and an 8 KiB raw body limit
before form parsing. Duplicate, unknown and mixed query/body fields are refused.
Reader pages expose no mutations. History and receipt pages are `no-store`, escape
retained metadata and omit certificates, broker keys and executable envelopes.

Empty or incomplete stages remain preserved by this read-only workflow.
[Independent scaffold cleanup](netbird-removal-stage-cleanup.md) has its own
reviewed native owner, agent admission and complete separate console lifecycle.
Manifest continuation cannot silently fall back to verification or stage
cleanup. Linux individual enrollment, publisher trust and physical-device
acceptance remain separate roadmap requirements.

## Verification

The initial integration pinned runtime module `v0.11.1-0.20260914151935-517b4fe927dc`. Shared
command/package race tests pass; verification decoder fuzzing passed 341,756
inputs. Full agent native package/journal/command races, isolated Linux
journal/command suites and macOS/Linux/Windows agent builds pass. Owned NATS
publisher tests pass with one direct delivery, no stream message, all retained
outcomes, no reply, cancellation, expiry and cross-operation rejection. Existing
publisher tests also pass under the race detector. Linux console and worker
builds pass. These fixtures do not constitute physical-device acceptance.


The complete console inventory selection passed under the race detector against
owned PostgreSQL: all 235 `TestNetbird…` tests in 758.785 seconds, including 39
absence lifecycle tests, plus the scoped NetBird task-default regression in
2.568 seconds. Coverage includes immutable original proof, renewed identities,
cross-family SQL and concurrent admission, one delivery, late/lost replies,
expiry, audit rollback, owned release and withdrawal, restart, retained history
and startup guard checks. The registered HTTP lifecycle suite passed in 23.42
seconds, including the independent absence forms, raw CSRF limits and original
outcome preservation.

All console view and CSRF middleware race tests passed. The complete browser
matrix passed 2,790 cases, including 75 absence cases at 390, 768 and 1440 pixels.
Narrow review and released-receipt screenshots were inspected. Runtime startup
binds and reuses both continuation and absence stores and joins all workers;
shutdown cancellation/join also passed with the race detector. Linux console,
handler-test and runtime-test builds passed. These checks use owned inert fixtures
and do not perform a host or vendor NetBird operation.

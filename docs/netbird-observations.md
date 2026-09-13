# NetBird observation and profile storage

The agent now bounds and validates NetBird CLI observations on Linux, macOS and
Windows. It retains one execution identity and deadline through a connection
command and the subsequent status read. A failed read is explicitly unconfirmed,
and only a missing executable establishes an absent installation. Current console
and worker writers reject failed observations before upsert, preserving the last
confirmed data. Their database writes have a ten-second deadline.
Implementation details are recorded in the
[agent observation contract](https://github.com/the-luap/openuem-agent/blob/42e488b/docs/netbird-observations.md)
and [worker persistence contract](https://github.com/the-luap/openuem-worker/blob/13b21ab/docs/netbird-observations.md).

Profile IDs and display labels are separate. Reports preserve optional structured
profile details alongside the existing handle list. Both writers use the shared
`netbirdstate` versioned JSON codec in the existing text column, retaining commas,
spaces and duplicate display names with distinct IDs. Existing comma-separated
rows remain readable; old ambiguous comma-containing names cannot be reconstructed
until replaced by a new observation. Invalid identities cannot replace prior data.

The console uses a labeled native selector. Labels include the ID when available,
while submission sends the exact handle. Duplicate names remain distinguishable;
agent-supplied text is escaped. Missing or malformed profile metadata disables the
selector and instructs the operator to refresh. This selector still submits to the
legacy scoped device route; it does not provide durable command admission.

Owned console/worker PostgreSQL tests prove round-trip identity, comma preservation
and retention of prior state after failed or ambiguous reports. Agent parser and
owned process tests cover bounded output, cancellation and invalid state. All 18
new browser cases and the full 2,094-case matrix pass, including three viewport
widths, keyboard submission, exact handles, duplicate labels and markup injection.
Affected builds and race suites are recorded in the implementation status.

Agent-reported profile/peer metadata is not proof of provider ownership. Legacy
console refresh fallback can still display previously saved data without permanent
observation-age/failure history. Durable requests, current authority/source locks,
immutable attempts/outcomes, explicit uncertainty resolution, authoritative
provider-peer association and physical acceptance remain required. See
[NetBird settings](netbird-settings.md) for credential/provider boundaries.

# Independent current removal absence: protocol and transport

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

The caller must durably store scoped intent and its exact attempt before calling
the publisher. No dispatcher, public route or form invokes it yet. The remaining
console work is the complete request/delivery/observation/resolution/history/UI
lifecycle with common device and permanent UUID exclusion. It must retain
original unconfirmed proof, current scoped software authority, an expiring
independent review and a separate current-state result. Manifest continuation
must not silently fall back to verification or stage cleanup.

## Verification

All consumers pin runtime module `v0.11.1-0.20260914151935-517b4fe927dc`. Shared
command/package race tests pass; verification decoder fuzzing passed 341,756
inputs. Full agent native package/journal/command races, isolated Linux
journal/command suites and macOS/Linux/Windows agent builds pass. Owned NATS
publisher tests pass with one direct delivery, no stream message, all retained
outcomes, no reply, cancellation, expiry and cross-operation rejection. Existing
publisher tests also pass under the race detector. Linux console and worker
builds pass. These fixtures do not constitute physical-device acceptance.

# Manifest-backed NetBird removal recovery integration

The [shared version-five command and version-four inspection](https://github.com/the-luap/openuem-nats/blob/ffb798edf585da5bef34537096c46556b56eda50/docs/netbird-removal-recovery.md)
and [agent journal/native service integration](https://github.com/the-luap/openuem-agent/blob/c2eb88abec01ff90d205c3f4bc04a49f302be8d2/docs/netbird-removal-staging-recovery.md)
now provide an explicit continuation of an interrupted macOS removal with a
valid protected original manifest. Console transport and the
[scoped request store](netbird-removal-recovery-requests.md),
[durable native delivery and receipt observation](netbird-removal-recovery-delivery.md)
are implemented. Dispatch, reviewed resolution and public UI integration remain
open. No recovery route or automatic recovery delivery is enabled.

## Evidence and independent attempt

Recovery binds the original uninstall request UUID, command hash, original review,
confirmed release UUID and native removal descriptor. A fresh individual-agent
inspection binds current native ownership and a ready-journal revision. The new
`recover-removal` request has its own UUID and console revision, separate from
both the original review and the explicit current journal revision.

The agent checks the exact original released unconfirmed attempt before native
inspection and again afterward. Native preparation holds reviewed objects
read-only; atomic journal admission precedes any runtime or filesystem mutation.
Run and cleanup join before the independent outcome. Exact replay retrieves that
outcome without reacquiring native ownership. Original uncertainty and release
evidence remain immutable, including after successful recovery.

Only `manifest` mode is currently valid. Missing/empty/incomplete manifests,
replacement installations and final-query failure after staging has disappeared
still need explicit policies. Native absence never rewrites an uncertain receipt.
Linux individual enrollment/publisher trust and physical package/reboot acceptance
remain separate requirements.

## Direct console transport

`PublishNetbirdRemovalRecovery` accepts only a valid fresh version-five command.
The delivery store commits the exact attempt and audit before calling it. It
performs one deadline-bound direct NATS request, validates the complete correlated
receipt and retains no JetStream message. A lost response returns unavailable;
it never retries. Connection, installation and fresh-removal publishers reject
recovery commands, and the recovery publisher rejects original uninstall commands.

The existing `RequestNetbirdControl` transports version-four inspection using its
explicit codec. It checks current identity, request UUID/hash, exact original
reference, mode and matching ready-journal revision. Missing, blocked, conflicting
and unavailable evidence remain distinct from successful current inspection.

## Verification and next integration

Owned NATS tests cover single direct delivery, all receipt outcomes, changed
original/release/journal/current-native fingerprints, wrong operations,
cancellation, expiry, legacy identities, original-UUID reuse and no response.
Inspection checks reject changed references, releases, journal revisions,
certificates, response hashes and old protocol versions. Existing publisher tests
also pass under the race detector; three timeout fixtures now keep their original
callback inputs immutable while testing a separate expired or alternate command.

All consumers pin the published runtime module
`v0.11.1-0.20260914130448-3606e2d2e6bd`. Agent native/journal/service race suites,
Darwin CGO, Linux and Windows agent builds, Darwin without-CGO native-package
compilation, and Linux console/worker builds pass.

The request store now verifies original owned unconfirmed release proof and
current individual native review, retains immutable scoped intent and explicit
cancellation, and shares permanent UUID/device exclusion with all other families.
The delivery store now persists one exact attempt before transport, excludes
cancellation after admission and never redelivers retained attempts. Read-only
receipt observation under current individual authority can confirm completion
without changing the first recovery result or the original uninstall evidence.
Joined dispatch, coherent history, reviewed resolution and public UI integration
remain required.

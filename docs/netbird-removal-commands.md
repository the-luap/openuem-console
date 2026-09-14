# Native NetBird removal protocol integration

The [shared removal command and inspection](https://github.com/the-luap/openuem-nats/blob/10ed2cf2ed01f76a0f83cb825f2a6c48fb86550e/docs/netbird-removal-commands.md) now distinguish exact
installed ownership from package approval and ordinary journal readiness.
Version-four `uninstall` binds a source-free native state fingerprint, package
identity/version, current individual recipient and original reviewed request.
Version-three read-only inspection reports present, absent or unavailable evidence
using a separate strictly correlated response grammar.

The agent executor now requires a separate native removal owner and the inspected
journal revision before creating an attempt. Removal shares permanent request
UUIDs, uncertainty, cancellation joining, restart barriers and explicit withdrawal/
release history with existing NetBird commands. Services without that owner reject
removal before admission; a journal alone cannot advertise package ownership.

The console connection and installation publishers both reject removal commands.
The existing direct control publisher transports the inspection response only
when its complete current recipient, UUID and request hash match. Owned NATS tests
verify present/absent/unavailable results, reject changed hashes/certificates or
old response versions, and prove that neither existing publisher sends a removal.
The separate [removal request store](netbird-removal-requests.md) now retains
fresh reviewed native state, exact-site software authority, immutable intent and
queued cancellation under the common five-family UUID/device barrier. It
now has a [public reviewed lifecycle](netbird-removal-ui.md); its
[joined dispatcher](netbird-removal-dispatch.md) processes committed requests.

The agent now also has a [private native package ownership inspector](https://github.com/the-luap/openuem-agent/blob/ee54842a8fe8e065ed935742a0d5e349b3421a63/docs/netbird-removal-ownership.md).
It verifies protected receipt/BOM and bundle objects, exact package file lists,
NetBird publisher signatures, native ACLs, the CLI link and supported daemon plist
under matching before/after snapshots. First-pass file handles prevent immediate
inode reuse from hiding an exchange during verification. This private filesystem
evidence is now joined by the [private runtime ownership observer](https://github.com/the-luap/openuem-agent/blob/eed274908645e816d16bab818465c0e06e63094b/docs/netbird-removal-runtime.md).
Kernel audit tokens, dynamic code validity and repeated process scans bind the
actual running instances. A typed system-domain launchd enumeration distinguishes
loaded, unloaded and unavailable evidence, and a running job PID must match the
root NetBird CLI. Two rounds of file/job/process evidence construct the complete
source-free descriptor privately. The [native execution owner](https://github.com/the-luap/openuem-agent/blob/aa1262dd95fa086649d7bc3bdee8beb08b0e13ad/docs/netbird-removal-execution.md)
now configures removal-state inspection and execution together on supported
individually enrolled root macOS services. It rechecks reviewed ownership under
the current journal revision, persists admission before mutation, stops exact
audit-token processes and the owned loaded job, and removes only verified objects
through exclusive protected staging. Completion requires repeated native absence.
Interrupted staging is preserved and prevents fresh preparation until local recovery.

Shared race/fuzz tests, agent journal/command/preparation race tests, owned native
agent/service/enrollment regressions and all supported consumer builds cover this
foundation. On the published protocol pin, the complete NetBird inventory suite
also passes with owned PostgreSQL, and direct publisher tests pass with owned NATS.
Existing command bytes and control digests remain stable. Tests do not
run a real vendor installer, daemon or remover.

Unconfigured services still reject fresh removal before admission. The console
now retains exact-site software rights, fresh reviewed intent, durable request
history and common device exclusion. [Native delivery](netbird-removal-delivery.md)
now commits one exact attempt before a direct version-four RPC, retains original
outcomes and recovers lost completed receipts through read-only queries under the
current certificate. Native admission excludes cancellation. [Explicit resolution](netbird-removal-resolutions.md)
now retains expiring reviews, owned control attempts and exact withdrawal/release
proofs, with read-only reconciliation for lost replies. [Joined dispatch](netbird-removal-dispatch.md)
now binds the native store at startup and retains immutable preflight stops.
The [public UI](netbird-removal-ui.md) now provides scoped review, confirmation,
status/history, receipt observation and explicit resolution. [Manifest-backed
local recovery](netbird-removal-recovery.md) now has separate shared command and
inspection grammars, native journal/service admission and console transport.
Its [scoped request store](netbird-removal-recovery-requests.md) now retains exact
original release proof and current native review. Native delivery, dispatch and
resolution/UI remain open.
Provider peer deletion and credential/configuration cleanup remain separate
reviewed operations. Linux individual enrollment/publisher trust and physical
package, interruption, reboot and daemon acceptance also remain open.

The console, agent and worker share immutable protocol revision
`v0.11.1-0.20260914130448-3606e2d2e6bd`. Original removal has a complete reviewed
console lifecycle. Independent retained-stage recovery still requires its own
console lifecycle and a separate policy for absent manifests.

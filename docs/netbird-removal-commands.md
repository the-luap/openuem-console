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
No public removal route or dispatcher is introduced by this protocol integration.

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
still needs exact-site software rights,
fresh reviewed intent, durable request/admission history, common device exclusion,
one native dispatch per immutable attempt, source-free receipts, explicit recovery and UI for removal.
Provider peer deletion and credential/configuration cleanup remain separate
reviewed operations. Linux individual enrollment/publisher trust and physical
package, interruption, reboot and daemon acceptance also remain open.

The console, agent and worker share immutable protocol revision
`v0.11.1-0.20260914083905-10ed2cf2ed01`. The removal protocol and guarded native
admission and native remover are present; console and retained-stage recovery
workflows remain required.

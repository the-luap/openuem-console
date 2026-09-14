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

Shared race/fuzz tests, agent journal/command/preparation race tests, owned native
agent/service/enrollment regressions and all supported consumer builds cover this
foundation. On the published protocol pin, the complete NetBird inventory suite
also passes with owned PostgreSQL, and direct publisher tests pass with owned NATS.
Existing command bytes and control digests remain stable. Tests do not
run a real vendor installer, daemon or remover.

Native ownership inspection and removal/result verification must be configured
before advertising support. The console still needs exact-site software rights,
fresh reviewed intent, durable request/admission history, common device exclusion,
one native dispatch per immutable attempt, source-free receipts, explicit recovery and UI for removal.
Provider peer deletion and credential/configuration cleanup remain separate
reviewed operations. Linux individual enrollment/publisher trust and physical
package, interruption, reboot and daemon acceptance also remain open.

The console, agent and worker share immutable protocol revision
`v0.11.1-0.20260914083905-10ed2cf2ed01`. The removal protocol and guarded native
admission are present; the native remover and console workflow remain required.

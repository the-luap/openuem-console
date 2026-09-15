# NetBird Unix package preparation

The shared package descriptor and agent preparation component now replace the
old unreferenced installer helpers as the basis for a managed Unix installer
flow. An immutable descriptor includes the organization, approval UUID, native
platform/architecture, package identity and version, exact HTTPS source, byte
length and SHA-256. The strict codec rejects ambiguous or unsupported fields and
keeps source coordinates out of ordinary formatting.

The agent downloads approved bytes into an owned private stage with an independent
HTTPS transport, no enrollment/provider credentials, no environment proxy and
no redirects. Size, content digest, container prefix and file identity are checked;
macOS also requires native PKG trust and a second hash of the same file. Cleanup
does not remove replaced paths. The removed legacy helpers no longer provide
remote shell or unpinned package installation as a fallback.

The descriptor does not authorize execution. Preparation now also requires exact
native package identity: DEB/RPM name, complete native version and architecture,
and macOS distribution/component identity plus both bundled executable headers.
The retained file and full descriptor are verified before and after inspection.
Linux queries use fixed tools, a clean environment, bounded output and joined
process cancellation. macOS streams bounded XAR/CPIO data without filesystem
extraction or Installer code evaluation; ambiguous paths and unsupported layouts
are rejected. Linux publisher provenance remains a separate requirement.

[Organization approval and history](netbird-package-approvals.md) now stores exact
descriptors with encrypted sources, current organization software authority,
explicit confirmation, atomic audit and permanent revocation. Authenticated
installer capability/command delivery, console durable attempt admission,
console resulting-state recovery, lifecycle UI and local removal remain open. The [version-three command and common journal](netbird-installation-commands.md)
now retain exact installation intent. Native macOS execution is implemented;
console current-approval admission and delivery still require integration.

This work uses inert TLS/filesystem/archive/process fixtures and read-only checks
of exact official v0.78.1 ARM64 PKG, DEB and RPM artifacts. Native metadata matches
their declared identities and rejects the wrong architecture. Apple's assessment
also confirms the PKG's notarization. The RPM native version is `0.78.1-1`; its
release component cannot be dropped. The macOS distribution advertises both CPU
architectures, so preflight also reads the actual CLI and UI executable headers.
No NetBird executable or installer is run. See the shared
[descriptor contract](https://github.com/the-luap/openuem-nats/blob/c9543d8ca1f2887fb62b90b50d55b1c2944cc547/docs/netbird-install-packages.md)
for its exact target and evidence boundaries. Independent Linux publisher trust and physical
installation acceptance must be established separately.

Descriptor race and seeded fuzz tests pass. Agent preparation, command and journal
race suites pass on macOS and Linux, and native service/broker regression checks
continue to reject legacy installer requests. macOS uses its real native verifier
to reject an inert unsigned PKG; no package is installed.
Full builds pass for the Linux console, Linux/macOS/Windows agent and
Linux/Windows worker with shared revision `c9543d8ca1f2887fb62b90b50d55b1c2944cc547`.
The native-identity change additionally passes macOS/Linux preparation, command
and journal race suites, native service regressions and fresh Linux/macOS/Windows
agent builds. Those native-identity checks preceded the separately implemented
console approval routes, UI and permanent storage.
The agent's [native identity contract and evidence](https://github.com/the-luap/openuem-agent/blob/be468ae0b5d1c5d1c54545eeb3b5817fed15f845/docs/netbird-package-identity.md)
document supported archive profiles, bounds, exact artifact hashes and remaining
authority requirements. Final preparation race checks pass in 7.715 seconds on
macOS and 3.856 seconds on Linux; command/journal and service regressions also
pass. XML and payload fuzz runs process 7,435 and 223,536 inputs; an additional
fixed-count XAR run completes 1,000 inputs successfully.

## Authenticated preparation endpoint

The shared [preparation RPC](https://github.com/the-luap/openuem-nats/blob/fbef45520563fa80ee2809ca815cd2e8a1c549bd/docs/netbird-commands.md#authenticated-private-package-preparation)
now carries a strict current individual identity, reviewed revision, live journal
revision, request UUID, exact private package and bounded issue/expiry times on
`agent.netbird.prepare.<device UUID>`. The individual-only `preparation-state`
control discovers actual staging support. Ordinary/registration state does not
establish that support, and staging support never advertises a native installer.

The [native agent service](https://github.com/the-luap/openuem-agent/blob/f6279f12aec1d34a3eada562de0c83cc78ebb38b/docs/netbird-package-preparation.md#authenticated-service-ownership)
opens a fixed private `netbird-preparation` sibling of
the execution journal beneath its validated individual identity directory. One
artifact may be retained. Download and inspection hold the common executor mutex,
and the result requires unchanged ready journal state. A concurrent withdrawal
invalidates preparation. Exact request replay verifies the same file without
downloading again; changed source/review/deadline conflicts. Replacing the broker
connection retains this owner, while current identity/certificate checks reject
foreign or expired messages before download.

The correlated response contains only identity, request UUID, complete hash and
outcome. It exposes no URL or local path and is not durable execution evidence.
Expiry, journal changes or service cancellation clear the cache. Shutdown joins
downloads and cleanup before closing the journal. Under the exclusive journal
lease, restart removes at most one strictly shaped private abandoned stage;
unknown entries, symlinks or unsafe permissions prevent preparation. No recursive
deletion or permission repair is used. Cleanup failures stop further preparation.
During a live service, unexpected files are preserved and disable preparation;
failed cleanup never invokes the broader startup recovery path. Native startup
does not publish managed readiness if it cannot safely open its preparation owner.

The [console preparation component](netbird-console-preparation.md) now binds one
exact request to immutable attempt/result storage and a direct preparation RPC.
It rechecks current approval/recipient authority and both native capabilities,
commits admission before RPC and holds no database lock through download. The
[native delivery component](netbird-installation-delivery.md) now rechecks
current authority and exact preparation, retains one fresh command attempt and
verifies/retrieves its completed receipt. Native attempts exclude cancellation;
preparation alone remains cancellable. [Reviewed uncertain-operation recovery](netbird-installation-resolutions.md)
is implemented; lifecycle UI and local removal remain required. Native macOS
installation now consumes the exact prepared package under atomic current
journal admission, rechecks trust and verifies its receipt, complete payload and
CLI link. It requires a root individual agent with native ACL support and advertises
a separate `installation-state` capability. Linux additionally needs individual
enrollment and independent publisher provenance. Native delivery is available
through its separately configured backend method;
[Automatic dispatch](netbird-installation-dispatch.md) now resumes prepared work
with fresh native admission and retains preflight stops; device lifecycle routes
remain unconnected.

Owned broker/filesystem tests cover source correlation, exact replay, parallel
admission, retained uncertainty, journal changes during download, connection
replacement, expiry, partial crash files, symlinks and joined shutdown. A test
through the real native binding rejects the wrong platform before any HTTP call.
These tests do not run a NetBird installer, daemon or provider.
That endpoint milestone used `v0.11.1-0.20260914044144-fbef45520563`. The complete shared race
suite passes; seeded preparation decoding fuzzes 11,748,164 inputs in 31.401
seconds. Final macOS command/preparation/journal race suites pass in
5.638/4.201/7.633 seconds and native agent regressions in 2.574 seconds.
Linux journal/command/preparation race suites pass in 5.208/3.793/3.820 seconds.
All six complete builds pass: Linux console, Linux/macOS/Windows agent and
Linux/Windows worker. No console route, form or browser asset changed in this
endpoint milestone; its installation publisher remains unconnected.
The compiled console publisher fixtures also pass and confirm that installation
commands still cannot use the connection/registration delivery path.
The full native `internal/agent` race suite additionally passes in 24.424 seconds,
covering runtime interactions beyond the focused NetBird fixtures.

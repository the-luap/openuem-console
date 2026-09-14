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
installer capability/command delivery, durable attempt admission, install/remove
execution, resulting-state observation and
uncertainty recovery are still open. Existing NetBird command versions continue
to reject installer operations, and console installation remains unavailable.

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

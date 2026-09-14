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

The descriptor does not authorize execution. Linux preparation establishes exact
bytes and container prefix; authenticated approval provenance, native package
identity and eventual execution require their own checks. Console approval and
storage, authenticated installer capability/command, durable attempt admission,
native preflight, install/remove execution, resulting-state observation and
uncertainty recovery are still open. Existing NetBird command versions continue
to reject installer operations, and console installation remains unavailable.

This work uses inert TLS/filesystem/native rejection fixtures, not a real NetBird
installer or endpoint. See the shared
[descriptor contract](https://github.com/the-luap/openuem-nats/blob/c9543d8ca1f2887fb62b90b50d55b1c2944cc547/docs/netbird-install-packages.md)
for its exact target and evidence boundaries. Publisher authenticity and physical
installation acceptance must be established separately.

Descriptor race and seeded fuzz tests pass. Agent preparation, command and journal
race suites pass on macOS and Linux, and native service/broker regression checks
continue to reject legacy installer requests. macOS uses its real native verifier
to reject an inert unsigned PKG; no package is installed.
Full builds pass for the Linux console, Linux/macOS/Windows agent and
Linux/Windows worker with shared revision `c9543d8ca1f2887fb62b90b50d55b1c2944cc547`.

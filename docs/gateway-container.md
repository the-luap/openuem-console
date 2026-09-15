# Gateway container image and process verification

[`Dockerfile.gateway`](../Dockerfile.gateway) builds the native HTTPS gateway as
a separate Linux container for the one-port installation. The runtime contains
the statically linked gateway executable, runs as UID/GID `65532:65532`, and
declares only TCP 8443. Its default arguments select `--listen :8443`; when
supplying a complete replacement argument list, include that option explicitly.
Production configuration uses the [gateway trust and routing contract](gateway-operations.md).

The build pins the official Go 1.26.8 Bookworm multi-platform image by digest and
sets `GOTOOLCHAIN=local`. Go dependencies are resolved read-only against the
repository's module files. Docker's
[multi-stage build](https://docs.docker.com/build/building/multi-stage/) copies
only the executable into a `scratch` runtime. The Dockerfile-specific build
context allowlist includes only module files and the required Go source
directories. Local certificates, environment files, backups, browser artifacts
and unrelated repository files are excluded from that build context.

Build the runtime from this repository using BuildKit:

```sh
docker build -f Dockerfile.gateway --target runtime -t openuem-gateway:local .
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges openuem-gateway:local --help
```

The default final target is also the runtime. `TARGETOS` and `TARGETARCH` support
Linux amd64/arm64 builds; the test workflow uses native GitHub runners for both
architectures. An image build is not a signed release or a registry publication.
Release signing, publication and installation orchestration remain separate work.

## Runtime configuration

Provide the public origin, approved administrator source networks, private backend
origins and certificate paths through the gateway's existing command arguments.
Mount the public certificate directory and dedicated gateway credentials read-only
with permissions allowing UID 65532 to read them. The image has no default
certificate, private key, database credential, NKey, system CA bundle or shell.
`--backend-ca` explicitly supplies trust for private backend server certificates;
each backend separately pins the dedicated gateway client leaf. All referenced
paths are paths inside the container.

Public certificate renewal observes complete archive generations through the
mounted directory. Keep its publisher separate and follow
[atomic public TLS publication](gateway-operations.md#public-tls-renewal).
The [separate DNS-01 issuer](gateway-acme.md) can obtain and renew these generations
while keeping its account and DNS credentials outside the gateway mount.
No writable root filesystem or Linux capability is required by the gateway.
SIGTERM closes tracked streams, stops serving and joins the certificate watcher.

A full installation maps external TCP 443 to the gateway's 8443 listener and keeps
all other service ports private. Docker `EXPOSE` is image metadata; actual port
publication and firewall behavior are properties of the installation. Verify the
source address observed by the gateway across IPv4, IPv6 and the selected container
network, because administrator admission uses the actual TCP source. A forwarding
proxy or NAT address cannot replace an approved administrator network. The
reference stack, provider DNS-01 issuance, source-preserving network/firewall proof
and physical-device acceptance remain open.

## Isolated process test

The separate `smoke` target adds a Go test executable and runs the **same gateway
binary** as the runtime target. It creates its own TLS authority, public leaf,
gateway credential, synthetic endpoint key and private backend on loopback. It
starts the real command with a one-second reload interval and verifies:

- Private administration succeeds from its sole approved source and is denied
  from a second loopback source, including forged forwarding headers and aliases.
- Public Apple, desktop and Windows paths reach the pinned private backend; the
  actual TLS end-device certificate survives forwarding.
- The command's scheduled watcher serves a replacement certificate on new TLS
  connections while preserving its original HTTP/2 connection.
- A partial key publication is rejected, the valid loaded pair remains usable,
  and SIGTERM completes joined shutdown.

Run the owned fixture with read-only root, dropped capabilities, bounded memory,
bounded temporary storage and only loopback networking:

```sh
docker build -f Dockerfile.gateway --target smoke -t openuem-gateway-smoke:local .
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 64 --memory 128m \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m \
  openuem-gateway-smoke:local
```

The test rejects root execution. Its 128 MiB memory limit is a fixture constraint,
not production sizing. The process fixture passes locally on native Linux arm64
under Docker Desktop in **3.13 seconds**. Runtime startup help and an exported
filesystem inspection also pass; the runtime contains only the gateway executable
and Docker-created mount/metadata paths. The
[container workflow](../.github/workflows/gateway-container.yml) builds and runs
both architectures, requires the explicit test pass line and checks runtime user,
declared port and absence of test/source/credential files.
At `79d415d`, all native amd64 and arm64 jobs pass in both
[push CI](https://github.com/the-luap/openuem-console/actions/runs/34497033584)
and [pull-request CI](https://github.com/the-luap/openuem-console/actions/runs/34497040423),
including the required process-test execution and runtime filesystem checks.

The broader gateway race suite independently tests real NATS request/reply through
public TLS renewal, per-handshake expiry including session resumption, atomic
archive switches, issuer constraints and concurrent publication. The process
fixture tests the container/command wiring; it does not replace actual backend
enrollment, broker, provider, external-network or device acceptance.

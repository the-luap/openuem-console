# Private broker reference image

`Dockerfile.broker` builds the unmodified `nats-server` command from the exact
NATS server module selected by this repository's `go.mod` and `go.sum`. The current
pin is 2.14.6, also used by the protocol fixtures. The builder pins Go 1.26.8 by
image digest and resolves dependencies read-only. Its restricted build context
contains only the two module files.

The scratch runtime contains the statically linked executable and the dependency's
Apache license. It runs as UID/GID 65532, prints help by default, declares no
exposed ports and uses SIGTERM for shutdown. It contains no service seeds, private
keys, default broker configuration, shell, package manager or public CA bundle.

```sh
docker build -f Dockerfile.broker --target runtime -t openuem-broker:local .
python3 scripts/check-broker-image.py openuem-broker:local
```

This is a local distribution build, not a published or signed release.

## Private configuration and storage

Generate `broker.json` with the existing `openuem-cert-manager individual-broker`
command. Its TLS and storage paths must match paths inside the broker container.
Keep the provisioning directory separate; mount only these inputs:

| Mount | Access |
| --- | --- |
| Generated `broker.json` | Read-only; contains public service NKeys |
| Dedicated broker server certificate and key | Read-only |
| Pinned gateway leaf bundle for the WSS listener | Read-only |
| JetStream storage directory | Private, persistent and writable by the broker UID/GID |

The broker must never receive the authorization signing seed, service user seeds,
database credentials or private CA key. Service processes receive only their own
credentials. For generated backend identity paths, follow the pinned private PKI
initializer's instructions and [private service mounts](private-service-containers.md).

Start with `--config /run/openuem/broker.json` and
`--read-only --cap-drop ALL --security-opt no-new-privileges`, supplying the exact
private mounts and suitable memory/process limits. The generated configuration
uses private TLS/NKey authentication, a separate gateway-authenticated WSS
listener and bounded JetStream storage. Preserve that configuration when starting
the stock command. Do not publish either backend port. The public gateway owns
the device WSS route; direct service connections use private TLS broker origins.

Prepare storage and input ownership before startup, retain the same JetStream
directory across restarts, and retain the original provisioning identities.
Changing a runtime UID requires corresponding ownership preparation; broadening
credential permissions is not an installation step.

## Verification and remaining integration

The image audit executes offline help and version checks with the read-only
runtime and default non-root account, rejects a missing configuration, verifies
the exact executable/license file set, and checks the pinned license bytes.

The console PostgreSQL fixture extracts this image's stock executable and starts
it as a separate process using the actual private PKI and broker initializers.
It connects through TLS with the private provisioning NKey, creates the command
stream, runs the console's first-login/password-replacement flow, and restarts
both processes. It checks successful SIGTERM exits, retained JetStream stream
configuration and retained administrator state. Its surrounding Docker fixture
has no external network or published ports. These process checks supplement the
existing embedded broker authorization, command, worker and gateway tests.

The local Linux arm64 image audit, complete PostgreSQL suite and affected vet
checks pass with the stock distribution executable.

Native Linux amd64 and arm64 console CI requires the image and process checks.
The fixture uses one isolated container for its processes; separate container
mount/network boundaries, a complete installation/restore workflow, public
firewall/source-address proof and physical endpoint acceptance remain open.

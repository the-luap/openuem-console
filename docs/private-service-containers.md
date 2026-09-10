# Private authorization, command and worker images

The authorization service and command provisioner have separate distribution
targets in `Dockerfile.services`:

```sh
docker build -f Dockerfile.services --target authorization -t openuem-agent-auth:local .
docker build -f Dockerfile.services --target commands -t openuem-agent-commands:local .
python3 scripts/check-service-images.py openuem-agent-auth:local openuem-agent-commands:local
```

Each scratch runtime contains one static executable and its license. The Go
1.26.8 builder is pinned by digest. Both run as UID/GID 65532, expose no port,
use SIGTERM and print English help by default. Their build context allows only
the required source and module files; private configuration, keys, tests and
sibling checkouts are excluded. The images have no shell or system CA bundle.
The build does not publish images or change a running installation.

The individual worker's separate image is built by the worker repository at
[revision 4a5462e](https://github.com/the-luap/openuem-worker/commit/4a5462e832d9896816a7759af9a9a9453fc302c9).
See its [container operations guide](https://github.com/the-luap/openuem-worker/blob/4a5462e832d9896816a7759af9a9a9453fc302c9/docs/individual-container.md).

## Runtime inputs

Complete database bootstrap and registry migrations before starting these
services. Use the existing [authorization](agent-authorization-operations.md)
and [command](agent-command-operations.md) flags with protected database URL
files. Mount the selected private broker CA explicitly. The database URL must
use `sslmode=verify-full` and point to the mounted public database CA.

| Service | Private inputs | Public trust/configuration |
| --- | --- | --- |
| Authorization | Application database URL, issuer account seed, authorization user seed and system revocation user seed | Broker CA, database CA, explicit private broker origins and device account name |
| Commands | Application database URL and provisioner user seed | Broker CA, database CA and explicit private broker origins |
| Individual worker | Application database URL, worker user seed and task encryption key when used | Broker CA, database CA and explicit private broker origins |

Mount only each service's required inputs read-only. No service receives the
database administrator password, private CA key, installation provisioning journal
or another service's NKey. Authorization and commands do not receive the task
encryption key. Optional private broker client identities require the matching
certificate and protected key on the relevant service only.

Private files must retain the library's ownership and permission requirements.
Choose a runtime UID matching the owned input mounts; `--user` can override the
image default when the deployment prepares a different account. Do not broaden
permissions to accommodate different UIDs. Keep parent directories trusted.
Automatic ownership preparation remains part of reference deployment work.

The services need private PostgreSQL/TLS broker connectivity and no published
host ports. Authorization and commands keep their existing health listeners
bound to numeric loopback addresses. Run with a read-only root, dropped
capabilities, `no-new-privileges` and suitable memory/process limits. These
individual service paths require no writable working directory or PID file.

## Verification

The image audit runs help and rejected unconfigured startup offline, with the
default unprivileged UID and read-only filesystem. It checks image settings and
the exact permitted exported files, including Docker's generated runtime files.

Native amd64/arm64 console CI extracts all three executables from their actual
distribution images. The isolated PostgreSQL suite uses generated private PKI
and provisioned application credentials, then starts those executables through
the existing authorization, command and worker fixtures. These verify TLS broker
traffic, revocation, durable queues, authenticated Windows/Mac requests and
successful process termination. The test container runs them as its PostgreSQL
fixture account with matching private input ownership. Image-default UID startup
is covered separately by the offline audit; this is not a full multi-container
installation or ownership migration test.

Local native Linux arm64 checks pass for all three image boundaries and the
combined distribution-executable fixture (6.69 seconds). Full service composition,
console/admin authority integration, installation/restore acceptance and signed
release publication remain open in the [implementation ledger](implementation-status.md).

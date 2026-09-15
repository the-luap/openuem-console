# Console reference image

`Dockerfile.console` builds a dedicated console runtime with pinned build and
runtime image digests. It runs as UID/GID 65532, exposes no Docker ports, selects
individual agent mode and prints English help by default:

```sh
docker build -f Dockerfile.console --target runtime -t openuem-console:local .
python3 scripts/check-console-image.py openuem-console:local
```

The build keeps CGO enabled because the existing Windows package catalog importer
uses the `go-sqlite3` driver. It builds for the target architecture with the pinned
Go 1.26.8 Bookworm compiler image. The pinned
[Distroless Debian 13 base](https://github.com/GoogleContainerTools/distroless)
supplies the C runtime and public CA certificates without a shell or package
manager. Native amd64 and arm64 CI builds are required; a cross-compiled
CGO-disabled binary is not equivalent to this runtime.

Only the executable, versioned assets and console license are added to that base.
The restricted build context contains required source, translations, migration
SQL and embedded public Apple trust data. Credentials, sibling checkouts and
unrelated workspace files are excluded. The image audit compares every base file
and every versioned asset byte against the final image. No image is published by
these build commands.

## Private runtime mounts

Mount only the console's own inputs read-only:

| Input | Configuration |
| --- | --- |
| Application database URL and public database CA | `DATABASE_URL_FILE`; the URL must use `sslmode=verify-full` and the mounted CA path |
| JWT and task-field encryption keys | `JWT_KEY_FILE`, `ENCRYPTION_MASTER_KEY_FILE` |
| Installation identifier and initial administrator password | `OPENUEM_INSTALLATION_ID`, `OPENUEM_BOOTSTRAP_ADMIN`, `OPENUEM_BOOTSTRAP_PASSWORD_FILE` |
| Console NKey and public private-broker CA | `OPENUEM_AGENT_CONSOLE_KEY_FILE`, `OPENUEM_AGENT_BROKER_CA_FILE`; explicit `OPENUEM_AGENT_BROKER_URLS` |
| Console server certificate/key and pinned gateway leaf bundle | `--cert`, `--key`, `OPENUEM_TRUSTED_GATEWAY_CERTIFICATES` |
| Independent administrator public CA | `--cacert`; not the private backend CA |

The database administrator password, private CA key, other service NKeys and
provisioning journals are not console mounts. See
[protected installation credentials](installation-secrets.md),
[private service images](private-service-containers.md),
[the private broker image](broker-container.md) and
[database ownership](reference-database-ownership.md).

The existing foreground console requires two writable locations with private
ownership matching the selected runtime UID:

| Path | Contents |
| --- | --- |
| `/tmp` | PID file and temporary download, release and package catalog directories |
| `/var/log/openuem-server` | Existing authentication log |

For the default UID, suitable temporary mounts use
`--tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m,uid=65532,gid=65532,mode=0700` and
`--tmpfs /var/log/openuem-server:rw,nosuid,nodev,noexec,size=16m,uid=65532,gid=65532,mode=0700`.
Temporary authentication logs disappear with the container. Production operations
must retain and rotate them using a private persistent mount or collection
mechanism. Adjust UID/GID and resource bounds deliberately when selecting another
deployment account; do not broaden private input permissions.

Run with `--read-only --cap-drop ALL --security-opt no-new-privileges`. Start the
actual service with `start --domain <domain> --org-name <organization>` plus its
private configuration, intended ports and canonical `OPENUEM_PUBLIC_ORIGIN`.
Complete database bootstrap before console schema/account initialization. It
requires the private broker to be available before serving. Public exposure
belongs to the gateway; no console, authentication, database or broker host port
should be published. Outbound provider/catalog access is a separate deployment
network requirement.

## Verification and limits

The `smoke` target runs the actual console executable's help and verifies its
CGO build metadata, a SQLite catalog create/query and available public TLS roots
inside the distribution runtime, offline with a read-only root and no privileges:

```sh
docker build -f Dockerfile.console --target smoke -t openuem-console-smoke:local .
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 64 --memory 256m \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=32m,uid=65532,gid=65532,mode=0700 \
  openuem-console-smoke:local
```

Native console CI extracts the distribution executable and its assets for the
isolated PostgreSQL suite. The console process uses generated installation
credentials, the provisioned application database, actual private PKI/broker
initializers and the separately started stock broker distribution. It serves the
English login and image assets through pinned gateway TLS, rejects direct clients
on both backend listeners, requires password
replacement at first login, persists the new hash and installation binding, and
retains the administrator password across a clean SIGTERM stop/restart of both
console and broker. The broker retains its provisioned JetStream stream.

Foreground startup registers shutdown signals before starting listeners. Its
release requests share the shutdown context, so an in-flight catalog request
cannot keep startup blocked until its network timeout after SIGTERM. The process
fixture deliberately holds the catalog connection at an offline loopback proxy
on both starts and requires successful process exit within the shutdown deadline.
The preceding implementation fails this regression; the context-aware version
passes. A native unit test also verifies request cancellation. Installed-service
startup and other initialization phases retain their existing lifecycle behavior.

Local Linux arm64 Docker checks pass for the image audit, runtime/SQLite smoke
and the complete PostgreSQL suite, including the console and separate
authorization, command and worker processes. Windows cross-build and affected
Linux/Windows vet checks pass. The console process
fixture runs as its PostgreSQL container account with matching writable runtime
mounts; the image-default UID and libraries are checked separately in the image
audit/smoke. Separate-container wiring now has its own
[reference composition acceptance](reference-composition.md). Administrator
certificate issuance/OCSP, provider connectivity,
physical endpoint acceptance and complete installation/restore operations
still require their own acceptance evidence.

# Installation setup container images

`Dockerfile.setup` builds three separate setup images. Each runtime contains one
statically linked command and the console license, runs as UID/GID 65532, exposes
no port, and includes no shell, source tree, test executable or credentials. Build
the intended target explicitly:

```sh
for target in installation-secrets database-credentials database-bootstrap; do
  docker build -f Dockerfile.setup --target "${target}" \
    -t "openuem-${target}:local" .
done
```

The Go builder and its version are pinned by digest. The default Dockerfile target
is `database-bootstrap`; none of the images is published by this build procedure.
With no arguments, each image prints its command's English help. Provisioning
requires explicit paths and configuration.

| Target | Job | Required access |
| --- | --- | --- |
| `installation-secrets` | Generate or verify the retained installation identifier, JWT/master keys and first password | One private output directory; no network |
| `database-credentials` | Generate or verify independent database passwords and a verify-full URL | Protected public metadata read-only; separate private output directory; no network |
| `database-bootstrap` | Create or verify the bound PostgreSQL application role/database | Completed credentials, metadata and public CA read-only; separate journal writable; private database network |

See [installation secrets](installation-secrets.md),
[database credentials](database-credentials.md) and
[database bootstrap](database-bootstrap.md) for their configuration and recovery
rules. All three commands preserve existing committed state; rebuilding an image
does not rotate keys or passwords.

## Storage and startup order

Create deployment directories under trusted existing parents, with ownership and
permissions appropriate to the selected runtime UID. Output/journal directories
are private mode 0700. Completed credential files must remain readable only by
their intended account or the system administrator; read-only mode 0400 files and
mode 0500 input directories are accepted by the online bootstrap. Its credential
reader neither creates files/directories nor syncs input mounts. Bootstrap journal
writes remain separate and durable.

The images do not recursively create host parents, change existing ownership or
repair permissions. A different `--user` requires matching ownership for that job's
inputs and outputs. PostgreSQL's runtime account must be able to read its own
private server key and initialization password. Do not broaden file permissions
to work around different service UIDs. Full deployment ownership wiring is a
separate remaining reference-installation step.
The [reference database ownership fixture](reference-database-ownership.md)
exercises all setup images and the official PostgreSQL entrypoint under one
explicit non-root UID/GID, with private bind mounts and retained restart state.

For example, after provisioning `/srv/openuem/installation` for the selected UID:

```sh
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 64 --memory 128m \
  --mount type=bind,src=/srv/openuem/installation,dst=/state \
  openuem-installation-secrets:local --directory /state
```

Use its public installation identifier in the protected database metadata and run
the database credential job in another private directory. Then initialize the
private PKI with database DNS names, start PostgreSQL with its server TLS identity
and generated administrator password, and run the database bootstrap job. Mount
its metadata, completed credentials and public CA read-only, and mount only its
separate journal writable. Give that job access to the private database network;
it needs no published host port. Start the console only after bootstrap succeeds,
with its application URL and installation keys mounted read-only. The bootstrap
administrator password, private CA key and provisioning journals are not console
mounts.

## Verification

The `smoke` target contains the exact runtime executables plus a separate test
binary. It runs offline inside an unprivileged, read-only scratch container with
only a small writable temporary filesystem. It checks actual command startup and
help, protected generation, public output, exact retries, missing committed
credentials and refusal to enter online bootstrap with damaged inputs.

```sh
docker build -f Dockerfile.setup --target smoke -t openuem-setup-smoke:local .
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 64 --memory 128m \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m openuem-setup-smoke:local
```

The native amd64/arm64 pipeline checks each distribution image's entrypoint,
runtime UID, absence of exposed ports and exported filesystem. Its PostgreSQL
suite extracts the actual `database-bootstrap` distribution executable and runs
it with generated private TLS, read-only credential permissions, real database
locking and process termination. The ordinary console model migrates the resulting
database. CI also requires an explicit pass from the offline smoke fixture.

The same isolated PostgreSQL suite starts the actual authorization and command
service executables and the pinned individual worker at
`4a5462e832d9896816a7759af9a9a9453fc302c9`. Each executable is extracted from its
[separate service distribution image](private-service-containers.md), and consumes a protected application
database URL file; the worker also receives a protected task encryption key file.
Their existing real TLS broker fixtures exercise authorization/revocation,
durable command reconciliation and authenticated Windows/Mac worker requests,
then require successful process shutdown after SIGTERM. The database uses the
generated private PKI and provisioned application role. The service process
fixture requires all six test/runtime binary paths and explicit pass markers;
an incomplete or skipped child fixture cannot pass CI.

These checks use only synthetic material. Complete reference composition,
automatic service ownership preparation, signed release publication and full
fresh-install/restore acceptance remain open in the
[implementation ledger](implementation-status.md).

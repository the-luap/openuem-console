# Retained reference broker maintenance

[`scripts/maintain-reference-broker.py`](../scripts/maintain-reference-broker.py)
reviews and resumes the known worker-grant migration in an existing
[seven-service reference project](reference-composition.md). It adds the
`hardware`, `recovery` and `rotation` request subscriptions through the PKI
component's [retained broker upgrade](https://github.com/the-luap/openuem-cert-manager/blob/b06bac13bd0e72f306a87ed119d2f7be66a66063/docs/broker-upgrade.md).
The database keeps running. Application services and the gateway have a planned
interruption; the broker container is recreated against the reviewed local image
and the same persistent JetStream directory.

This operation preserves installation credentials, service seeds, device
identities, administrator accounts and queued commands. It does not implement
general image upgrades, fresh installation, backup restoration or certificate
rotation. It rejects custom broker policies rather than merging permissions.

## Review and apply

Use a non-root POSIX account with access to the existing Docker project and its
private state. Supply the same absolute Compose files, project directory and
explicit environment file used by that installation, including its publication
overlay when applicable. An initialized project normally omits the
`compose.bootstrap.yaml` overlay and initial-password mount. An older reference
project that still has that exact protected console mount is also accepted; it
must be reflected in the reviewed configuration. Maintenance does not remove it
or recreate application containers. It also accepts the preceding exact protected
`administrator-ca.pem` trust location at the state root, as well as the current
`pki/state/trust/administrator-ca.pem` export. It neither moves nor replaces trust.
All service images, the pinned PKI upgrade image and
the `reference-probe` target of `Dockerfile.setup` must already exist locally.
The command resolves image references to immutable local image IDs. It does not
pull images. The Python controller requires only the standard library and Docker
Compose; Docker access remains on the host and is never mounted into a service.

For an existing project named `openuem`, with its explicit environment file at
`/srv/openuem/reference.env`, a review invocation is:

```sh
python3 scripts/maintain-reference-broker.py \
  --project-name openuem \
  --project-directory /srv/openuem \
  --file /opt/openuem/deploy/reference/compose.yaml \
  --file /opt/openuem/deploy/reference/compose.publish.yaml \
  --env-file /srv/openuem/reference.env \
  --setup-image openuem-private-pki:local \
  --probe-image openuem-reference-probe:local \
  --check
```

Use paths and locally reviewed image references belonging to that installation.
The default environment file is `/dev/null`; inherited explicit environment
variables still participate in Compose interpolation. The controller does not
discover an installed `.env` or guess a project from the current directory.

The JSON review reports the project, `review_sha256`, before/after broker hashes,
required change, completed steps, interruption scope and retained database. It
contains no credential values. `--check` writes no installation or operation
state and uses only a read-only broker-state mount for its offline preview.

To apply, repeat the same inputs, replace `--check` with `--apply`, and add
`--expected-review` with that exact reviewed digest. A stale review is rejected
before any service stops or operation directory is created. The review binds the
rendered configuration, local images, state location and existing container
identities. The controller compares the actual project against explicit mount,
network, environment, executable and privilege boundaries. A missing project,
unhealthy database, extra service, unexpected mount or exposed backend fails
review. Compose `null` command/entrypoint values retain their image defaults;
explicit empty values remain distinct, following the
[Compose service model](https://docs.docker.com/reference/compose-file/services/).

The application proceeds in this order:

1. Acquire the private operation lease and durably retain the reviewed inputs.
2. Stop the gateway, then worker, authorization, commands and console. Require
   successful joined shutdown of processes that were running.
3. Stop the broker cleanly and apply the exact reviewed offline migration.
4. Recreate only the broker using the frozen rendered model and its local image
   ID. Authenticate with the retained worker seed over verified private TLS;
   require every current request subscription and reject a broader wildcard.
5. Start the retained console, authorization, command and worker containers.
   Require both private HTTP health endpoints and the worker's current-start
   subscription marker. Start the gateway last, then verify Windows discovery
   and desktop bootstrap discovery through its HTTPS listener and public host.
6. Confirm the seven running services and publish the completion receipt.

The broker's single-file configuration mount is deliberately recreated as part
of this procedure. Whether atomic replacement is already visible through an
existing bind depends on the container runtime; recreation is an explicit step
here, not a claim that every Docker restart leaves an old file mounted.

## Interruption and retained state

The state directory is
`OPENUEM_REFERENCE_STATE/maintenance/broker-worker-grant-v1/`. It contains a
private review, frozen Compose model, OS lease and six ordered completion
markers. Files are created exclusively, synchronized and never overwritten;
directories use mode 0700 and files mode 0600. Treat the rendered model as private
deployment metadata even though raw database URL and encryption-key settings are
refused. The PKI
component retains its own configuration backup and migration journal separately
under `broker/state`.

After interruption, repeat the same invocation and original review digest.
Completed steps remain durable, and the controller resumes before declaring
readiness. A newly recreated broker can be recovered after interruption without
replacing the retained application containers. Failed maintenance attempts stop
the gateway on a best-effort basis and keep the journals for recovery. Abrupt
host failure still requires the ordinary Docker/host recovery procedure before
resuming; the journal does not control another administrator's Docker commands.

Do not remove journals, rotate keys or restore an old broker file to retry. Missing,
partial, noncanonical, aliased or reordered operation records fail closed. A
configuration rollback after publication is rejected. A stopped broker with an
unsuccessful exit cannot become a successful shutdown merely because the
controller was interrupted before recording it. Concurrent maintenance is
rejected by the operation lease. Deployment changes outside the operation require
separate review; they are not silently incorporated into a retained migration.

For current broker configuration with no migration required, apply returns
`unchanged` without downtime or a new operation journal. A completed operation
returns `already-complete` without restarting services. That receipt records a
finished operation; it does not claim a fresh readiness check of a subsequently
changed runtime.

## Readiness command and acceptance

The separate `openuem-reference-probe` command has `broker`, `http` and `gateway`
modes and a bounded timeout from one second to one minute. It emits only
`{"ready":true}` on success and fixed redacted errors on failure. HTTP health
probes accept only numeric loopback listeners and status 204. Gateway probes
connect to an explicit private IP while preserving the public HTTP host and TLS
name, pin the currently provisioned leaf certificate and require status 200 from
both discovery routes. Redirects and environment proxies are disabled. Broker
probes verify the current subscription grant using the retained worker key;
run this mode during maintenance before public device traffic resumes.

The isolated reference acceptance mode uses the actual historical initializer,
stock broker, current worker and production maintenance command. It proves the
old grant fails worker startup, creates a synthetic enrolled identity and pending
command, checks read-only/stale/concurrent review handling, interrupts immediately
after configuration publication and resumes through the CLI. Administrator login,
the pending message/consumer and authenticated device requests survive. Completed
retry preserves container IDs and start times; the remaining complete-reference
shutdown, restart and live WSS revocation tests still run.

Native Linux amd64/arm64 CI runs both fresh and maintenance fixtures with private
temporary projects and no published ports or provider access. Go tests cover
actual TLS, broker grants, redirects and cancellation; Python tests cover protected
metadata and interrupted shutdown rejection. Windows CI covers the portable probe;
the Python maintenance controller requires POSIX. These are synthetic integration
checks. External ingress, backup recovery, signed releases and physical endpoint
acceptance remain separate requirements.

# Reference composition and isolated acceptance

[`deploy/reference/compose.yaml`](../deploy/reference/compose.yaml) connects the
separate console, gateway, stock broker, authorization, command provisioning,
individual worker and PostgreSQL distribution images. It declares explicit
networks and private bind mounts, a non-root runtime account, read-only root
filesystems, dropped capabilities and bounded resources.

This is integration work toward NET-01 and the reference installer. A complete
guided production installer, external authority/provider setup, backup recovery
and physical endpoint acceptance remain open.

## Runtime boundaries

| Network | Services |
| --- | --- |
| `data` | PostgreSQL, console, authorization, commands, worker |
| `messaging` | Broker, console, authorization, commands, worker |
| `console_backend` | Gateway and console |
| `broker_backend` | Gateway and broker |
| `edge` | Gateway; the public entry point |
| `egress` | Console; outbound provider and catalog operations |

The four backend networks are internal. The
[Compose network model](https://docs.docker.com/reference/compose-file/networks/)
requires explicit service membership; a declared internal network has no
external connectivity. The acceptance fixture also makes `edge` and `egress`
internal, so it cannot contact providers or publish services outside its owned
Docker networks.

All backend listener names match their private certificate DNS identities.
The gateway sends console, authentication, Apple, desktop enrollment and Windows
MDM requests to their distinct private listener ports. Device WSS reaches the
broker through the dedicated gateway identity. Only the gateway receives its
client key. The broker receives public service NKeys in its generated
configuration; service seeds remain separate mounts for their intended users.

The base manifest publishes no ports. The separate
[`compose.publish.yaml`](../deploy/reference/compose.publish.yaml) adds only TCP
443 to gateway port 8443. The fixture validates this rendered mapping without
starting the publication overlay. Host firewall behavior, source preservation
across the chosen ingress/NAT and real external IPv4/IPv6 access still need
deployment acceptance.

## State and startup

The manifest requires an explicit `OPENUEM_REFERENCE_STATE`, non-root
`OPENUEM_RUNTIME_UID`/`OPENUEM_RUNTIME_GID`, image references, public origin/host,
domain/organization, administrator source networks and generated installation
identity. It never supplies default credentials. Missing bind sources are
errors; Compose must not create replacement input directories.

Prepare the installation secrets, [protocol keys](protocol-keys.md), database
credentials, private service PKI and broker configuration with their actual setup
commands. Retain their provisioning
journals separately from runtime mounts. PostgreSQL receives its administrator
password and database TLS identity; application processes receive only the
application URL and public database trust. Keep the generated `verify-full`
hostname and trust-file path consistent with the manifest.

The dedicated Windows encryption and desktop bootstrap signing keys come from
the retained `protocol-keys` setup command under `protocol/state`. It receives
only a read-only installation foundation and a separate writable output. Runtime
mounts contain the two exported keys; its journal stays outside the console.
The Windows key uses `WINDOWS_MDM_MASTER_KEY_FILE`, preserving canonical Base64
without placing the secret in container environment metadata.

Fresh reference PKI also enables `--administrator-authority`. Its independent
self-signed root has a separate retained key; only
`pki/state/trust/administrator-ca.pem` reaches the console. The administrator CA
key and its journal remain outside every runtime mount. This replaces the former
synthetic administrator trust file in the reference fixture. Administrator client
certificate issuance, account binding and deployed OCSP/status delivery remain
separate work; the first administrator uses the protected password workflow.

Additional inputs include public HTTPS files, approved release public keys and
the release repository. The fixture still generates synthetic versions of these
inputs. Its optional release-image mode then invokes the actual
[release admission job](agent-release-operations.md) against a synthetic signed
manifest and non-executable package. That driver does not obtain public TLS or
produce a natively signed installer.

Use the broker initializer revision pinned by the console workflow. The separate
container test exposed an older initializer grant without `hardware`, `recovery`
and `rotation`; the current worker correctly rejects that configuration. Revision
`e7525ad161cc06323e8cc7573f1d6525379d88a7` includes the current subjects and an exact
grant regression test. The workflow now pins its successor
`633bc7bb0dc34c1240a72a9df25c74ad19451885`, which also supplies the independent
administrator root and a
[reviewed broker upgrade](https://github.com/the-luap/openuem-cert-manager/blob/b06bac13bd0e72f306a87ed119d2f7be66a66063/docs/broker-upgrade.md).
The reference runner invokes its read-only preview against freshly generated
configuration and requires an exact unchanged result before starting services.
The separate upgrade distribution test runs the actual previous initializer and
stock broker, retaining service keys, messages and a durable consumer across
configuration publication and process restart. The
[reference maintenance controller](reference-maintenance.md) now reviews and
resumes that migration across all seven services, retains PostgreSQL and queued
commands, recreates the broker from a frozen definition, and establishes readiness
before publishing its completion receipt. General image upgrades and complete
installation/restore orchestration remain separate work.

Database, JetStream and authentication-log storage are persistent private bind
mounts. The console's temporary cache/PID directory uses a private tmpfs. Every
input mount is read-only, and the gateway and worker cannot read provisioning
directories or another service's seeds. Log retention/rotation, ownership
preparation for the final installer and backup operations remain separate work.

Startup is staged: initialize PostgreSQL, complete authenticated database
bootstrap, establish private broker readiness, initialize the console schemas
and listeners, then start the authorization, command and worker services. These
services deliberately reject an uninitialized registry. The fixture performs
these stages explicitly; the runtime manifest alone is not a setup wizard.

The base manifest is the initialized runtime and has no initial-password mount.
While creating the first administrator, also supply
[`compose.bootstrap.yaml`](../deploy/reference/compose.bootstrap.yaml). It adds
only the protected initial password to the console and selects its file setting.
After the first login and mandatory password replacement, stop the gateway and
console, wait for successful shutdown, then recreate only the console using the
same inputs **without** the bootstrap overlay. Restart the gateway and verify
login with the replacement password. Retain the original installation provisioning
directory for recovery; retiring a runtime mount does not delete that source.

For example, once database and broker startup have completed, the initial console
stage of an existing, explicitly configured project can use:

```sh
docker compose --project-name openuem --project-directory /srv/openuem \
  --env-file /srv/openuem/reference.env \
  --file /opt/openuem/deploy/reference/compose.yaml \
  --file /opt/openuem/deploy/reference/compose.publish.yaml \
  --file /opt/openuem/deploy/reference/compose.bootstrap.yaml \
  up --detach --no-deps console
```

Use the initialized file set, omitting the last `--file`, for the subsequent
console recreation (`up --detach --no-deps --force-recreate console`) and future
operations. Preserve any installation-specific overlays. A first start without
bootstrap material cannot create an administrator; an already initialized
console checks its retained binding and never reloads the initial password.
See [first-administrator bootstrap](first-administrator-bootstrap.md).

## Acceptance fixture

`scripts/check-reference-composition.py` creates a uniquely named temporary
Compose project. It starts the same distribution images under the host's
non-root UID/GID. Its Go probe is compiled from `internal/setup/reference` and
mounted only into separate acceptance clients. No test executable or Docker
socket is added to a service image or runtime mount.

The fixture checks:

- Generated protected inputs and actual TLS database bootstrap.
- Independent administrator public trust from the production PKI initializer,
  with its CA key and provisioning journal excluded from runtime mounts.
- First administrator login and mandatory password replacement through the
  gateway from one admitted client IP, with a separate client denied even when
  it forges the admitted source in forwarding headers.
- Console recreation without the bootstrap password mount or environment setting,
  preserving the original recovery file and successful replacement-password login.
- Public Apple unknown-enrollment rejection, desktop bootstrap-key discovery and
  Windows discovery through their actual private HTTPS listeners.
- With the release image selected, actual private database admission and public
  gateway HEAD, GET and range downloads whose bytes match the signed manifest;
  retained approval after restart and download denial after exact withdrawal.
- In that mode, a release-bound invitation prepared through the production store,
  followed by an actual HTTPS claim from the public edge using the shared endpoint
  client. The client owns and persists its pending certificate and broker keys;
  it receives no database credential, server encryption key, CA key or service seed.
  Repeated metadata GET/HEAD requests and an invalid proof leave the use available.
  A valid claim consumes one use; identical proofs recover the same certificate
  immediately and after the complete restart, while different keys are denied.
  Metadata retains the signed release, exact download target and organization/site.
  Withdrawal denies metadata and claim recovery before device revocation is tested.
- A synthetic scoped identity, the real command provisioner's durable consumer
  reconciliation, and a WSS request through gateway, broker authorization and
  the individual worker that changes only that identity's inventory settings.
- Actual container mount recipients, read-only inputs, absence of raw key/URL
  environment values, network membership, privileges and unpublished ports,
  plus failed direct socket access from the public client to backend addresses.
- Successful joined shutdown and restart of all seven services with retained
  administrator, device, database and JetStream state.
- Revocation of a live WSS session, completed consumer reconciliation and an
  explicit authorization denial when the same endpoint tries to reconnect.
- In maintenance mode, actual old worker-grant rejection, protected review and
  lease handling, interruption after configuration publication, CLI resume with
  retained administrator/device/message state, and a completed retry without
  another container restart.

Without the optional release image, the trusted registry probe still admits the
synthetic device directly. In both modes, inventory is prepared by a trusted
fixture after checking the stored identity's scope and broker key; the fixture
does not run installed-agent reporting. Public protocol claims do not establish
natively signed installer execution, endpoint activation, native Windows MDM,
Apple enrollment or hardware acceptance. These remain separate requirements.

The Linux amd64/arm64 console workflow builds the probe and all required images,
then invokes the runner with explicit image arguments. The runner uses a private
temporary project directory and `/dev/null` as the Compose environment file;
it does not read an installed `.env` or deployment state. Cleanup removes only
the owned project, probe containers and temporary synthetic data.

Local Docker Linux arm64 acceptance passes the complete sequence, including
backend socket denial, retained-state restart and live WSS revocation. The
Windows protected-file/configuration/lifecycle tests, affected Linux/Windows
vet, Windows cross-build, console image audit and manifest/workflow syntax checks
also pass. Native Linux amd64/arm64 CI is required for the committed integration.

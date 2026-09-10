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

Additional inputs include public HTTPS files, independent administrator public
trust, approved release public keys and the release repository. The fixture
generates synthetic versions of these inputs. That driver is an acceptance
fixture, not an ACME, administrator PKI or release provisioner.

Use the broker initializer revision pinned by the console workflow. The separate
container test exposed an older initializer grant without `hardware`, `recovery`
and `rotation`; the current worker correctly rejects that configuration. Revision
`e7525ad161cc06323e8cc7573f1d6525379d88a7` includes the current subjects and an exact
grant regression test. The workflow now pins its successor
`b06bac13bd0e72f306a87ed119d2f7be66a66063`, which also supplies a
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

## Acceptance fixture

`scripts/check-reference-composition.py` creates a uniquely named temporary
Compose project. It starts the same distribution images under the host's
non-root UID/GID. Its Go probe is compiled from `internal/setup/reference` and
mounted only into separate acceptance clients. No test executable or Docker
socket is added to a service image or runtime mount.

The fixture checks:

- Generated protected inputs and actual TLS database bootstrap.
- First administrator login and mandatory password replacement through the
  gateway from one admitted client IP, with a separate client denied even when
  it forges the admitted source in forwarding headers.
- Public Apple unknown-enrollment rejection, desktop bootstrap-key discovery and
  Windows discovery through their actual private HTTPS listeners.
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

The trusted registry probe admits a synthetic device directly through the
registry API. This does not claim a completed public signed-installer claim,
native Windows enrollment, Apple enrollment or hardware operation. Those
protocol, release and physical acceptance requirements remain in the roadmap.

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

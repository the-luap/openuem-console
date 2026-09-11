# Retained reference installation

`scripts/install-reference.py` combines the existing setup images and seven-service
reference definition into a reviewed, resumable installation. It generates the
installation and protocol credentials, database credentials, private service PKI,
independent administrator CA and broker configuration, bootstraps PostgreSQL and
starts the console, broker, authorization service, command provisioner, worker and
gateway. It verifies the first administrator's password replacement before
recreating the console without its initial-password mount.

This workflow uses already available local images, supplied public HTTPS files
and independently obtained release public keys. Automatic DNS/ACME provisioning,
signed image distribution, a graphical setup wizard, general upgrades/rollback,
complete restore orchestration and external/device acceptance remain separate
roadmap requirements. The installer does not issue a public certificate or approve
an agent release on the operator's behalf.

## Prepare the configuration

Use Python 3.10 or newer with OpenSSL partial-chain verification and a local Docker
Unix-socket context with Compose. Run under the non-root account that will own the
private state; the installer uses that account's actual UID/GID for all containers.
Create an empty mode-0700 state directory under a trusted parent. No existing
installation, database directory or unrelated Compose project is adopted.

Save the following configuration as a private mode-0600 file outside that state
directory. Replace the example account paths, domain, VPN network and local image
references. Build compatible images from the same source revisions as the
[native console workflow](../.github/workflows/console-broker.yml); the readiness
image must include the administrator completion mode. The database image uses the
pinned PostgreSQL digest in the reference manifest.

```json
{
  "version": 1,
  "project": "openuem",
  "directory": "/home/openuem/state",
  "domain": "example.com",
  "organization": "Example Organization",
  "public_origin": "https://uem.example.com",
  "administrator": "first-admin",
  "administrator_networks": ["10.42.0.0/24"],
  "access": "public",
  "tls_certificate": "/home/openuem/inputs/server.pem",
  "tls_key": "/home/openuem/inputs/server.key",
  "release_keys": "/home/openuem/inputs/release-keys.pem",
  "images": {
    "installation": "openuem-installation-secrets:local",
    "protocol": "openuem-protocol-keys:local",
    "credentials": "openuem-database-credentials:local",
    "bootstrap": "openuem-database-bootstrap:local",
    "pki": "openuem-private-pki:local",
    "probe": "openuem-reference-probe:local",
    "console": "openuem-console:local",
    "broker": "openuem-broker:local",
    "authorization": "openuem-agent-auth:local",
    "commands": "openuem-agent-commands:local",
    "worker": "openuem-individual-worker:local",
    "gateway": "openuem-gateway:local"
  }
}
```

Inputs use canonical absolute paths under trusted parents. Keep the TLS private
key private and owned by this account or the system administrator. Public
certificate/key files may be readable by other accounts but cannot be writable by
them. Release trust contains one to eight distinct Ed25519 public keys in PKIX PEM
format, obtained from the trusted release pipeline.

The TLS preflight performs an in-memory handshake with the supplied certificate
as an explicit trust anchor. It verifies the pair, configured DNS name, lifetime
and TLS usage without opening a network socket. This does not establish the trust
that external clients need; deploy the appropriate public/enterprise certificate
chain for those clients.

Public mode publishes only gateway TCP 443. The four backend networks are private;
the gateway's source-network policy controls administrator access. Select the
actual VPN or management source networks as observed at the gateway. Source
preservation through the intended ingress/NAT and host firewall behavior still
require deployment acceptance. Isolated acceptance mode uses `"access":"isolated"`
and an HTTPS origin on port 8443; it publishes no port and also makes the edge and
egress networks internal.

## Review and initialize

```sh
python3 scripts/install-reference.py \
  --config /home/openuem/installation.json --check
```

The read-only review reports the exact local image IDs, public TLS/release-key
fingerprints, account-bound directory, source networks and intended publication.
It neither creates installation files nor starts containers. It does not pull
images. Preserve the returned `review_sha256` and apply that exact review:

```sh
python3 scripts/install-reference.py \
  --config /home/openuem/installation.json --apply \
  --expected-review 'COPY_THE_REVIEW_SHA256_HERE'
```

The review binds the configuration, local daemon, runtime account, state directory
identity, input bytes, source templates and resolved image IDs. Changed input,
template or image references require investigation; an old review cannot silently
authorize different state. Actual Compose operations use retained rendered
definitions with exact image IDs, protected mounts and literal-dollar escaping.
Environment-selected Compose files and runtime credentials are not inherited.

The first successful run returns `awaiting-administrator`, the public origin,
account name and private initial-password file path. It never prints the password
or other generated secrets. From an admitted management network, open the origin,
sign in using the generated password through your normal credential-handling
process, and complete the mandatory password replacement. Run the same apply
command again.

The [read-only administrator check](first-administrator-bootstrap.md#read-only-setup-completion)
must then succeed. The controller cleanly stops gateway and console, recreates the
console without bootstrap password access, and rechecks service readiness before
recording `complete`. The original provisioning material remains available for
recovery. A completed retry returns `already-complete` without restarting anything;
this is a retained completion receipt, not a new health assessment or an upgrade.

## Interruption and retained state

The private `.setup` directory contains the review, frozen Compose definitions,
exclusive lease and ordered progress records. Completed provisioning stages record
the exact retained files. Missing, altered, aliased, unexpectedly public or
noncanonical state is rejected without regenerating keys or resetting accounts.
Empty lock files from the underlying PKI provisioner are retained and verified.

Setup jobs have explicit project/review/specification labels and retained process
identities. If the controller is interrupted, rerun the same command. A still
running job is joined before another process can start; an observation timeout
does not mean the job stopped. Only a verified terminal failed job may be replaced,
using its existing protected output and journal. Containers and networks belonging
to another review are not adopted.

The controller can resume around bootstrap console replacement, including a
replacement already created before its progress record or a console absent during
that transition. It validates existing resources before starting or creating
services, and can restart the retained database after a clean stop. An unexpected
failure closes the owned public gateway while preserving private services, data
and unfinished jobs. A competing controller that cannot acquire the lease makes
no service changes.

This is fresh-install recovery under the same review. It does not replace the
[broker maintenance operation](reference-maintenance.md), image updates, key/CA
rotation or restoration into a different state directory.

## Acceptance

`scripts/check-reference-installation.py` creates a uniquely named private project
with synthetic TLS/release inputs and the distribution images. It exercises the
actual check/apply commands, wrong-review rejection, real first login/password
replacement, protected bootstrap retirement and completed retries. Its interruption
mode terminates a live controller after retained PKI generation, resumes through
the CLI, and checks that the original credentials and authorities are preserved.
It also exercises stopped-database recovery and interruption around console
replacement. Cleanup removes only the owned test containers, networks and data.

`tests/setup/test_reference_installation.py` covers review and lease boundaries,
retained artifact loss, journal integrity, public-key shape, foreign job state and
joining a live job after an observation timeout. The separate full reference
composition continues to test source-network denial, public enrollment/downloads,
broker maintenance, retained commands and live WSS revocation. Neither fixture
executes a native installer, contacts a real provider or proves hardware acceptance.

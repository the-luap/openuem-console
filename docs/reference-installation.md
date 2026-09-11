# Retained reference installation

`scripts/install-reference.py` combines the existing setup images and seven-service
reference definition into a reviewed, resumable installation. It generates the
installation and protocol credentials, database credentials, private service PKI,
independent administrator CA and broker configuration, bootstraps PostgreSQL and
starts the console, broker, authorization service, command provisioner, worker and
gateway. It verifies the first administrator's password replacement before
recreating the console without its initial-password mount.

This workflow uses already available local images, supplied public HTTPS files or
automatic DNS-01 issuance, and independently obtained release public keys.
Signed image distribution, a graphical setup wizard, general upgrades/rollback,
complete restore orchestration and external/device acceptance remain separate
roadmap requirements. Release approval remains an independent operation.

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

For automatic public TLS, use configuration version `2`, remove `tls_certificate`
and `tls_key`, and add this field. Keep all other fields and the twelve role images
from the version-1 example:

```json
"public_tls": {
  "configuration": "/home/openuem/inputs/issuer",
  "image": "openuem-acme:local"
}
```

The image must support the [issuer input check](gateway-acme.md). Create the
external configuration directory with mode 0700. It contains private `issuer.json`
and `provider.json`, plus only their explicitly referenced files. Configure the
same public HTTPS hostname, ACME directory, contact, explicit terms acceptance and
DNS provider. Use these fixed container paths:

| Issuer setting | Required value |
| --- | --- |
| `provider_environment_file` | `/run/openuem-acme/provider.json` |
| `state_directory` | `/var/lib/openuem-acme` |
| `publication_directory` | `/var/lib/openuem-public-tls` |

Provider `_FILE` values and optional `acme_roots_file` must name separate flat files
inside `/run/openuem-acme/`; use mode 0600 for credentials. The installer retains
these exact inputs in `acme/config/`. It creates `acme/state/` for the original ACME
account and `public/` for the publication. Its separate `<project>-public-tls`
service owns only those mounts and an outbound network. It receives no private
backend network or credentials and publishes no port. Only the public directory
is shared read-only with the gateway.

The first successful DNS-01 attempt must publish a matching, valid certificate
before private provisioning continues. The controller then starts the retained
renewal service and selects the gateway's atomic-publication overlay. The gateway
checks for reloads once per minute; renewal uses the configured issuer interval.
No TCP 80 listener is required. Provider authorization, reachable
DNS/ACME services and client trust in the issued chain remain deployment inputs.

The issuer image must also provide the private readiness socket and `--ready`
probe. Its Docker health check validates the active service's original state,
account and valid published TLS. The installer requires this positive result
after startup and before marking setup complete. No additional host port or
readiness credential is created.

Public mode publishes only gateway TCP 443. The four backend networks are private;
the gateway's source-network policy controls administrator access. Select the
actual VPN or management source networks as observed at the gateway. Source
preservation through the intended ingress/NAT and host firewall behavior still
require deployment acceptance. Isolated acceptance mode uses `"access":"isolated"`
and an HTTPS origin on port 8443; it publishes no port and also makes the edge and
egress networks internal. With version 2, the issuer network is also internal;
the issuer's canonical HTTPS origin still uses the hostname without port 8443.

## Review and initialize

```sh
python3 scripts/install-reference.py \
  --config /home/openuem/installation.json --check
```

The read-only review reports the exact local image IDs, public TLS/release-key
fingerprints, account-bound directory, source networks and intended publication.
Version 2 reports the directory URL and provider instead of a certificate
fingerprint before issuance; afterward it reports the retained initial certificate
fingerprint. Its bounded issuer checker runs without networking
or writable mounts and is removed afterward. Neither mode creates installation
files, starts provisioning or pulls images. Preserve the returned `review_sha256`
and apply that exact review:

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

Version 2 also joins an interrupted initial issuer process before starting
renewal. A failed provider attempt retains the original account for retry. The
account key and matching account/publication identity bindings become immutable
provisioning anchors; renewed certificate generations are deliberately excluded
from that snapshot. A missing original account key is rejected, including after
a failed first attempt. Keep external inputs available and unchanged until setup
completes. Completed receipts no longer read those external files; the renewal
service uses the protected retained configuration.

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

Passing both `--acme-image` and `--acme-fixture-image` exercises version 2 against
separate local Pebble/DNS containers. The fixture uses an explicitly allocated,
reviewed test network and the real issuer executable. It verifies DNS TXT creation,
validation and cleanup, the gateway's chain against fixture CA trust, the retained
renewal container and unchanged completed retries. With `--interrupt`, it also
rejects a missing original account key after a provider failure and interrupts the
actual controller during a held DNS request before joining the same live issuer
process. No preissued certificate is substituted into installation state.

`tests/setup/test_reference_installation.py` covers review and lease boundaries,
retained artifact loss, journal integrity, public-key shape, protected issuer inputs,
paired account identities, foreign job state and joining a live job after an
observation timeout. The separate full reference
composition continues to test source-network denial, public enrollment/downloads,
broker maintenance, retained commands and live WSS revocation. Neither fixture
executes a native installer, contacts a real provider or proves hardware acceptance.

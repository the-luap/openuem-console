# Automatic public gateway certificates

`openuem-acme` obtains and renews the gateway's public certificate through DNS-01.
It uses the pinned lego v5.4.1 executable, retains one ACME account and publishes
validated certificate generations atomically. The gateway reloads the published
pair without restarting existing connections. The issuer opens no inbound port.

This is the public TLS component of NET-01. The complete private backend,
firewall and installer composition remains separate work. No public CA account,
real DNS credentials or live device was used for the automated acceptance below.

## Image and configuration

Build from this repository:

```sh
docker build -f Dockerfile.acme --target runtime -t openuem-acme:local .
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges openuem-acme:local --help
```

The runtime is `scratch`, UID/GID `65532:65532`, with the issuer, lego, system CA
bundle and lego license. It has no shell, test server, source tree or baked-in
credentials. The builder and lego image are pinned by version and digest in
[Dockerfile.acme](../Dockerfile.acme). Distribute the runtime target, not `smoke`.

The [Compose component](../deploy/acme/compose.yaml) expects an existing absolute
host directory selected by `OPENUEM_ACME_ROOT`, containing:

| Host path | Container use | Required access |
| --- | --- | --- |
| `config/issuer.json` | Operator configuration | Issuer read-only, mode 0600 |
| `config/provider.json` | Explicit DNS provider environment | Issuer read-only, mode 0600 |
| `config/dns-update-secret` | Example provider secret file | Issuer read-only, mode 0600 |
| `state/` | ACME account, client state, identity binding and status | Issuer read/write, mode 0700 |
| `publication/` | Gateway TLS generations, selection and installation metadata | Issuer read/write; gateway read-only, mode 0700 |

Provision these directories and files for UID/GID 65532 on the deployment host.
The component refuses to create missing bind-mount sources. All private files
must be regular, have one hard link, and be owned by the issuer UID or root;
the process must also be able to read them. A root-owned mode-0600 file is not
readable by the unprivileged container. Do not broaden secret permissions to
work around a mismatched host UID. Protect parent directories against writes
by other users. Use native local filesystems with locking, atomic rename and
directory fsync; network filesystems are outside the verified deployment.

Copy [issuer.example.json](../deploy/acme/issuer.example.json) and replace its
reserved domain and email. Select your ACME directory and explicitly set
`accept_terms` to `true` only after accepting that service's terms. The example
starts with `false`, so an unchanged example cannot issue a certificate.
The public origin is one canonical HTTPS DNS hostname, optionally port 443;
wildcards, IP origins and additional domains are not supported.

Select a provider supported by the pinned lego release. The supplied
[RFC 2136 example](../deploy/acme/provider.rfc2136.example.json) uses the v5
`dnsupdate` provider and a separate TSIG secret file. Replace its documentation
address, update-key name and secret with the existing DNS service's values.
Authorize that key only for the required challenge records where the provider
supports such restrictions. Provider credentials are JSON string values in
`provider.json`; they are never command arguments. Supported `_FILE` variables
refer to private absolute paths within the issuer's mounts. The provider
environment is reloaded before each attempt, allowing credential-file rotation.
[Pinned provider configuration](https://github.com/go-acme/lego/blob/v5.4.1/providers/dns/dnsupdate/dnsupdate.toml),
[DNS provider catalog](https://go-acme.github.io/lego/dns/).

The child receives only that explicit environment and the optional pinned ACME
trust file. Ambient credentials, proxy variables, loader overrides and `LEGO_*`
configuration are excluded. Manual DNS challenges are rejected. Providers needing
host tools, an interactive login, daemonized helpers or an inherited home directory
are unsuitable for this runtime. The application does not provision DNS accounts.
External account binding and ACME account-key rollover are not implemented.

Optional configuration fields are:

| Field | Meaning |
| --- | --- |
| `dns_resolvers` | Up to four explicit numeric IP:port recursive resolvers |
| `acme_roots_file` | Protected PEM trust file for a private ACME HTTPS endpoint |
| `certificate_profile` | ACME certificate profile supported by the selected CA |
| `check_interval` | Normal check interval; default 6h, allowed 1m–12h |
| `attempt_timeout` | Maximum client attempt; default 15m, allowed 10s–30m |

The ACME HTTPS endpoint is always verified. Custom ACME roots replace the client's
default system roots. This does not change gateway backend trust. Outbound access
is needed to the chosen ACME service, DNS provider and DNS resolvers/authoritative
servers. Lego also uses the container's system resolver for authoritative server
addresses; configure working container DNS even when `dns_resolvers` is set.
No HTTP-01 or TLS-ALPN-01 listener or port-80 mapping is needed.

## First issuance and gateway handoff

After preparing and reviewing the configuration on the deployment host:

```sh
export OPENUEM_ACME_IMAGE=openuem-acme:local
export OPENUEM_ACME_ROOT=/srv/openuem-acme
docker compose -f deploy/acme/compose.yaml config --quiet
docker compose -f deploy/acme/compose.yaml run --rm acme \
  --config /run/openuem-acme/issuer.json --once
```

Start the gateway only after this command succeeds. Mount the entire host
`publication/` directory read-only at `/run/openuem-public-tls` in the gateway,
using the same UID. Do not bind-mount the individual `current` files: that can
pin old inodes and prevent renewal from becoming visible. Add these flags to
the gateway's already configured private-backend and administration arguments:

```text
--tls-cert /run/openuem-public-tls/current/fullchain.pem
--tls-key /run/openuem-public-tls/current/private.pem
--tls-reload-interval 1m
```

Then run the issuer continuously:

```sh
docker compose -f deploy/acme/compose.yaml up -d acme
```

The issuer has no published ports. Only the gateway maps external TCP 443 to its
unprivileged HTTPS listener. The gateway receives neither `state/` nor `config/`.
Its private backend CA and client certificate remain separate mounts; see
[gateway operation](gateway-operations.md) and [gateway image](gateway-container.md).

The daemon checks immediately, then adds up to 20% jitter to the normal interval.
It shortens checks for short-lived certificates and applies retry backoff after
issuance failures. Lego's normal renewal and ACME Renewal Information (ARI)
decisions remain enabled. No unconditional force-renew flag is used.
[Pinned renewal implementation](https://github.com/go-acme/lego/blob/v5.4.1/cmd/cmd_run_renew.go).

## Publication, failure and recovery

Each successful result is validated for hostname, matching private key, complete
PEM, ordered chain, server usage and certificate lifetime. Files are written and
synced in a new private generation directory before an atomic relative `current`
symlink switch. An unchanged certificate does not create a retained generation.
Ordinary failed attempts remove only their own unpublished staging directory.
Five recent complete generations are retained, plus the selected generation when
necessary. Automatic cleanup leaves interrupted, unfamiliar or modified folders
for operator inspection. A directory exceeding the bounded retention scan stops
the issuer instead of recursively deleting unfamiliar data.

Two permanent file leases exclude competing issuers. Both volumes carry the
same installation UUID and exact origin, ACME directory, contact email and DNS
provider binding. An existing publication cannot be paired with an empty or
unrelated account volume. Once an account key exists, its fingerprint is retained
even if the first DNS challenge fails. A missing, replaced or corrupt bound key
stops the issuer before lego can generate an automatic replacement. The
registration may be recovered using the retained original key; the issuer does
not authorize account-key replacement.

Back up `state/` and `publication/` as a consistent pair while the issuer is
stopped, and separately protect the operator configuration and DNS credentials.
Preserve ownership, permissions, immutable metadata and relative symlinks during
restore. Do not delete binding or lock files to bypass an error. If initial
binding was interrupted between its two durable writes, inspect and restore the
matching pair before retrying. Staging and production use separate roots and
bindings; switch the gateway only to a successfully issued production root.

`state/status.json` records the last attempt, fixed phase and optional public
generation metadata. Logs contain fixed states and expiry times, never raw DNS
provider output, account identifiers or private keys. Monitor the selected
certificate's expiry and the age/phase of status, including failed publication or
retention. DNS/API failures preserve the selected pair; they do not extend its
validity. The gateway rejects new handshakes after the loaded chain expires.
SIGTERM stops the daemon, terminates the owned client process group, reaps its
leader and releases leases. The Compose component uses a small init process to
reap orphaned descendants. Providers must remain inside that process group.

## Automated acceptance

The unit/race suite covers exclusive leases, concurrent calls, root replacement,
ambiguous JSON, partial output, invalid keys, account loss, paired restore,
unchanged output, bounded retention, cancellation and immediate child exit.

The separate smoke image runs the actual issuer executable, pinned lego and
pinned Pebble v2.10.1 against a synthetic DNS server on loopback. DNS validation
remains enabled. It checks provider failure, successful DNS-01, TXT cleanup,
original account-key reuse, server-requested ARI renewal, gateway TLS reload and
SIGTERM/restart. The image is read-only and unprivileged, with no external network:

```sh
docker build -f Dockerfile.acme --target smoke -t openuem-acme-smoke:local .
docker run --rm --network none --dns 127.0.0.1 --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 128 --memory 256m \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=32m openuem-acme-smoke:local
```

The [dedicated workflow](../.github/workflows/acme-issuer.yml) runs this fixture
on native Linux amd64 and arm64 and requires an explicit test pass, not a skip.
It also checks that the runtime exposes no port and contains no shell, test server
or credential material. Live provider access, production issuance, network/firewall
composition and operational alert delivery still require deployment acceptance.
[Pebble test server](https://github.com/letsencrypt/pebble/tree/v2.10.1).

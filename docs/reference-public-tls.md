# Public TLS issuance and renewal for the reference composition

The reference composition can consume the DNS-01 issuer's atomic publication
directly. The [gateway overlay](../deploy/reference/compose.acme.yaml) selects
`/run/public/current/fullchain.pem` and `private.pem` within its existing read-only
public directory mount. Its other routes, backend identities and administrator
source restrictions stay in the reference definition.

The [issuer component](../deploy/reference/compose.issuer.yaml) runs under a
separate Compose project. It uses the same explicit non-root UID/GID, has no
published port, and joins only its own outbound network. The seven reference
services never receive its account or DNS provider configuration. Only the issuer
can write the publication; the gateway reads that complete directory so renewed
generations remain visible without container replacement.

This is a configuration option for a newly provisioned reference composition.
The [reviewed installation controller](reference-installation.md) currently
accepts supplied TLS files. Its automatic DNS-01 orchestration remains separate
work; do not change its frozen configuration or provisioning journal to select
this layout.

## Prepare the issuer

Use the [protected issuer configuration](gateway-acme.md) and a runtime image that
supports `--check`. Keep the normal reference account and state variables:

```sh
export OPENUEM_REFERENCE_STATE=/srv/openuem
export OPENUEM_RUNTIME_UID="$(id -u)"
export OPENUEM_RUNTIME_GID="$(id -g)"
export OPENUEM_ACME_IMAGE=openuem-acme:local
```

Prepare these private directories with mode 0700 and matching ownership:

| Reference path | Purpose |
| --- | --- |
| `acme/config/` | Read-only issuer JSON, provider JSON and referenced credential files |
| `acme/state/` | Retained account, client state, identity binding and status |
| `public/` | Atomic public TLS publication shared read-only with the gateway |

Start with empty account and publication directories. Copy the
[issuer configuration example](../deploy/acme/issuer.example.json) to
`acme/config/issuer.json`, then configure the public HTTPS origin, directory URL,
contact and provider. Explicitly accept the selected service's terms before
enabling issuance. Use the fixed container paths from that example:
`/run/openuem-acme/provider.json`, `/var/lib/openuem-acme` and
`/var/lib/openuem-public-tls`. Provider `_FILE` inputs and optional ACME trust must
be readable through the configuration mount. Protect secret files with mode 0600.

The issuer needs outbound access to the configured ACME/DNS services and working
DNS resolution. It opens no HTTP-01 listener and requires no public TCP 80 mapping.

## Check, issue and connect the gateway

Use a distinct project name for the issuer throughout its lifecycle:

```sh
docker compose --project-name openuem-public-tls \
  --file deploy/reference/compose.issuer.yaml \
  run --rm --no-deps acme --config /run/openuem-acme/issuer.json --check

docker compose --project-name openuem-public-tls \
  --file deploy/reference/compose.issuer.yaml \
  run --rm --no-deps acme --config /run/openuem-acme/issuer.json --once

docker compose --project-name openuem-public-tls \
  --file deploy/reference/compose.issuer.yaml up --detach acme
```

Require successful initial issuance before starting the gateway. Retain both
issuer volumes and their bindings after a failed attempt; do not delete them to
retry. Input preflight alone does not prove provider authorization or successful
issuance. The normal issuer command performs the account and publication checks.

Include `deploy/reference/compose.acme.yaml` in every reference Compose operation
and in the staged provisioning/startup sequence from
[reference composition](reference-composition.md). Combine it with the initial
bootstrap overlay only while the first administrator still requires the initial
password, and with the publication overlay when exposing gateway TCP 443:

```sh
docker compose --project-name openuem \
  --file deploy/reference/compose.yaml \
  --file deploy/reference/compose.acme.yaml \
  --file deploy/reference/compose.publish.yaml config --quiet
```

The default public TLS reload interval is one minute.
`OPENUEM_PUBLIC_TLS_RELOAD_INTERVAL` can select a value from one second to one hour.
The issuer publishes a complete generation before switching its relative `current`
link; a failed reload retains the prior valid pair. New handshakes still reject
expired certificates. Existing connection continuity is covered by the gateway
and issuer component tests.

Pass the same ACME gateway overlay to the
[reference maintenance controller](reference-maintenance.md). Readiness resolves
the selected bounded generation and mounts only its public certificate chain into
the probe. It rejects mixed TLS paths, escaping selections and aliased certificate
files. The probe receives no publication private key or issuer configuration.

Back up account and publication as a consistent pair while the issuer is stopped,
and protect the provider configuration separately. Preserve the selected relative
link and private permissions. General installation restore and automated installer
handoff remain separate roadmap requirements.

## Acceptance scope

`scripts/check-reference-public-tls.py` checks the actual issuer component's
account, mount and network boundaries using a uniquely named isolated project.
Its actual `--check` invocation preserves the empty account/publication volumes
and protected configuration; it contacts no provider.

The full reference fixture's `--acme-publication` option uses synthetic certificate
generations to exercise publication selection, gateway TLS reload, retained
container identities and maintenance readiness. The separate issuer smoke test
uses actual lego and Pebble DNS-01, including issuance, retained account retry,
ARI renewal and gateway reload. These are separate acceptance layers; they do not
claim production-provider, firewall or physical-device acceptance.

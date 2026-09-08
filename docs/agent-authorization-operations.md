# Individual agent authorization service

`cmd/openuem-agent-auth` runs connection authorization and durable revocation for
the individual-agent broker. It requires the PostgreSQL registry to have been
initialized by enrollment setup. It does not run schema migrations or load an
organization CA key or enrollment encryption master key.

This executable is one part of desktop integration. Signed installers, console
issuance, endpoint storage/renewal and a complete reference deployment are still
required; running this process does not enable those features.

## Broker prerequisites

Use NATS Server 2.14.6 with a dedicated individual-device account. Do not place
legacy shared agent credentials in that account. Configure these separate users:

| Account/user | Permission |
| --- | --- |
| `UEM_AUTH` authorization NKey | Subscribe to `$SYS.REQ.USER.AUTH`, publish only one temporary response per received request |
| `UEM_SYSTEM` revocation NKey | Publish `$SYS.REQ.SERVER.*.KICK`, subscribe `_INBOX.>` |
| `UEM_DEVICES` | Dynamic individual grants issued by authorization; trusted workers use separate service credentials |

The auth callout's issuer is the **public account NKey** matching the service's
issuer seed, its account is `UEM_AUTH`, and its allowed account is `UEM_DEVICES`.
In config mode, `auth_users` is the callout bypass list: include the authorization
user and all statically configured trusted service NKeys (worker, console,
provisioner and revocation service). They still authenticate by NKey and retain
only their configured account permissions. Otherwise a worker in `UEM_DEVICES`
is sent to the device registry and rejected. Never add individual device keys to
this list. Set the system account to `UEM_SYSTEM`.
A configured NKey service user is required for the stock server to
send a nonce; merely adding `auth_callout` does not enable nonce authentication.

Keep native broker TLS and monitoring listeners private. The existing gateway's
exact `/agent-channel` route forwards WSS to the broker over mutual TLS. A
forwarded certificate header does not authenticate an individual agent to NATS.

## Process configuration

Build with `go build ./cmd/openuem-agent-auth`. Supply the database connection URL
through `OPENUEM_AGENT_DATABASE_URL` in the service's protected environment, rather
than a command-line argument. Start the binary with protected service key files:

```sh
openuem-agent-auth \
  --broker-urls tls://broker.internal:4222 \
  --broker-ca /run/openuem/broker-ca.pem \
  --issuer-key-file /run/openuem/authorization-issuer.seed \
  --auth-key-file /run/openuem/authorization-user.seed \
  --system-key-file /run/openuem/revocation-user.seed \
  --health-listen 127.0.0.1:1326
```

The issuer file contains an account NKey seed. The other files contain different
user NKey seeds. On Unix, private files must belong to the current service user
or root and have no group/other permissions. On Windows, file ownership and every
effective allow ACE must be restricted to the service user, LocalSystem or local
Administrators. Broad inherited permissions are rejected. Windows ACL checks are
tested on a native Windows runner, in addition to Unix permission tests.

If the private broker requires client TLS certificates, also set
`--broker-client-cert` and `--broker-client-key`. The TLS private key has the same
file protection requirements. Certificate verification is always enabled. URLs
must use `tls://`, contain no credentials, path, query or fragment, and are limited
to 16 explicit origins. Broker discovery cannot change the configured origins.

Only the health listener may use HTTP, and it is restricted to a numeric loopback
address. `GET /healthz` returns 204 when both broker connections and PostgreSQL are
available, or 503 while a dependency is unavailable. Responses disable caching.
Forward this status through a private monitoring agent if needed.

## Failure and revocation behavior

Authorization uses at most 32 concurrent requests and grants at most five minutes
or the remaining device certificate lifetime. Each successful grant records the
broker server ID and connection ID in the same identity-locking protocol used by
revocation. A database or authorization outage denies new device connections.

Every two seconds, the service attempts up to 32 pending disconnections, with at
most eight simultaneous one-second broker requests. It retries uncertain results
until the original grant expires. Work survives process restarts, and expired
session records are removed. A broker outage withdraws readiness and triggers
reconnection. Messaging/permission errors stop the service so a supervisor can
restart it; logs contain generic state messages rather than credentials or raw
broker errors. SIGINT/SIGTERM cancels in-flight authorization and closes both
connections and the health listener.

## Automated evidence

`internal/desktop/authservice` has a race-tested lifecycle fixture using a real
TLS/WSS NATS server and an isolated PostgreSQL schema. It verifies trusted TLS,
individual authentication, persisted connection IDs, active disconnects following
revocation, denied reconnection, readiness during broker loss, and graceful
shutdown. The fixture requires `AGENT_ENROLLMENT_TEST_DATABASE_URL`; the console CI
sets it and runs the test. These tests are synthetic endpoint evidence, not
physical Windows/Mac or deployment/firewall acceptance.

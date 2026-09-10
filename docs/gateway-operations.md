# Native HTTPS gateway

The gateway implements Apple/administrator routing, an optional native-agent
WSS route and bounded desktop enrollment/download routes for NET-01 and SEC-01.
It is not yet the complete one-port distribution:
production installer integration,
Windows MDM routes, automated certificate provisioning, rate limits and a complete
reference deployment remain open in [implementation status](implementation-status.md).

## Implemented trust boundary

`cmd/openuem-gateway` terminates public TLS and connects to private console,
certificate-authentication and Apple listeners using a dedicated gateway client
certificate. Each backend explicitly pins the entire gateway leaf certificate.
Trusting the general agent or organization CA as a gateway authority is insufficient.

The gateway replaces incoming certificate headers with the actual TLS peer leaf.
The backend accepts this assertion only after TLS proof of possession of an
explicitly pinned, currently valid gateway credential. Apple additionally checks
the issued device certificate's exact stored fingerprint, expiry, revocation and
device binding. Certificate login additionally validates its internal CA, account
and certificate-specific, fresh OCSP response. The gateway identity itself is
never treated as the end-device or administrator identity.

The transport uses [RFC 9440 Client-Cert encoding](https://www.rfc-editor.org/rfc/rfc9440.html).
The gateway handles TLS possession; the appropriate backend validates end-client
trust and authorization. It sends no client-certificate chain header because
current device/admin identities are issued by a known backend authority.

With gateway trust configured, **every backend request requires the gateway**,
including anonymous enrollment and login pages. The TLS handshake rejects missing
and unrelated client certificates, and every HTTP request rechecks the pin and
expiry. Copying a public certificate or a captured `Client-Cert` value cannot
satisfy the gateway's TLS proof of possession.

## Public route policy

The current public allowlist contains only:

- `GET` and `HEAD /mdm/apple/enroll/<43-character invitation>` for instructions/status
- `POST /mdm/apple/enroll/<43-character invitation>` for confirmed claims/downloads
- `PUT /mdm/apple/<canonical UUID>/checkin`
- `PUT /mdm/apple/<canonical UUID>/connect`
- `GET` and `POST /mdm/apple/<canonical UUID>/scep` for [initial SCEP enrollment](apple-scep-enrollment.md)
- `GET` and `POST /mdm/apple/<canonical device UUID>/scep/<canonical renewal UUID>` for [authorized identity renewal](apple-identity-renewal.md)
- `GET /agent-channel` only as a validated native WebSocket upgrade when an
  explicit private agent backend is configured
- `GET` and `HEAD /enroll/desktop/<canonical token>/metadata`, and
  `POST /enroll/desktop/<canonical token>/claim`, when `--desktop-url` is configured
- `GET` and `HEAD /enroll/desktop/bootstrap-keys` and
  `/enroll/desktop/<canonical token>/configuration`, when `--desktop-url` is configured
- `GET` and `HEAD /enroll/desktop/releases/<release digest>/<platform>/<architecture>`
  when `--desktop-url` is configured; exact supported targets and no query parameters
- `GET`, `HEAD` and `POST /EnrollmentServer/Discovery.svc`, when `--windows-url` is configured
- `POST /EnrollmentServer/Policy.svc`, `/EnrollmentServer/Enrollment.svc` and
  `/mdm/windows/syncml`, when `--windows-url` is configured; no query parameters or path aliases

See [native Windows operations](native-windows-operations.md) for its optional
private listener, pinned gateway identity and durable schedule worker.

See [desktop protocol operations](desktop-public-protocol.md) for its independent
private TLS listener, JSON proof, separate configuration/release signatures, read-only downloads,
rate/concurrency limits and bounded transfer deadlines. Its invitation landing
page and native bootstrap/installer integration remain open.

Everything else requires an explicitly configured administrator source network,
including `/login`, `/auth`, `/admin`, `/tenant/...`, `/devices`, `/computers`,
`/profiles`, `/deploy`, assets and future management APIs. Unsupported device
routes are not implicitly public. Noncanonical paths and a Host different from the
configured public origin are rejected.

Administrator network checks use the TCP connection's source address, never
`Forwarded`, `X-Forwarded-For` or `X-Real-IP`. Connect this gateway directly to the
public/VPN network. Placing another forwarding proxy or source-NAT device before
it changes the observed source and requires a separate, reviewed design. Do not
allow the NAT/proxy address merely to make administrator access work. Both IPv4
and IPv6 are supported; an all-addresses `/0` administrator network is rejected.

Public Apple access still requires device authentication after the public route
check. Responses use `Referrer-Policy: strict-origin` to omit paths and tokens
while preserving the `Origin` header on native forms. Gateway-generated errors
contain no upstream URLs, invitation tokens or certificate contents. This process
has no access log that records token-bearing request URLs.

## Configuration

Build with the repository's pinned toolchain:

```sh
go build -trimpath -o openuem-gateway ./cmd/openuem-gateway
```

Provide the following existing credentials until automated PKI setup is delivered:

1. A public HTTPS certificate/key for the canonical hostname.
2. Valid backend server certificates whose DNS names match the configured private
   HTTPS origins, and their trusted CA bundle.
3. A dedicated gateway client-auth leaf certificate/key. Protect its private key
   as a server credential. Do not use an administrator, enrolled device or CA key.
4. A separate PEM bundle containing only the explicitly trusted gateway public
   leaf certificates, mounted read-only into the console process.

Set these environment variables on the **console process**, covering all three
listeners:

```sh
OPENUEM_TRUSTED_GATEWAY_CERTIFICATES=/run/openuem/gateway-leaves.pem
OPENUEM_PUBLIC_ORIGIN=https://uem.example.org
APPLE_MDM_LISTEN_ADDR=:1325
```

The canonical origin controls certificate/password/2FA redirects. Use the same
origin in Apple organization settings and the gateway's `--public-origin`.
Configure OIDC's registered callback for that origin through existing OIDC settings.
Legacy reverse proxies on a nonstandard public port must set the explicit public
origin; login redirects no longer derive their target from an arbitrary Referer.

Run the gateway, substituting actual paths and private server names:

```sh
./openuem-gateway \
  --listen :443 \
  --public-origin https://uem.example.org \
  --tls-cert /run/openuem/public-chain.pem \
  --tls-key /run/openuem/public-key.pem \
  --gateway-cert /run/openuem/gateway-client.pem \
  --gateway-key /run/openuem/gateway-client-key.pem \
  --backend-ca /run/openuem/backend-roots.pem \
  --apple-url https://console.internal:1325 \
  --console-url https://console.internal:1323 \
  --auth-url https://console.internal:1324 \
  --admin-networks 10.42.0.0/16,fd12:3456:789a::/48
```

Publish only this listener. Keep console/auth/Apple backend ports, PostgreSQL,
NATS/workers and monitoring inside the private network. For an unprivileged
container, listen internally on 8443 and map public 443 to it. Do not publish the
backend ports. Network isolation is additional protection; the application also
rejects direct access when gateway mode is configured.

Only HTTPS backends with normal server certificate verification are accepted.
The gateway ignores outbound HTTP proxy environment variables for these internal
connections. It imposes header/read/write/idle timeouts and shuts down gracefully
on SIGINT/SIGTERM. Upgraded agent streams have their HTTP deadlines cleared and
are tracked explicitly: shutdown closes them because ordinary HTTP server shutdown
does not close hijacked connections.

In direct mode, leave `OPENUEM_TRUSTED_GATEWAY_CERTIFICATES` unset. Apple and admin
certificate login then require the actual end-client TLS certificate and cannot
use a forwarded header. A missing, invalid, empty or expired **configured** trust
bundle is a startup error, not a reason to fall back to direct mode.

## Native agent WebSocket route

Set `--agent-url https://nats.internal:8443` to enable the exact `/agent-channel`
route. This value is a private HTTPS origin, without a path, query or credentials;
the public agent endpoint is `wss://uem.example.org/agent-channel`. Leaving the
option empty keeps the route disabled. `--agent-connection-limit` defaults to
4096 and bounds concurrent upgrades and streams (accepted range: 1–65536).

Only HTTP/1.1 GET with a valid WebSocket upgrade/key/version reaches this backend.
Queries, request bodies, browser Origin, cookies, HTTP authorization and subprotocol
headers are rejected. Browser applications are not supported on this native-agent
route. Malformed requests do not fall through to an administrator backend. The
backend still authenticates each device with individual NKey nonce proof; a
successful WebSocket upgrade alone grants no NATS permissions.

Configure the private NATS WebSocket listener to require the dedicated gateway
TLS identity using its explicit leaf trust, without certificate-to-user mapping.
The gateway's certificate must not grant an agent or worker account. Configure
individual broker authorization and scoped subjects separately as described in
[desktop enrollment](desktop-enrollment-plan.md). End-client certificate headers
are removed for this route; they cannot replace end-to-end NKey possession proof.
Do not point this route at the upstream shared-agent broker configuration.

HTTP deadlines do not limit an upgraded stream. The broker must enforce its short
authentication timeout and expiring authorization grants, while agents use protocol
pings, private reply inboxes and reconnect only through the configured public path.
The gateway does not perform broker identity lookup or certificate renewal itself.

## Rotation

To rotate the gateway credential with overlap, place both valid public leaf
certificates in the backend bundle and restart all console replicas. Then switch
the gateway to the new certificate/key. Finally remove the old public leaf and
restart the backends. Removing its pin denies the old identity even when its CA
and expiry are otherwise valid. Do not remove the last working pin before the
replacement gateway can connect. Bundles are read at startup; editing a mounted
file alone does not reload trust in an existing process.

This is gateway credential rotation, not yet the device/CA/encryption-key rotation
and backup/restore workflow required by PKI-01.

## CSRF and authentication

The common router now issues a secure, HTTP-only `__Host-openuem-csrf` cookie.
HTMX sends the rendered token in `X-CSRF-Token`; ordinary forms submit a `csrf`
body field. Native forms are limited to 4 MiB before token extraction; large
HTMX uploads retain the configured global upload limit. Cookie-only requests and
query-string tokens fail. Cross-origin
mutations are denied even with a token. Fetch Metadata cannot bypass token
validation. Reload open pages after an upgrade from the former `_csrf` cookie.

The HTTP error renderer preserves error status codes, including 403 for denied
mutations. The gateway's network restriction is complemented by persisted
[console roles and organization/site permissions](access-control.md). Native
Apple actions enforce scoped capabilities; desktop routes currently require a
global server administrator while their individual scope checks are audited.

## Verification boundaries

Automated tests cover real frontend/backend TLS, gateway leaf pinning and overlap,
missing/wrong gateway credentials, copied certificate headers, direct backend
rejection, private administrator route checks, source-header spoofing, malformed
paths, IPv4/IPv6 address decisions, OCSP serial/freshness checks and request-token
CSRF through the common router. The PostgreSQL Apple integration runs enrollment
and device check-in both directly and through the gateway. A real NATS 2.14.6
WebSocket test proves individual-key login and request/reply through frontend TLS
and gateway mutual TLS, rejection of direct backend access, malformed/native route
boundaries, connection capacity, survival beyond ordinary HTTP deadlines and
closure of existing streams on gateway shutdown.

These tests use synthetic device identities. They do not prove Safari's optional
certificate-selection behavior, real APNs delivery, hardware management, an actual
firewall's port exposure, durable agent enrollment integration or a production-scale
deployment.
Record those independently in the roadmap's acceptance evidence.

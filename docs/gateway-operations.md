# Native HTTPS gateway

The gateway implements the Apple/administrator portion of NET-01 and SEC-01.
It is not yet the complete one-port distribution: agent WSS, bootstrap/downloads,
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
on SIGINT/SIGTERM. Long-running agent WebSocket support is not yet implemented.

In direct mode, leave `OPENUEM_TRUSTED_GATEWAY_CERTIFICATES` unset. Apple and admin
certificate login then require the actual end-client TLS certificate and cannot
use a forwarded header. A missing, invalid, empty or expired **configured** trust
bundle is a startup error, not a reason to fall back to direct mode.

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
and device check-in both directly and through the gateway.

These tests use synthetic device identities. They do not prove Safari's optional
certificate-selection behavior, real APNs delivery, hardware management, an actual
firewall's port exposure, agent WSS authorization or a production-scale deployment.
Record those independently in the roadmap's acceptance evidence.

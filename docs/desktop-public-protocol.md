# Public desktop enrollment protocol

The console can run a separate, private HTTPS listener for individual Windows/Mac
enrollment and approved installer downloads. The gateway exposes its exact routes
on the canonical public HTTPS origin. No console routes are registered on this
listener. It serves independently signed bootstrap configuration as well as the
claim protocol. Native installer integration and the installation page remain open.
The console does not yet offer a new installation-link form.

## Enable the private listener

Configure the console process with all three settings:

```sh
OPENUEM_AGENT_ENROLLMENT_LISTEN_ADDR=:1328
OPENUEM_AGENT_RELEASES_DIRECTORY=/srv/openuem/approved-agent-releases
OPENUEM_AGENT_RELEASE_KEYS_FILE=/run/openuem/agent-release-public-keys.pem
```

The registry requires the existing `ENCRYPTION_MASTER_KEY` and a migrated database.
Set `OPENUEM_PUBLIC_ORIGIN` to the same canonical HTTPS origin used by the gateway
and organization authorities. Configure `OPENUEM_TRUSTED_GATEWAY_CERTIFICATES`
with the dedicated gateway leaf bundle. Keep port 1328 private; publish only the
gateway's 443 listener. Partial configuration, invalid trust keys, unavailable
repository, missing registry or an invalid origin prevents listener startup.

The listener normally uses the console's server certificate/key. To use a separate
private backend identity, set **both** `OPENUEM_AGENT_ENROLLMENT_TLS_CERT` and
`OPENUEM_AGENT_ENROLLMENT_TLS_KEY`. Its name must match the gateway's private
backend URL, and its issuer must be in the gateway's backend server trust bundle.
Add this argument to the gateway:

```sh
--desktop-url https://console.internal:1328
```

The optional NATS `--agent-url` is independent. Desktop forwarding preserves the
authenticated gateway boundary whether or not the NATS backend is enabled.
The listener does not accept direct endpoint access when gateway pins are set.
An invalid configured pin bundle never falls back to direct mode.

Mount the package repository read-only to the console. Publish release directories
atomically; do not modify approved files in place. Load protected, administrator-
supplied Ed25519 public keys and admit a release with the
[release operations command](agent-release-operations.md). An empty catalog is
allowed at startup so an administrator can subsequently accept its first release.
The listener never accepts release keys supplied by a request or its manifest.

To enable signed configuration downloads, also set
`OPENUEM_AGENT_BOOTSTRAP_KEY_FILE` to a protected, single PKCS#8 Ed25519 private-key
PEM file. Provision it for the console service account using the platform's private
file permissions. This dedicated server key must differ from every trusted release
key; it is not an organization CA key. Invalid or reused keys prevent startup.
Without this optional setting, the two bootstrap routes return 404. Key generation,
distribution and rotation are currently operator-managed.

## Exact routes and responses

Paths, methods, targets and tokens must be canonical. Query parameters, encoded
path aliases and extra path segments are rejected. `token` below is the canonical
43-character invitation token; `digest` is the 64-character lowercase release
payload digest, not a package hash.

| Method and path | Behavior |
| --- | --- |
| `GET /enroll/desktop/<token>/metadata` | Public organization/site labels and IDs, exact platform/architecture, expiry, remaining uses, approved artifact, original signed release envelope and download URL |
| `HEAD /enroll/desktop/<token>/metadata` | The same availability check and representation headers without a body |
| `GET` or `HEAD /enroll/desktop/bootstrap-keys` | Schema-1 key document containing the configured origin and current configuration signing public key with its SHA-256 key ID |
| `GET` or `HEAD /enroll/desktop/<token>/configuration` | Signed configuration attachment binding the origin, organization/site, invitation, target, expiry and exact approved release envelope |
| `POST /enroll/desktop/<token>/claim` | Validate both endpoint key proofs, claim the bound invitation and return the assigned individual identity and public certificates |
| `GET` or `HEAD /enroll/desktop/releases/<digest>/<platform>/<architecture>` | Verify and serve the current approved target; platform is `windows` or `macos`, architecture is `amd64` or `arm64` |

The base invitation URL is reserved for the future installation page and is not
currently a public gateway route. Metadata, configuration and package reads do not reserve a use,
issue an identity or register a device. Metadata remains readable after all uses
are consumed so a pending client can recover using its original keys. This grants
no right to create another identity. Configuration remains available for the same
recovery purpose. Unknown, expired, revoked, superseded and
withdrawn invitations do not expose an active installation. Changed site ownership
also makes the old invitation unavailable.

A claim is an `application/json` object with exactly the versioned shared fields:
`version`, `invitation`, `platform`, `architecture`, `device_name`, `csr`,
`broker_key` and `proof`. The body token must equal the path token. Duplicate or
unknown fields, case aliases, null values, wrong value types, invalid UTF-8 and
trailing JSON are rejected. The body limit is 16 KiB. The shared
`enrollment.Keys.Request` helper creates the CSR and NKey proof; private keys must
already be durably protected on the endpoint before the first claim.

Successful claims return the shared version-1 `enrollment.Response`. Only public
certificates, assigned organization/site/device IDs, expiry and the canonical
`wss://<public-origin>/agent-channel` endpoint are returned. A same-key retry
recovers the same certificate and identity without another use. Registry-only
invitations without an approved release binding cannot use this endpoint.
Release acceptance/withdrawal serializes with issuance: an already authorized
claim may finish, while subsequent claims use the new committed release state.
Release withdrawal does not revoke identities previously issued successfully.

The configuration signature uses a dedicated domain and key, distinct from the
release signature. Clients must authorize the expected origin independently before
fetching its key document over verified HTTPS. The origin/key inside a downloaded
configuration cannot establish its own trust. The schema-1 key document uses
`keys: [{"key_id": "<SHA-256>", "public_key": "<unpadded standard base64>"}]`.
The shared `bootstrap.Verify` requires the authorized origin, authenticated
configuration keys, independently pinned release keys, target and release checkpoint.
It verifies both signatures and their origin, scope, lifetime and release binding.
Configuration expiry cannot exceed invitation or release expiry. Current database
state is checked again during claims; a downloaded configuration does not override
withdrawal or revocation.

Native clients must independently authorize the expected server origin, verify
HTTPS without redirecting credentials, verify the release
signature/checkpoint/package and verify the operating system's native code
signature. The shared `enrollment.NewHTTPClient` now performs the bounded HTTPS
claim and validates the returned identity against the local CSR key and expected
origin. It does not provide native key storage, package/bootstrap validation or
installation by itself.

## Downloads, browser boundaries and capacity

Packages are public immutable binaries and contain no invitation or device private
key. Each request verifies the current release signature/trust/expiry, hashes the
selected file, rechecks the current release, and serves that same open descriptor.
The response uses an attachment filename from the signed manifest, binary content
type and the package SHA-256 as its ETag. One byte range is supported for resume;
multiple ranges are rejected. Conditional requests still pass release and file
verification. A replaced or changed file cannot silently substitute new bytes.
An authorized transfer may finish after a later release acceptance/withdrawal;
new transfers cannot select the old release.

Responses use `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, no-referrer
protection and no CORS permissions. No request URL, token, CSR, key or database error
is logged by this listener. A native client need not send an Origin header. When
present, Origin must exactly match the configured public origin; `null`, foreign
origins and browser cross-origin Fetch Metadata are rejected. Claims require JSON
and both key proofs and do not use browser cookies or HTTP authorization headers.

The listener admits at most 4 claims, 8 downloads and 32 metadata/configuration/key
document requests at once.
It applies a global 100 requests/second, burst-200 limiter and per-source
2 requests/second, burst-30 limit, with at most 4096 source buckets. IPv6 sources
share a /64 bucket. Forwarded source addresses are used only from a pinned gateway
and must contain one address. Otherwise the actual TCP source determines the limit.
Idle buckets can be reclaimed after five minutes. Admission failures return 429
with `Retry-After: 5`. These initial limits are fixed in the implementation.

Headers are bounded to 32 KiB. Claims have a 10-second body read deadline and a
20-second request context; the body deadline is cleared once its bounded input is
complete, so HTTP/2 does not reset a valid claim during a database wait. Metadata
and both bootstrap routes also have a 20-second context. Ordinary server
responses have a 60-second write deadline. Only an admitted download receives a
15-minute context/write deadline, on both TLS legs. The gateway admits at most
16 concurrent downloads, including requests awaiting the backend. Shutdown cancels
desktop requests at the gateway; the console closes listener connections, cancels
and joins handlers before closing their catalog. Native clients must retain their
protected pending keys and retry safely after interrupted claims or transfers.

## Verification

Real PostgreSQL and TLS tests cover read-only GET/HEAD behavior, original release
signature verification, exact package bytes, single-range resume, changed files,
withdrawal, invitation/authority expiry and site movement. Claim tests cover
strict JSON and origin/body boundaries, one-identity recovery, database-lock
contention, capacity rejection and cancellation without issuance at shutdown.
An HTTP/2 claim test crosses the actual body deadline during an observed database
lock and verifies that issuance still returns its response after the lock releases.
Two TLS legs verify anonymous/foreign direct-backend rejection, forwarding-header
replacement, optional-broker routing and denied public administrator aliases.
A streaming gateway test crosses a short ordinary HTTP deadline and verifies that
gateway closure cancels the private download.

The public server/gateway implementation at console commit `0268458` passed
[console CI](https://github.com/the-luap/openuem-console/actions/runs/34181569389).
The subsequent shared client at library commit `d6129ce9fe9b` passed
[Linux and native Windows CI](https://github.com/the-luap/openuem-nats/actions/runs/34182431163).
`TestNativeEnrollmentClientClaimsAndRecoversThroughThePinnedGateway` uses that
published client against the actual private handler, two TLS legs and PostgreSQL
registry. It verifies current release binding, certificate/key/origin validation,
one-identity recovery after reconstructing the client and withdrawal rejection.
It also fetches origin keys, verifies the independently signed configuration and
checks the selected package through the real public TLS gateway. Separate tests
cover GET/HEAD without invitation use, disabled signing, key-role reuse, protected
key-file parsing, revoked invitations and withdrawn releases.
Its keys are retained in test memory. The related agent's separate native storage
suite now covers DPAPI and isolated Keychain recovery after a lost HTTPS response;
see [desktop integration evidence](desktop-enrollment-plan.md).

```sh
AGENT_ENROLLMENT_TEST_DATABASE_URL='<isolated PostgreSQL test DSN>' \
  go test -race -count=1 ./internal/desktop/... ./internal/gateway
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./...
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./...
```

These are server-side protocol and build checks. Signed installer execution,
native bootstrap activation, user-facing consent and physical endpoint
acceptance remain separate implementation and verification work.

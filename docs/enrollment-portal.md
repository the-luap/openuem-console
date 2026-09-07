# Public Apple enrollment portal

The public invitation now opens an English instruction page. A GET or HEAD request
does not consume it, issue a device certificate or return a management profile.
This protects invitations from mail previews and link scanners that only read
links. A scanner that actively submits confirmed forms is outside that guarantee.

## Device-owner flow

1. An authorized operator selects an organization/site and creates an invitation.
   The console displays a private link and a QR code generated locally. No QR or
   tracking service receives the invitation.
2. The owner opens the link on their intended iPhone or iPad, checks the named
   organization, chooses the device type and confirms management.
3. A same-origin POST claims the invitation for that browser. The browser then
   downloads the profile through an explicit POST and installs it in Settings.
4. The owner returns to the page and selects **Check enrollment status**. A download
   is not a successful enrollment: **Enrollment complete** appears only after the
   device has authenticated and registered its push token.

The help explains unsupported platforms, interrupted downloads, device prompts,
expired or previously used invitations and how to obtain a replacement. Apple
requires installing a downloaded profile through Settings and removes an
uninstalled download after eight minutes. See [Apple's installation instructions](https://support.apple.com/en-us/102400).

Manual Device Enrollment remains distinct from Apple's User Enrollment privacy
model. It does not silently install management or enable supervision. Windows and
Mac installation/download flows remain separate expanded-roadmap work.

## Claims, retries and revocation

Invitations expire after one hour. A successful claim issues one individual
certificate and binds the retry/status record to the browser's random 256-bit
secret. The secret is held in a Secure, HttpOnly, host-only, SameSite Strict cookie.
Only its hash is stored in the database. Repeating a claim from the same browser
is idempotent; another browser receives an already-used state without organization,
inventory, identifiers or credentials.

The claiming browser has **three download attempts within ten minutes**, always
returning the same profile and certificate. Attempts count when the server starts
returning the file, including interrupted transfers. The device row and claim are
locked during download, so concurrent requests cannot exceed the limit. A process
restart does not reset the claim, counter or expiry.

For these retries, the profile is encrypted with a key derived from the browser
secret, then encrypted again with the server master key. Database backups and the
master key alone cannot recover it without that browser secret. The encrypted
copy is cleared on the third attempt, on the first authenticated device check-in,
or on administrator revocation. The worker also clears expired copies; expiry is
enforced on every download even if the worker is unavailable. Expired status rows
are removed after one hour. Deleted database values may remain encrypted in
database backups/WAL; this is not a claim of physical secure erasure.

The browser status window is one hour after the claim. Ending that window does
not revoke a successfully enrolled device. Clearing cookies or changing browsers
does not transfer a claim. If installation cannot finish, the administrator must
revoke the old enrollment and create a new invitation. Revocation blocks the old
certificate immediately; it does not erase the device or remove its local profile.

## Public boundary

Only the existing `/mdm/apple/enroll/<token>` path accepts the portal's GET, HEAD
and POST methods. The [gateway](gateway-operations.md) allows those exact routes.
No administrator session, inventory API or general static asset route becomes
public. PUT check-in/connect still requires the issued certificate over TLS.

Form mutations require the configured HTTPS origin, browser cookie, per-invitation
request token and compatible Fetch Metadata. Query-string tokens, duplicate CSRF
fields, missing cookies, cross-origin/opaque origins, unsupported form types and
oversized bodies are rejected. Claim requires a selected supported platform and
explicit confirmation. The platform selector is a usability check; actual device
identity and model validation occurs in authenticated check-in.

Pages have no scripts, external fonts or tracking. CSP permits only their embedded,
hashed stylesheet and same-origin forms, and denies framing. All responses use
`no-store`. `Referrer-Policy: strict-origin` removes path/query tokens while
preserving Origin on native form submissions; external help links additionally
use `noreferrer`. A live browser reproduced that `no-referrer` makes form Origin
`null`, so accepting null origins is not used as a workaround.
[Browser referrer/Origin behavior](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy#effect_on_the_origin_header).

Each listener limits enrollment traffic to 100 requests/second with a burst of 200,
and each source to two/second with a burst of 30. IPv6 addresses share a /64 bucket.
There are at most 4,096 source buckets and four concurrent identity claims. HTTP
429 responses include retry guidance. Source forwarding is accepted only from
the pinned gateway, which replaces client-supplied headers. These are per-process
limits; replicas do not share a global rate counter. Device protocol traffic uses
separate paths and is not throttled by enrollment browser activity. Production
load and distributed denial-of-service acceptance remain open.

Successful claims/downloads are audited using the device record ID. Tokens,
browser secrets and profile data are omitted. The portal returns short actionable
errors without raw database or transport details. Configure any surrounding
access-log system to omit invitation paths and request cookies/bodies.

## Verification

PostgreSQL/TLS tests cover scanner GET/HEAD, claims, CSRF/Origin/body boundaries,
concurrent competing browsers, idempotent claim retry, encrypted copies, process
restart, concurrent download limits, expiry/revocation, first-check-in termination
and registered-device status. The full HTTPS flow passes both directly and through
the pinned gateway. Existing inventory/profile/update tests continue to pass.

On 8 September 2026 local time, a live Chromium browser exercised the actual TLS
handler and isolated PostgreSQL schema. It submitted native forms, downloaded
three byte-identical profiles, observed download exhaustion and denied a separate
browser. The request's Referrer contained only the HTTPS origin. Styles passed
CSP without console errors; the first keyboard focus was the device selector.
The instruction page had no horizontal overflow at 390, 768 and 1440 CSS pixels;
light and dark rendering were inspected. This does not establish full accessibility,
Safari download behavior or physical iPhone/iPad acceptance.

To open an isolated interactive fixture, set a private temporary path:

```sh
APPLE_MDM_TEST_DATABASE_URL='<isolated PostgreSQL DSN>' \
OPENUEM_ENROLLMENT_BROWSER_FIXTURE=/tmp/openuem-enrollment-preview.url \
go test -count=1 -v -run '^TestEnrollmentBrowserFixture$' -timeout 10m ./internal/mdm/apple
```

The file contains the synthetic invitation URL. The fixture uses a local test TLS
certificate; configure only the test browser to trust it. Create the same file
path with `.stop` appended to close the fixture. The test also times out after
eight minutes and removes its unique database schema and private URL file. The
ordinary suite skips this fixture unless explicitly enabled.

# Native Windows enrollment and device console

The private console now exposes organization CA creation, one-device enrollment
invitations, native device metadata and access revocation. Configure the
[Windows listener and gateway](native-windows-operations.md) first, then open
**Devices → Native Windows management**. The gateway's public device allowlist
does not expose these administrative pages. WIN-02 remains in progress.

## Enrollment workflow

An organization administrator creates the organization's immutable enrollment
authority. The form selects an RSA minimum key size of 2048, 3072 or 4096 bits
and a device certificate lifetime of 1–365 days. It requires explicit confirmation;
submitting again returns a conflict instead of replacing the issuer. CA private
keys remain encrypted and cannot be downloaded from the page. The underlying
[CA service](native-windows-mdm.md#protected-organization-ca-and-authenticated-policy-service) controls
issuer validation and storage. The XCEP renewal period is one quarter of the
selected lifetime; automatic certificate renewal is still separate work.

Choose a concrete site before creating an invitation. An enrollment operator
enters an enrollment username and a lifetime of 1–24 hours. The successful POST
shows its independent, random enrollment password once, the configured public
server origin and manual Windows enrollment instructions. It also immediately
includes the new invitation in the list. A subsequent GET shows metadata only;
neither the URL, session nor a password retrieval endpoint contains the secret.
Responses use `Cache-Control: no-store` and `Referrer-Policy: strict-origin`.
The origin-only referrer policy preserves the same-origin Origin header used by
the CSRF check for ordinary browser form submissions. Lost credentials require
revoking the unused invitation and creating another.

Use Windows **Settings → Accounts → Access work or school → Enroll only in
device management**, following the
[Microsoft instructions](https://learn.microsoft.com/en-us/windows/client-management/mdm-enrollment-of-windows-devices#enroll-in-device-management-only).
The page supplies enrollment-specific credentials; directory and console account
passwords are unrelated. This flow does not install the OpenUEM agent. Physical
Windows enrollment acceptance has not yet been performed.

Invitation revocation requires a confirmation checkbox and prevents further
use or replay of that invitation. It does not revoke an already issued identity.
The existing credential transaction still enforces live creator permissions,
permission revision, exact tenant/site ownership, expiry and one-use consumption.

## Device inventory and revocation

The site page shows 25 devices and 25 invitations per page, independently paged.
Device search is a case-insensitive literal substring of reported name or native
UUID. Requests allow at most 128 UTF-8 bytes of search text, offsets 0–100,000
and bounded database page sizes. Paging uses enrollment time and UUID as a stable
ordering; concurrent new enrollments can shift offset pages.

Device details show reported enrollment hints, native identity, certificate
fingerprint and expiry. Status means **Certificate issued**, **Certificate
expired** or **Access revoked**. No enrollment field establishes current online
state, platform attestation, a completed management exchange or applied policy.

The shared device inventory includes up to 100 recent native Windows identities
for the authorized organization or site, alongside existing agents. A visible
notice at that limit points to the paged site inventory; filtering this preview
searches only those recent entries. Links retain each device's actual tenant and
site. Native and agent identities stay separate until an independently verified
association exists. Native enrollment does not fabricate a last-contact time.

Device access revocation requires the revoke-device capability and an explicit
confirmation. It serializes with in-flight identity transactions, records one
immutable audit event and blocks subsequent native authentication, enrollment
replay and command admission. Concurrent retries remain idempotent. It retains
the device, certificate and command history. It does not unenroll Windows,
remove settings, send a wipe command or revoke a separate agent.

## Routes and authorization

These routes are available without a prefix, under `/tenant/:tenant`, and under
`/tenant/:tenant/site/:site`. Default navigation resolves the user's selected
scope; an explicitly unknown or inconsistent URL scope cannot fall back to it.

| Method and path | Required capability and scope |
| --- | --- |
| `GET /windows` | `ReadDevices`; organization view selects a site |
| `GET /windows/:id` | `ReadDevices` in the exact device site |
| `POST /windows/setup` | `ManageCertificates` for the whole organization |
| `POST /windows/invitations` | `EnrollDevices` in a concrete site |
| `POST /windows/invitations/:id/revoke` | `EnrollDevices` in the exact invitation site |
| `POST /windows/:id/revoke` | `RevokeDevices` in the exact device site |

Readers do not receive invitation usernames or issuer-management forms. A scoped
operator cannot create an organization CA or revoke a device. Handlers resolve
live permissions and stores authorize again inside their transactions. Device
lists join current site ownership and hold row locks until the read audit commits;
moving a site does not transfer an old native identity to its new organization.
Organization inventory requires an organization-wide read grant.

POST actions accept only bounded URL-encoded bodies, with one matching body CSRF
token and no query parameters, unknown/repeated fields or content encoding.
Both shared CSRF parsing and Windows handlers enforce the 8 KiB limit, including
streamed requests and previously parsed forms. Requests have a 30-second context
deadline. Dynamic HTML is escaped and failures use fixed messages.

Migration 010 adds append-only console read/revocation audit events. These contain
actor, action, scope and optional resource UUID, never credentials, certificate
bytes, device names or search text. Failed audit writes return no read payload
and roll back revocation. Enrollment and CA mutations retain their own existing
transactional audits. The general audit browser does not yet aggregate this
new console audit table.

## Validation and remaining work

Synthetic PostgreSQL and real console/session tests cover role and site isolation,
organization inventory, site moves, pagination, literal search, bounded forms,
CSRF, escaped output, issuer creation conflicts, one-time credentials, invitation
revocation, concurrent device revocation, lock waits, replay denial, audit rollback
and immutable history. Browser checks on an owned loopback fixture exercise CA
creation, invitation creation, GET secret absence and invitation revocation.
Layouts at 390, 768 and 1440 pixels retain contained forms, numbered instructions
and keyboard-focusable horizontal table scrolling without page overflow.

The full local PostgreSQL 17/race suite passes in 84.932 seconds at 83.7%
Windows package coverage, with router and shared CSRF tests passing. The full
handler suite passes in 7.950 seconds and shared view tests in 2.147 seconds.
Vet and both Linux/Windows builds pass. Both complete workflows pass for the
corrected console/history commit `9f33aae`
([push](https://github.com/the-luap/openuem-console/actions/runs/34425352621),
[pull request](https://github.com/the-luap/openuem-console/actions/runs/34425355677)).

The fixtures create only isolated synthetic database state and loopback services.
No host certificate, policy, account or device is changed. Native Windows management
now includes [typed policy forms, run history and confirmed cancellation](native-windows-update-console.md).
The roadmap still requires raw command/result and ring/schedule administration workflows, broader CSP
policies, certificate renewal and unenrollment, key rotation/restore, verified
native/agent association, Entra/Autopilot and physical Windows acceptance.

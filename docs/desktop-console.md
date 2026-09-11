# Desktop enrollment administration

Open **Desktop enrollment** from device management. The page uses the selected
organization and site, and the current session's permissions. It manages the
individual identity registry used by the private agent authorization, command
provisioning and worker services.

## Initial organization setup

The console initializes additive `uem_agent_*` migrations before accepting
requests when its encryption master key is configured. Preserve that key with
the database backup. A missing key or migration failure leaves desktop enrollment
unavailable; the page shows a setup message without returning database errors.

A server administrator must configure `OPENUEM_PUBLIC_ORIGIN` as the canonical
HTTPS origin, for example `https://uem.example.com`. This is an installation
setting. Request host headers and submitted form fields cannot change it.

An organization or server administrator then enters the organization name and
chooses one of these authority sources:

- **Create an organization authority automatically** creates the private CA on
  the server and encrypts its private key in the database.
- **Import an enterprise authority** accepts a matching PEM CA certificate and
  unencrypted PEM private key, subject to the registry's key, validity and signing
  constraints. Files are bounded to 64 KiB and 32 KiB respectively. The key is
  encrypted for storage, never rendered and never included in an agent download.

An existing authority is displayed as public metadata. A repeated automatic setup
with the identical organization and origin is idempotent; incompatible existing
configuration and replacement imports are rejected. Authority replacement and
rotation need a separate lifecycle and are not provided by this form.

## Permissions and lifecycle

| Action | Required permission |
| --- | --- |
| Read public CA metadata, invitations and individual identities | Viewer in the selected organization or site |
| Read the scoped computer overview | Viewer in the selected organization or site |
| Search reported computer software | Viewer in the selected organization or site |
| Read and search reported network adapters | Viewer in the selected organization or site |
| Read and search reported physical/logical disks | Viewer in the selected organization or site |
| Read and search reported monitors/printers | Viewer in the selected organization or site |
| Request fresh computer inventory | Operator in the selected organization or site |
| Create an installation invitation from an approved release | Operator in the selected organization or site |
| Revoke an invitation | Operator in its organization or site |
| Set up the organization authority | Organization administrator for the entire organization |
| Revoke a device identity | Organization administrator for that device's organization |

Server administrators can perform all these actions. Multiple site grants do not
grant organization-level certificate administration. Both the routes and their
database queries enforce scope. Unknown or foreign URLs cannot select a fallback
organization, and supplying another device or invitation ID does not widen access.

Revocation first displays its effect and requires explicit confirmation. The
server checks confirmation, CSRF and permissions. Revoking an invitation prevents
new enrollment through that link; it does not revoke existing identities.
Revoking an identity rejects subsequent authorization and records broker-session
disconnect and command-consumer cleanup work. Run the separate
[authorization service](agent-authorization-operations.md) and
[command service](agent-command-operations.md) for those external effects.
Re-enrollment requires a new endpoint identity.

Lists use 25-row keyset pages, retain revoked records and never recover invitation
tokens or private keys. Successful reads are recorded in `uem_agent_audit` with
actor and scope. Collection events use the nil UUID as their resource ID. A
[general audit viewer](audit-log.md) supports scoped search, export and reviewed
retention policies.

**Identity ready** means that issuance and the last recorded command-consumer
provisioning succeeded. It does not mean that the computer is online, that the
agent installed successfully or that inventory was received. The console also
distinguishes revoked/expired identities, changed site ownership and pending
command provisioning. It does not infer online status from unused timestamps.

## Installation boundary and verification

The page creates installation invitations when an approved release, matching
packages and the protected bootstrap signer are configured. It binds the chosen
target, release and organization/site, then displays the invitation URL once.
The [private/public HTTP protocol](desktop-public-protocol.md) supplies the public
installation instructions, signed configuration and protected claim/download
workflow. Protected endpoint storage, durable claim recovery and native installed
service activation have synthetic tests; finished signed Windows/Mac installer
distribution and physical endpoint acceptance remain open.

The unified device list and linked Mac page open a scoped computer overview for
scoped roles. It includes hardware, operating system version and report metadata,
with explicit empty states for missing reports. It does not depend on enrollment
being configured. Its reads recheck permissions and commit an inventory audit
event before responding. See [access control](access-control.md) for the exact
scope and field boundaries. Other legacy desktop details and actions retain
their server-administrator boundary.

Operators can use [Request fresh inventory](desktop-inventory-refresh.md) from
the dedicated computer inventory page. The request is persisted, audited and
checked again before delivery. The displayed state distinguishes delivery
acceptance from a report actually being received from the device.

The **Reported software** inventory tab provides [scoped search and pagination](desktop-software-inventory.md).
It reads only report metadata and records access before responding. Stored
software reports are distinct from verified deployment outcomes.

Delegated hardware and operating-system GET aliases open the same scoped
overview. Optional memory and processor-core values remain **Not reported**
when absent, preserving a distinction from a stored zero. Internal agent
settings and signed-in user information remain outside this projection.

The **Reported network** tab provides [scoped adapter reports](desktop-network-inventory.md)
with literal name/MAC/IP search, bounded pagination and a committed read audit.
Missing flags and empty reports retain their uncertainty; stored configuration
does not verify current connectivity.

The **Reported storage** tab provides [scoped physical and logical disk reports](desktop-storage-inventory.md),
with literal search, bounded pages and audited reads. Stored usage defaults and
BitLocker strings remain reported evidence; current encryption is not verified.

The **Reported peripherals** tab provides [scoped monitor and printer reports](desktop-peripherals-inventory.md),
with bounded literal search, audited reads and distinct missing/false/true
printer flags. The page reports stored configuration without testing a port or
asserting that a peripheral is connected or working.

The shared inventory navigation identifies the current page through a highlighted,
underlined link and `aria-current="page"`. The physical/logical storage selector
uses the same presentation. Shared navigation labels use the existing language
catalog with English fallback. Scoped targets and first-page recovery remain
unchanged; browser checks verify computed styling and narrow-screen wrapping.

PostgreSQL tests use the real console router, session store and Ent schema. They
cover role aliases, foreign objects/scopes, setup origin binding, encrypted CA
storage, redacted import errors, token-free metadata, confirmation/CSRF rejection
and atomic identity/command-cleanup revocation. A separate store test verifies
bounded pagination and audited reads across organizations and sites.

The opt-in `OPENUEM_DESKTOP_BROWSER_FIXTURE` test uses a loopback TLS listener and
an isolated schema. It supplies an authenticated test account and runs the real
form handlers with the production cookie/Origin CSRF middleware. Set the variable
to a private temporary filename when running
`TestNativeAppleConsoleRoutesWithPostgres`; the file receives its preview URL.
Create `<filename>.stop` to close it and remove the schema. The fixture expires
after eight minutes and is disabled in normal CI runs.

Chromium checks covered native setup and keyboard-confirmed revocation over HTTPS,
origin-only Referer headers, and light/dark rendering at 390/768/1440 CSS pixels.
These checks are not physical endpoint, Safari or complete accessibility acceptance.

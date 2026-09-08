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
general audit viewer and retention/export controls remain pending.

**Identity ready** means that issuance and the last recorded command-consumer
provisioning succeeded. It does not mean that the computer is online, that the
agent installed successfully or that inventory was received. The console also
distinguishes revoked/expired identities, changed site ownership and pending
command provisioning. It does not infer online status from unused timestamps.

## Installation boundary and verification

The current page does not create new installation links. Signed package selection,
the public Windows/Mac installation portal, endpoint key storage and bootstrap
integration are still in progress. Existing invitations created through the
shared registry can be reviewed and revoked. Legacy desktop administration routes
retain their separate server-administrator boundary.

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

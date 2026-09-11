# Console access control

Authentication, second-factor verification and authorization are separate checks.
The console loads the signed-in user's current database grants for each request.
Changing grants therefore affects existing sessions on their next request. A user
with no grants can manage their own account but cannot read managed inventory.

## First start and upgrades

The console applies additive `uem_access_*` migrations before opening listeners.
On the first start with these migrations it assigns server administration to the
existing `openuem` account. To select another existing user, set
`OPENUEM_BOOTSTRAP_ADMIN` to that user's ID before starting. Startup fails if the
selected user does not exist. The bootstrap event is recorded once in the database;
changing the environment or restarting does not restore revoked permissions or
grant a different user administrator access.

Sign in as the bootstrap administrator and open **Access permissions** in the
administrator navigation, or `/admin/access`. Enter an existing user ID. Select
the role, organization and site, confirm the target user and save. This assigns
permissions; it does not create or authenticate an account. Existing password,
certificate and OIDC accounts require the same explicit grants. Existing users
are not automatically made administrators during migration.

The legacy reset of the built-in account changes its credentials in place,
invalidates its sessions and removes its existing second-factor registration and
recovery codes. It preserves its user ID and grants. It cannot turn a previously
demoted account into an administrator. Keep an additional named administrator and
protect database backups containing permission records.

## Roles and scope

| Role | Scope | Allowed native Apple actions |
| --- | --- | --- |
| Viewer | One organization or one site | Device inventory/details and profile metadata |
| Operator | One organization or one site | Viewer actions plus invitations, inventory refresh, assignment/removal of existing profiles, command retry and OS update policies |
| Organization administrator | One entire organization | Operator actions plus APNs credentials, profile content/create/revision/delete/download, enrollment revocation, FileVault policy management and recovery key retrieval |
| Server administrator | Global | All native Apple actions, installation settings, desktop administration and user access assignments |

Grants are additive. A grant for an organization covers every site in that
organization. Adding a viewer grant to one of its sites cannot restrict a broader
operator grant. Multiple site grants do not imply authority over the whole
organization. Profile contents and APNs credentials always require organization
authority even if their URL includes a site. Site-scoped operators may assign
existing organization profiles only to their permitted devices. Raw profile
downloads require organization administration because payloads can contain secrets.

[FileVault](macos-filevault.md) uses separate `devices.security.manage` and
`devices.recovery.retrieve` capabilities. Both require organization or server
administration. Policy changes and recovery retrieval recheck permissions inside
their database transaction, serialized with permission replacement. A recovery
key is returned only after its read audit commits, through a non-cacheable
CSRF-protected POST response. Profile-assignment authority does not grant access
to the dedicated FileVault workflow or its keys.

The organization/site selectors display only permitted scopes. A site-scoped user
cannot select **All sites**. Explicit foreign organization/site URLs are rejected;
object lookups are additionally scoped on the server. Invitation and bulk-action
form fields cannot expand the selected URL scope.

The [individual desktop enrollment page](desktop-console.md) allows scoped
metadata reads, operator invitation revocation, and organization-administrator
authority setup and identity revocation. Its action routes are explicitly mapped
to capabilities and verify the selected scope before using the registry.

The unified inventory links desktop rows to a scoped overview for
viewers, operators and organization administrators. Both `/computers/:uuid` and
`/computers/:uuid/overview` accept the organization/site URL prefixes. Linked Mac
devices also offer **Open agent inventory**. The overview includes device identity,
report times, addresses, hardware and operating system version. Missing reports
have explicit empty states. Notes, task output, agent configuration, remote access
data and signed-in user information are excluded from the database projection.

The existing GET `/computers/:uuid/hardware` and `/computers/:uuid/os` aliases
also open this scoped overview for delegated roles, with the same projection,
authorization and committed read audit. They do not expose the legacy OS page's
signed-in user fields. Missing memory/core counts remain **Not reported**;
stored zero values remain distinct, and the page identifies them as reports.

The read transaction rechecks current grants and records `inventory.desktop.read`
with the actual organization, site and legacy agent ID before returning data.
Audit failure returns an unavailable response without inventory. Waiting,
unassigned, foreign and ambiguously assigned devices return the same 404 response;
exactly one site must exist, including associations outside the requested scope.
The unified desktop list applies the same single-site rule to scoped readers,
including filtered searches. Server administrators can still inspect ambiguous
assignments to repair their membership.
This view also works when individual desktop enrollment is disabled.

Server administrators retain the existing desktop overview. Its edits, other
legacy detail routes beyond the scoped projections, software deployment and
remote actions still require a server administrator. Those individual desktop action permissions remain roadmap
work. A new route is not implicitly enabled for a scoped role because it shares a
URL prefix or uses GET.

The [inventory refresh workflow](desktop-inventory-refresh.md) is available to
operators and administrators with `devices.refresh` in the selected scope. The
dedicated inventory page provides a protected form and durable delivery status.
Both the new refresh endpoint and legacy force-report aliases recheck current
authority and exact device assignment before each broker handoff. Viewers retain
read-only access; broker acceptance does not imply a completed device report.

[Reported software](desktop-software-inventory.md) adds a scoped read-only page
with literal name/publisher search and 25-entry continuation. Its projection and
`inventory.software.read` audit share current transaction authorization. Delegated
roles can also use the existing GET software aliases; POST remains restricted.

[Reported network](desktop-network-inventory.md) uses the same scoped read
boundary for adapter configuration, literal name/MAC/IP search and 25-entry
continuation. Current transaction authorization and `inventory.network.read`
audit are required before returning data. Delegated roles can also use the
existing GET network-adapter aliases; mutations remain restricted.

[Reported storage](desktop-storage-inventory.md) adds physical and logical disk
reports, literal search and 25-entry continuation under the same scoped read
boundary. Current authorization, exact membership and a committed
`inventory.storage.read` audit precede data return. Delegated GET disk aliases
open these reports; file browsing, download and mutation permissions do not expand.

[Reported peripherals](desktop-peripherals-inventory.md) provides scoped monitor
and printer projections with nullable flags, literal search, 25-entry pages and
a committed `inventory.peripherals.read` audit. Delegated GET monitor/printer
aliases select the corresponding report kind. Reported ports remain inert text;
device actions are not added to this read capability.

[Reported memory modules](desktop-memory-inventory.md) adds a bounded projection
of slot, capacity/type, serial/part number, speed and manufacturer. Literal
search and continuation share current authorization, exact membership and the
committed `inventory.memory.read` audit. It grants no mutation permission.

[Account display language](account-language.md) is a self-service preference.
Its protected form always derives the account from the authenticated session;
a language selection does not change roles or device permissions.

## Concurrent changes and audit

Every permission form contains the revision it displays. If another administrator
changes the same user first, the stale submission receives HTTP 409; reopen the
user and review the current assignments. The database serializes permission
changes and checks the acting user's current rights again inside the transaction.
It rejects removal of the final server administrator, including concurrent
demotions. User, organization and site deletion is blocked while referenced grants
remain; remove those grants first.

`/admin/access/audit` shows successful permission changes, including actor, target
user, previous grants, resulting grants and UTC time. It is restricted to global
server administrators and paginates 100 records at a time. Native Apple inventory
reads and profile downloads are recorded separately in `mdm_apple_audit`; no
profile contents, invitation tokens or private keys are stored in those events.
The [scoped audit log](audit-log.md) combines Apple, agent, access, release and
audit activity/retention metadata. Organization administrators can read/export
their own scope and set an explicitly confirmed organization retention policy;
server administrators can also search all organizations and manage server-wide
retention. The default is indefinite. Sensitive audit reads recheck permissions
in their database transaction, serialized with permission replacement.

The global request-token/Origin CSRF layer and explicit confirmation protect
permission changes. Login, MFA and the [private gateway boundary](gateway-operations.md)
remain required. Application grants do not change which source networks can reach
administration.

## Verified behavior

PostgreSQL-backed tests exercise the actual console route table, all registered
administrator routes, scoped Apple aliases and object IDs, forged body scopes,
viewer/operator/administrator actions, mixed-scope bulk assignment, existing
session revocation, concurrent editors, concurrent last-administrator demotions,
bootstrap idempotence, permission history and credential reset. Race checks and
Linux/Windows cross-builds pass locally. Browser checks of the rendered permission
page at 390, 768 and 1440 CSS pixels found no horizontal page overflow. These are
specific checks, not complete desktop authorization or accessibility acceptance.

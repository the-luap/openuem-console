# Scoped audit log and retention

The console combines existing audit sources in an English audit viewer. Open
**Audit log** in navigation. Organization administrators can read and export their
organization's events, optionally filtered to a site. Server administrators can
also use `/audit` to search all organizations and server events. Viewers and
operators cannot read or export audit records or change retention.

## Search and export

- Organization: `/tenant/:tenant/audit`.
- Site: `/tenant/:tenant/site/:site/audit`.
- Server-wide search: `/audit`, available only to server administrators.
- Filters: exact actor, action, target ID, source and result, plus UTC timestamps.
  The start is inclusive and the end exclusive. The default is the last 30 days.
  HTML date/time inputs show browser formatting; their values are interpreted as
  UTC. Requests also accept RFC 3339 timestamps with offsets.
- Pages contain at most 100 events, ordered by timestamp, source and source event
  ID. The Older events link preserves absolute filter bounds and a filter-bound
  cursor. Concurrent insertion does not shift offsets. Each page/export reads a
  current database snapshot; deletion by retention can remove older matches.
- CSV and JSON exports use protected POST forms and all matching events, with a
  maximum of 10,000 events and 16 MiB. Larger exports return an error without a
  partial attachment; narrow the filters. Two exports can run per console process.

Every returned event contains time, source, source event ID, organization/site,
actor, action, target and result. Metadata above 1,024 bytes for actor/action or
2,048 bytes for target is replaced with an explicit omission marker. Arbitrary
source JSON, command/profile contents, permission grant documents and credentials
are excluded. The separate `/admin/access/audit` page remains available to server
administrators for previous/resulting permission grants.

CSV uses standard quoting and prefixes formula-like or tab/newline-containing
text with the visible marker `[text] `. Prefix detection includes leading Unicode
whitespace/format characters and ASCII/full-width formula operators. JSON keeps
the original text values within the metadata limits above. Spreadsheet behavior
varies; CSV quoting alone is insufficient, and apostrophe escapes may disappear
when files are saved again. See [OWASP CSV Injection](https://owasp.org/www-community/attacks/CSV_Injection).
The tests verify encoded fields, not every spreadsheet application's behavior.

## Sources and meaning

| Source | Backing table | Scope and outcome |
| --- | --- | --- |
| Apple | `mdm_apple_audit` | Original organization; new device/command events capture site at write time and explicit results |
| Agent | `uem_agent_audit` | Organization and stored site; legacy result is `recorded` |
| Inventory | `uem_inventory_audit` | Scoped desktop overview reads with the actual organization/site and legacy agent ID, result `recorded`; available independently of desktop enrollment |
| Inventory refresh | `uem_inventory_refresh_audit` | Scoped request admission, committed handoff attempts, retries and delivery outcomes; no report contents or broker error text |
| Access | `uem_access_audit` | Server-wide; permission change metadata, result `recorded` |
| Release | `uem_desktop_release_audit` | Server-wide; approved desktop release metadata, result `recorded` |
| Activity | `uem_audit_activity` | Audit page/export access in the requested scope |
| Retention | `uem_audit_retention_history` | Committed policy changes and deletion receipts for the policy scope |
| Windows | Twelve original Windows audit tables; [source mapping and deletion guards](native-windows-audit.md) | Original organization/site, result `recorded`; no credentials, command values or mail recipients |

Absent optional platform tables are omitted; available sources are shown on the
page. Organization/site searches exclude global access and release events.
Historical Apple events without site/outcome metadata remain organization-wide
with result `recorded`; no outcome or original site is inferred from current
device placement. Site searches cannot show events without a stored matching site.
`recorded` means no explicit outcome was stored, not that an action succeeded.
Apple command acknowledgement, failure and deferral now record their corresponding
results without copying device error text into audit metadata.

Inventory refresh attempt evidence remains protected while its request is queued.
Retention previews and deletion both exclude those active records. Once the request
is terminal, normal organization retention applies. This preserves retry limits
and uncertainty after a lost acknowledgement or failed completion commit.

Successful page reads and completed export generation are audited with actor,
scope, a SHA-256 digest of the filters and event count, committed before data is
returned. Oversized exports record failure. Export success confirms generation,
not receipt by the browser. Authentication/authorization failures and arbitrary
legacy console actions are not comprehensively covered by these sources. This
viewer is not a claim of complete installation-wide auditing or tamper resistance
against a database administrator.

## Retention policies

Retention defaults to **indefinite**. Installing or migrating the feature does not
enable deletion. Policies are independent per organization; policy scope zero
covers only server-wide access/release/activity records, not organization data.
There is no site-specific policy or inherited global default.

On an organization or global audit page, open **Retention policy**, enter `0`
(indefinite) or `30`–`3650` days and choose **Preview change**. Review the old/new
policy, cutoff, available-source counts and affected scope. Confirm the ongoing
policy with the checkbox and **Apply retention policy**. A finite policy enables
permanent deletion of original audit rows. It does not delete devices, desired
configuration, command state or deployment state.

Windows audit events have a separate **Include Windows audit events in this
retention policy** selection on organization pages. It defaults to off, including
for existing finite policies and pending previews migrated from earlier versions.
Review and confirm the Windows inclusion change as well as the number of days.
The selection applies to all available Windows audit sources in that organization.
Global and site policies cannot opt in. Clearing the selection preserves future
Windows audit events while the organization's other sources continue to follow
its day setting. Choosing zero retains every covered source indefinitely.

Previews expire after ten minutes, are account/scope-bound and usable once. Only
the latest preview for an account and scope remains valid. The database stores a
hash of the confirmation token. Changed policy revisions, expired/used previews,
another account or revoked rights require a new authorized review. Preview counts
can change during concurrent activity; confirmation sets an ongoing age policy,
not a fixed set of IDs. Switching to zero stops future cleanup after any already
running transaction finishes; it does not restore deleted events.

The joined console worker sweeps immediately and every minute. A sweep processes
up to ten due policies and up to 1,000 old rows per source/policy. Policy row locks
coordinate replicas. Full batches become due in a minute; otherwise in an hour.
Each deletion batch commits with a receipt containing source, cutoff, policy
revision and deleted count. Failed receipt writes roll back the deletion. Policy
changes likewise commit with their before/after retention evidence, including the
old/new Windows inclusion flag. Windows deletions additionally require an immutable
batch of the exact event IDs, source table, organization, cutoff, policy revision
and current transaction. Their row guards always reject updates and reject deletes
without a matching live policy and receipt. These guards cover audit rows only;
protected command, packet and observation evidence keeps its existing lifecycle.

Retention history is excluded from automatic pruning and retained indefinitely.
The policy page shows the latest 25 detailed records; the audit log exposes older
retention event metadata. Source tables are read directly, without a second audit
archive. Backup snapshots, WAL/PITR and exported files require their own storage
and retention procedures; this worker does not erase those copies.

## Operation and verification

Startup initializes audit storage after access control and before serving the
console. Migrations add tables and timeline indexes on available source tables,
and recheck optional platform tables on later starts. Native Windows startup also
registers its audit tables after their own migrations and before launching its
listener or maintenance worker. A registration failure prevents native startup.
Only known Windows audit-row triggers are replaced by the scoped retention guard;
other Windows history and integrity triggers stay installed. The database account needs
schema/index/trigger creation and source audit DELETE permissions in addition to normal
read/write access. Index creation occurs in the bounded startup transaction and
can block writers; large existing installations should plan a maintenance window
and validate index creation time. No production-scale benchmark is claimed.

Each database read/export rechecks the actor's current permissions while holding
the same transaction lock used by permission changes. The ordinary session/2FA
checks, request-token/Origin CSRF and private gateway boundary still apply.
Exports and retention require small URL-encoded POST forms; duplicate/unknown
body fields are rejected and query parameters cannot override body credentials or
scope. Responses use `no-store` and `nosniff`; exports use fixed attachment names.
Database failures use fixed public messages without SQL or event data.

Disposable PostgreSQL tests cover migration idempotence, optional sources, cross
organization/site access, tied-timestamp pagination, export bounds, formula-like
CSV fields, permission revocation, default/global/disabled retention, stale and
replayed previews, concurrent cleanup, audit-write rollback and cancellation of a
worker waiting on the database. Real console routes exercise roles, second factor,
cookie/Origin CSRF, body limits, exact filters, attachment headers and confirmation.
Browser checks cover 390/768/1440 px layouts and keyboard confirmation. Physical
device acceptance and comprehensive legacy mutation auditing remain separate
roadmap work.

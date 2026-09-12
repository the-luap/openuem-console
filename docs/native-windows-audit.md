# Native Windows audit viewer and retention

The [shared audit log](audit-log.md) includes all twelve native Windows audit
sources. Organization administrators can read/export their organization's
metadata, including site-filtered history. Server administrators can also search
across organizations. Viewers and operators cannot access these audit routes.
CSP evidence downloads continue to use their separate protected service and
[JSON format](native-windows-csp-export.md).

## Source mapping

The source selector shows readable English labels. Filter values and CSV/JSON
source names remain the stable identifiers below. Each source has its own event
ID namespace for pagination, even when timestamps and numeric IDs are equal.

| Source identifier | Original audit table | Target and original scope |
| --- | --- | --- |
| `windows_enrollment` | `mdm_windows_audit` | Resource ID; stored organization/site |
| `windows_authority` | `mdm_windows_authority_audit` | Authority ID; organization-wide |
| `windows_management` | `mdm_windows_management_audit` | Session ID; stored organization/site |
| `windows_csp` | `mdm_windows_csp_audit` | Command ID; stored organization/site |
| `windows_updates` | `mdm_windows_update_audit` | Run ID; immutable update run organization/site |
| `windows_rings` | `mdm_windows_update_ring_audit` | Rollout ID, otherwise ring ID; stored organization/site |
| `windows_schedules` | `mdm_windows_update_schedule_audit` | Schedule ID; stored organization/site |
| `windows_console` | `mdm_windows_console_audit` | Resource ID, otherwise organization ID; stored organization/site |
| `windows_renewal` | `mdm_windows_renewal_audit` | Renewal ID; stored organization/site |
| `windows_unenrollment` | `mdm_windows_unenrollment_audit` | Report ID; stored organization/site |
| `windows_disconnection_requests` | `mdm_windows_unenrollment_request_audit` | Request ID; immutable request organization/site |
| `windows_certificate_reminders` | `mdm_windows_certificate_reminder_audit` | Delivery ID, otherwise reminder ID; immutable reminder organization/site |

Scope comes from original events or immutable parent records, never current device
placement, recipient membership or device-reported names. Organization-wide events
have site zero and cannot appear in a site search. Management session audit has no
stored actor column; its normalized actor is `windows-device`. Other sources use
their stored actor. All Windows events have result `recorded`: their action is
preserved, but the common viewer does not infer success, compliance, installation
or delivery from it.

The adapters select only event ID, time, actor, action, target and scope. They do
not copy arbitrary detail JSON, commands, observation values, passwords, private
keys, bootstrap secrets, packet bodies, mail addresses or SMTP errors. Existing
100-event pages, bounded CSV/JSON exports, transactional authorization checks and
read/export auditing apply unchanged.

## Explicit organization policy

Audit migration `002_windows_audit.sql` adds a Windows inclusion flag defaulting
to false to policies, previews and history. Existing finite policies and already
reviewed previews retain their previous deletion scope. Installing native Windows
or upgrading shared audit storage does not opt an organization into Windows
cleanup.

On the organization's **Retention policy** page, select **Include Windows audit
events in this retention policy**, enter 30–3,650 days and preview the change.
The page preserves the proposed days and selection, shows both old/new settings,
and lists eligible source counts. A separate unchecked confirmation applies the
ongoing policy. The saved preview, rather than extra confirmation form fields,
controls inclusion. Existing account/scope binding, permission rechecks, policy
revision conflicts, ten-minute expiry and one-use confirmation remain enforced.

Only organizations can include Windows events. The server-wide policy cannot
delete them, and there is no site policy. Clearing inclusion stops subsequent
Windows cleanup; choosing zero stops all cleanup for that organization. These
changes wait for an already running policy transaction and cannot restore prior
deletions. Windows payload, command, packet and observation retention is separate
work; audit cleanup does not delete or rewrite those records.

## Guarded deletion and startup

Shared audit initialization transactionally replaces only known Windows audit
UPDATE/DELETE triggers. All twelve audit tables receive the common guard, including
enrollment and authority audit tables that previously had no audit-row guard.
The original Windows command, enrollment identity, packet, observation and sealed
lifecycle guards remain installed. Optional native Windows startup repeats source
registration after Windows migrations and before launching its listener/worker;
registration failure stops native startup. Later audit initialization repairs a
missing or disabled common audit guard.

An eligible policy transaction locks the policy and selects at most 1,000 old
rows per available source using row locks and skip-locked selection. The cutoff
uses the database clock. Before deletion, it writes a retention receipt and an
immutable batch containing the exact event IDs, table OID, source, organization,
policy revision, cutoff and current transaction ID. A source trigger independently
requires that batch, a matching live enabled finite policy and matching receipt,
including count and event age. Updates are always rejected. Ordinary direct
deletes, foreign IDs, stale policy revisions and replay of a committed batch
cannot use that deletion authority. Cleanup refuses an unavailable guard.

All sources for one policy share a transaction. A later source or receipt failure
rolls back earlier deletions and receipts. Replicas coordinate through the policy
row lock. A full batch schedules another sweep in a minute; otherwise the policy
is due in an hour. The console checks due policies every minute. Receipts and
batch IDs remain indefinitely, with updates/deletes of Windows batch records and
their linked receipt rows rejected. The UI shows the latest 25 receipt/policy
records; older retention metadata remains searchable in the audit log.

A CSP export's `audit_id` can eventually refer to an event removed by an explicitly
confirmed Windows audit policy. Its source ID remains in the deletion batch. The
exported file and stored protected command evidence are unchanged. Receipts are
database evidence, not an independent signature or protection against a database
administrator. Backup/WAL/export copies need separate retention procedures.

## Verification

Disposable PostgreSQL tests exercise all twelve adapters, original organization
and site scope, role rejection, equal-time pagination, metadata-only CSV/JSON,
read/export audit rollback, a literal migration from the pre-Windows retention
schema, default-off pending previews, explicit inclusion, disabled policies,
concurrent sweeps, 1,000-row batches, retry scheduling, receipt failure rollback,
missing guard repair, immutable receipts and mismatched deletion authority.
Startup tests cover late optional table creation, restart and registration failure.
The complete audit PostgreSQL/race suite passes in **3.909 seconds**, audit views
in **2.412 seconds**, and webserver/startup tests in **1.918 seconds**. The actual
console route fixture passes in **12.598 seconds**; its live browser/race run
passes in **107.408 seconds**, including manual browser interaction. Vet and
complete Linux/Windows builds pass. The full Windows PostgreSQL/race suite also
passes in **161.787 seconds**, with protocol tests in **1.411 seconds**. Both full workflows pass for `26ee438`
([push](https://github.com/the-luap/openuem-console/actions/runs/34457649525),
[PR](https://github.com/the-luap/openuem-console/actions/runs/34457653660)).

The full console fixture uses the actual Windows migrations and synthetic
protocol-created parent records for every source. It demonstrates independent
organization cleanup, retained foreign events, confirmed forms, visible receipts,
and unchanged protected CSP exports before/after audit cleanup. Rendered tests
verify default, saved, proposed and cleared selections, and no global checkbox.
All fixture data is synthetic; no real device, provider or inbox is involved.

Browser checks use production cookie/Origin CSRF and native forms. Audit, preview
and receipt views remain contained at 390/768/1440 pixels. Keyboard selection,
preview, confirmation and JSON download work. The downloaded 500-event fixture
contains only the nine public metadata fields in the selected organization and
Windows CSP source. Clearing inclusion/setting zero and the global policy page
also pass. The owned browser tab, loopback listener and database schema are removed
after verification. Production-scale performance, comprehensive legacy audit
coverage and physical Windows acceptance remain open.

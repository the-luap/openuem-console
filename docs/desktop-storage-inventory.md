# Desktop storage inventory

Select **Reported storage** in a computer's inventory. Viewers, operators and
organization administrators can read physical and logical disk reports within
their current scope. Server administrators can use the dedicated page too.
`GET /computers/:uuid/inventory/storage` supports the default, organization and
organization/site URL prefixes. Delegated users of the existing GET
`physical-disks` and `logical-disks` aliases receive the corresponding scoped
report. Server administrators retain the legacy alias views.

Physical reports contain device identifier, model, serial number and reported
capacity. Logical reports contain label, volume name, filesystem, stored usage
percentage, reported free space, capacity and BitLocker status. The page also
shows device name, organization/site and last agent-report time. Report values
are escaped text, including markup-like names and encryption status. Missing
strings display **Not reported**. Out-of-range percentages remain visible with
an explicit label instead of being clamped or represented as valid usage.

These values describe stored reports. They do not verify current capacity,
usage or encryption. The existing logical-disk schema defaults usage to zero;
the page preserves that value and explains that it may be an older default,
not an observation of an empty disk. An empty page does not prove that the
device has no disks. No recovery keys, file browsing or device actions are
included. File upload, download, rename, deletion and folder endpoints gain no
additional permissions through this read capability.

`kind` selects `physical` (the default) or `logical`. Physical search matches
literal device identifiers, models or serial numbers; logical search matches
labels, volume names or filesystems. Search is case insensitive; `%` and `_`
are ordinary characters. At most 25 entries are returned, in stored ID order,
with a positive canonical `after` cursor for continuation. Search submits a
fresh first page; changing kind clears both search and cursor. First-page and
clear-search links retain the selected kind and scope.

Only `kind`, `q` and `after` are accepted, each at most once. A query is limited
to 4 KiB before parsing; search is limited to 256 UTF-8 bytes without control
characters. Malformed, duplicate, unknown and noncanonical parameters return
400. A legacy alias rejects a conflicting `kind` instead of silently opening
another report.

Each read rechecks transaction-bound `devices.read` authorization. A single
SQL statement selects exact device membership and the bounded report page;
foreign, waiting, unassigned or multiply assigned devices return 404. Cursors
confer no authority after a site move or grant revocation. The transaction must
commit an `inventory.storage.read` audit before report data is returned. Audit
failure returns a redacted 503, and successful responses use `no-store`. Audit
records contain the actor, actual organization/site and device ID without the
search or report contents. Existing inventory audit export and scoped retention
include storage reads.

Inventory migration 004 creates per-owner cursor indexes for both report tables.
For large existing installations, these indexes can be built ahead of the
bounded startup migration, outside a transaction:

```sql
CREATE INDEX CONCURRENTLY uem_inventory_physical_cursor
 ON physical_disks(agent_physicaldisks,id);
CREATE INDEX CONCURRENTLY uem_inventory_logical_cursor
 ON logical_disks(agent_logicaldisks,id);
```

Verify successful index completion before upgrading. The migration recognizes
the existing indexes. Audit migration 006 adds the storage action while
preserving the existing desktop, software and network read actions.

Tests use the actual Ent schema and disposable PostgreSQL databases: all fields,
stored defaults, literal searches, pagination, 50,000 foreign rows in each report
table, site moves, hidden objects, revoked grants, cancellation, audit failures,
repeated migrations and scoped audit export/retention. Real console-router tests
cover four roles, all three URL prefixes, both kinds and delegated aliases,
actual continuation links, malformed inputs and denied file operations.
Browser checks cover first/next/empty/long reports for viewers and operators at
390/768/1440 pixels, literal text, missing and invalid values, keyboard search,
scope-preserving links and page overflow. Collection from physical Windows/Mac
devices remains endpoint acceptance.

See [access control](access-control.md), [desktop console](desktop-console.md)
and the [implementation ledger](implementation-status.md).

# Desktop memory-module inventory

Select **Reported memory modules** in a computer's inventory. The dedicated
`GET /computers/:uuid/inventory/memory` page supports the default, organization
and organization/site URL prefixes. Viewers, operators and administrators can
read devices within their current scope. The hardware overview continues to
show its independently reported memory total and processor-core count.

The module page contains only slot, reported capacity, memory type, serial
number, part number, speed and manufacturer, together with device name,
organization/site and last agent-report time. Module values remain escaped
report strings. Capacity and speed keep their reported units; the page does
not calculate a new total from incomplete reports. Missing values display
**Not reported**. An empty page does not prove that a device has no memory
modules, and stored entries do not verify current capacity or complete module
coverage.

Search matches literal slot, serial number, part number or manufacturer text,
ignoring case. Percent and underscore have no wildcard meaning. Pages contain
at most 25 modules in stored entry-ID order. Next-page links preserve scope and
search; keyboard search resets the cursor. First-page and clear-search links
allow recovery when a new report replaces entries between requests.

Only `q` and a positive canonical `after` cursor are accepted, each at most once.
Raw queries are bounded to 4 KiB; search is limited to 256 UTF-8 bytes without
control characters. Invalid, duplicate or unknown parameters return 400.

Each request rechecks transaction-bound `devices.read` authorization. A single
SQL statement selects exact device membership and the bounded module page,
excluding foreign, waiting, unassigned and multiply assigned devices with 404.
Pagination grants no continued authority after a site move or rights revocation.
The transaction commits an `inventory.memory.read` audit before returning
report data. Audit failure returns a redacted 503 and successful responses use
`no-store`. Audit records include the actor, actual organization/site and device
ID without search text or module contents. Shared inventory audit export and
retention include these events. This page adds no mutation or device command.

Inventory migration 006 creates the per-owner cursor index. For a large existing
database, build it ahead of the bounded startup migration, outside a
transaction, and verify successful completion before upgrading:

```sql
CREATE INDEX CONCURRENTLY uem_inventory_memory_cursor
 ON memory_slots(agent_memoryslots,id);
```

The migration recognizes the existing index. Audit migration 008 adds the memory
read action and preserves the other five inventory read actions.

Tests use the real Ent schema and disposable PostgreSQL databases to cover every
projected field, missing values, all search fields, literal wildcards, bounded
continuation, 50,000 foreign entries, hidden devices, scope changes, revoked
grants, cancellation, audit failure and repeated migrations. Shared audit export
and retention cover all six inventory actions. Real console-router checks cover
four roles, all three URL prefixes, generated continuation links, malformed
queries and denied POSTs. Viewer/operator first/next/empty/long-report browser
states cover 390/768/1440-pixel widths, escaped strings, missing fields, visible
active navigation, native keyboard search and page overflow. Physical Windows/
Mac report collection remains endpoint acceptance.

See [access control](access-control.md), [desktop console](desktop-console.md)
and the [implementation ledger](implementation-status.md).

# Desktop peripheral inventory

Select **Reported peripherals** in a computer's inventory to view stored monitor
and printer reports. Viewers, operators and organization administrators can read
devices within their current scope. Server administrators can use the dedicated
`GET /computers/:uuid/inventory/peripherals` page as well. The default,
organization and organization/site URL prefixes are supported. For delegated
roles, existing GET `monitors` and `printers` aliases open the corresponding
scoped report; server administrators retain the legacy alias views.

Monitor reports contain model, manufacturer, serial number and reported
manufacture week/year. Printer reports contain name, port and default, network
and shared flags. The page also shows device name, organization/site and last
agent-report time. Missing text or flags display **Not reported**. Stored false
and true flags remain **No** and **Yes**, distinct from absent evidence. All
reported text is escaped, including names, serials and ports that resemble HTML
or addresses. Ports are text, without links, connection attempts or device
actions. These reports do not verify that a peripheral is connected, available
or working. An empty page does not prove absence.

`kind` selects `monitors` (the default) or `printers`. Monitor search matches
literal model, manufacturer or serial text; printer search matches name or port.
Search is case insensitive and treats `%` and `_` as ordinary characters. Pages
contain at most 25 entries in stored ID order. Continuation retains the selected
kind, scope and search; a new search starts on the first page. Changing kind
clears both search and cursor. First-page and clear-search links provide recovery
when reports change between requests.

Only `kind`, `q` and a positive canonical `after` cursor are accepted, each at
most once. Raw queries are bounded to 4 KiB before parsing. Searches are limited
to 256 UTF-8 bytes without control characters. Invalid, duplicate, unknown or
noncanonical parameters return 400, including a legacy alias with a conflicting
kind.

The read transaction rechecks current `devices.read` authorization. One SQL
statement selects exact device membership and the bounded report page. Foreign,
waiting, unassigned and multiply assigned devices return 404. A cursor cannot
retain access after a site move or grant revocation. An
`inventory.peripherals.read` audit must commit before report data is returned;
audit failure returns a redacted 503. Successful responses use `no-store`.
Audit records retain the actor, actual organization/site and device ID, without
search or report contents. The shared inventory audit source includes these
reads in scoped export and retention. Printer/monitor POST routes gain no
additional permission.

Inventory migration 005 adds per-owner cursor indexes. On large existing
databases, build them ahead of the bounded startup migration, outside a
transaction, and verify successful completion before upgrading:

```sql
CREATE INDEX CONCURRENTLY uem_inventory_monitor_cursor
 ON monitors(agent_monitors,id);
CREATE INDEX CONCURRENTLY uem_inventory_printer_cursor
 ON printers(agent_printers,id);
```

The migration recognizes existing indexes. Audit migration 007 adds the
peripheral action while preserving desktop, software, network and storage reads.

Disposable PostgreSQL tests use the actual Ent schema and cover every projected
field, all nullable printer flags, literal search, 25-entry continuation, 50,000
foreign rows in each table, hidden membership, site moves, revoked grants,
cancellation, audit failure and repeated migrations. Shared audit export and
retention cover all five inventory actions. Real console-router checks cover
four roles, all three prefixes, both kinds, delegated aliases, generated
continuation links, malformed inputs and forbidden POSTs. Viewer/operator
first/next/empty/long-report browser checks cover 390/768/1440-pixel widths,
literal text, missing flags, native keyboard search, visible active navigation
and overflow. Collection from physical Windows/Mac devices remains endpoint
acceptance.

See [access control](access-control.md), [desktop console](desktop-console.md)
and the [implementation ledger](implementation-status.md).

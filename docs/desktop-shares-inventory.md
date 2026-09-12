# Desktop share inventory

Select **Reported shares** in a computer's inventory. The dedicated
`GET /computers/:uuid/inventory/shares` page supports the default, organization
and organization/site URL prefixes. Viewers, operators and administrators can
read devices within their current scope. The legacy `GET /computers/:uuid/shares`
delegates scoped readers to this page; server administrators retain the legacy
view on that alias.

Only share name, description and path are projected, together with device name,
organization/site and last agent-report time. Values remain escaped report text.
UNC paths, URLs and script-like strings are never converted into links or used
to open a remote resource. Missing values display **Not reported**. An empty page
does not prove that a device has no shares, and stored entries do not verify
current availability, access rights or complete coverage.

Search matches literal name, description or path text, ignoring case. Percent
and underscore have no wildcard meaning. Pages contain at most 25 shares in
stored entry-ID order. Next-page links preserve scope and search; keyboard
search resets the cursor. First-page and clear-search links allow recovery
when a new report replaces entries between requests.

Only `q` and a positive canonical `after` cursor are accepted, each at most once.
Raw queries are bounded to 4 KiB; search is limited to 256 UTF-8 bytes without
control characters. Invalid, duplicate or unknown parameters return 400.

Each request rechecks transaction-bound `devices.read` authorization. A single
SQL statement selects exact device membership and the bounded report page,
excluding foreign, waiting, unassigned and multiply assigned devices with 404.
Pagination grants no continued authority after a site move or rights revocation.
The transaction commits an `inventory.shares.read` audit before returning data.
Audit failure returns a redacted 503 and successful responses use `no-store`.
Audit records include actor, actual organization/site and device ID, without
search text or share contents. Shared inventory audit export and retention
include these events. The page grants no mutation or file-operation permission.

Inventory migration 007 creates the per-owner cursor index. For a large existing
database, build it ahead of the bounded startup migration, outside a transaction,
and verify successful completion before upgrading:

```sql
CREATE INDEX CONCURRENTLY uem_inventory_shares_cursor
 ON shares(agent_shares,id);
```

The migration recognizes the existing index. Audit migration 009 adds the share
read action and preserves the other six inventory read actions.

Tests use the real Ent schema and disposable PostgreSQL databases to cover all
fields, missing values, literal search, bounded continuation, 50,000 foreign
entries, hidden devices, scope changes, revoked grants, cancellation, audit
failure and repeated migrations. Audit export and retention cover all seven
inventory actions. Real console routes cover four roles, three URL prefixes,
delegated aliases, actual continuation links, malformed queries and denied
POSTs. Viewer/operator first/next/empty/long-report browser states cover
390/768/1440-pixel widths, literal paths, escaped markup, missing fields, active
navigation, native keyboard search and page overflow. Physical Windows/Mac
collection and real share availability remain endpoint acceptance.

See [access control](access-control.md), [desktop console](desktop-console.md)
and the [implementation ledger](implementation-status.md).

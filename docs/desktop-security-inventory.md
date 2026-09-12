# Desktop security report inventory

Select **Reported security** in a computer's inventory. The dedicated
`GET /computers/:uuid/inventory/security` page supports the default, organization
and organization/site prefixes. Viewers, operators and administrators can read
devices within their current scope. The legacy `GET /security/:uuid/updates`
delegates scoped readers to this page. Server administrators retain the legacy
view on that alias; scoped readers receive no legacy POST permission.

The page separates the reported antivirus product and active/definition flags,
system update status and pending flag, last installation/search times, and a
bounded update history. Each history entry contains its reported title, date
and support URL. Organization/site and last agent-report time identify the
report's context. No agent configuration, user identity, remote-access material,
task output or recovery key enters the projection.

These are stored observations. Existing collectors can leave default false
flags, empty strings and zero dates when collection is incomplete. A reported
false value remains **No**, with the report limitation visible; it does not prove
inactive protection or that no updates are pending. An absent antivirus/update
record leaves its flags **Not reported**. Empty text remains **Not reported**.
The database projection preserves timestamps, including legacy zero values;
the view displays nil/Go-zero dates as **Not reported**, matching the collector's
unknown-date convention. Other timestamps retain their exact instant and UTC
machine-readable value through the shared localized timestamp component.

History does not prove successful or current installation, complete patch
coverage or absence of later changes. An empty page does not mean that no
updates are installed. Support URLs remain escaped text, including script-like
strings; rendering never navigates to them or fetches their contents. Report
strings are not interpreted as translation keys or HTML.

Search matches literal update title or support URL text, ignoring case. Percent
and underscore have no wildcard meaning. History pages contain at most 25
entries in stored entry-ID order; this is report order, not a date sort or a
claim to show the latest patches. Status summaries remain visible independently
of history filters. Next-page links retain scope and search. Keyboard search
resets the cursor; first-page and clear-search links support recovery when a new
report replaces history between requests.

Only `q` and one positive canonical `after` cursor are accepted. Raw queries are
limited to 4 KiB, and search to 256 UTF-8 bytes without control characters.
Duplicates, unknown parameters and malformed values return 400.

Every request rechecks transaction-bound `devices.read` authorization. A single
SQL statement selects current exact device membership, both one-to-one status
reports and bounded history. Foreign, waiting, unassigned and multiply assigned
devices return 404. Cursors confer no authority after scope or grant changes.
An `inventory.security.read` audit must commit before data is returned. Audit
failure returns a redacted 503; successful responses use `no-store`. Audit
records include actor, actual organization/site and device ID, without search
or report contents. Shared export and retention include these events.

Inventory migration 008 adds the per-owner history cursor index. For a large
existing database, build it outside a transaction before the bounded startup
migration, and verify successful completion before upgrading:

```sql
CREATE INDEX CONCURRENTLY uem_inventory_security_cursor
 ON updates(agent_updates,id);
```

The migration recognizes the existing index. Audit migration 010 preserves all
seven earlier inventory actions and adds security reads.

Real Ent/PostgreSQL tests cover every projection, absent reports, independent
boolean values, unknown status text, timestamp precision/zero dates, all search
fields, 25-entry continuation, 50,000 foreign history entries and foreign status
records. Hidden devices, moves, grant revocation, cancellation, audit failure,
repeated migrations and eight-action export/retention are included. Actual
console routes check four roles, three prefixes, delegated aliases, generated
continuation links, invalid queries and denied POSTs. Browser fixtures cover
viewer/operator first/next/empty/long/missing/negative states at 390/768/1440
pixels, native keyboard search, literal values and page overflow. Physical
collection and actual protection/patch acceptance remain endpoint work.

See [access control](access-control.md), [desktop console](desktop-console.md)
and the [implementation ledger](implementation-status.md).

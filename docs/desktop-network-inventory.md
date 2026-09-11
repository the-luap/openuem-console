# Desktop network inventory

## Scoped report page

Open a computer inventory and select **Reported network**. Viewers, operators
and organization administrators can read devices in their permitted scope. The
dedicated `GET /computers/:uuid/inventory/network` page also serves server
administrators. For delegated roles, the existing
`GET /computers/:uuid/network-adapters` alias opens this scoped page. All three URL
prefixes (default, organization and organization/site) are supported.

The page projects only adapter name, MAC and IP addresses, subnet, default
gateway, DNS servers/domain, DHCP flag, speed and virtual-adapter flag, with
device name, organization/site and last agent-report time. Optional flags remain
nullable: **Not reported** is distinct from a stored **No**. A legacy schema
default may already have stored a false flag; the page cannot reconstruct whether
an older agent omitted that field. Lease times, credentials and remote-control
data are excluded. All report strings are rendered as escaped text.

Search matches literal text in adapter names, MAC addresses or IP addresses,
ignoring case. Percent and underscore have no wildcard meaning. Only `q` and a
positive canonical `after` cursor are accepted, each at most once. Search is
limited to 256 UTF-8 bytes and raw queries to 4 KiB; malformed UTF-8, control
characters, duplicate or unknown parameters and invalid cursors return 400.
Keyboard search resets pagination, and continuation preserves scope and search.

Pages contain at most 25 adapters in stored entry-ID order. **First page** and
**Clear search** provide recovery when a new report replaces entries between
requests. Stored reports do not verify current connectivity or configuration.
An empty report does not prove the absence of network adapters.

Current `devices.read` authorization and `inventory.network.read` audit commit
in the same transaction. A single query selects device membership and adapters,
so concurrent membership changes cannot mix separate scope snapshots. Foreign,
waiting, unassigned and multiply assigned devices return 404. A previous cursor
cannot preserve access after a device moves or rights are revoked. Audit failure
returns a redacted 503 with no report data. Successful responses use `no-store`.
Audit events contain actor, actual organization/site and device ID, without
search text or report contents. The existing inventory audit source, export
permissions and retention rules include these events.

Inventory migration 003 adds `(agent_networkadapters,id)` for per-device cursor
reads. On a large existing database, an operator can create the index before
upgrading, outside a transaction, to keep its build out of the bounded startup
migration:

```sql
CREATE INDEX CONCURRENTLY uem_inventory_network_cursor
 ON network_adapters(agent_networkadapters,id);
```

Check that the index completed successfully before starting the upgraded
console. The migration recognizes the existing index. Audit migration 005 adds
the network-read action while preserving desktop and software audit records.

PostgreSQL tests exercise the real Ent schema, all projected fields, nullable
flags, literal searches, continuation, 50,000 foreign entries, hidden devices,
site moves, revoked grants, cancellation, audit failure and repeated migrations.
Real-router tests cover scoped roles, URL aliases, invalid queries and forbidden
mutations. Viewer/operator first/next/empty/long-report browser states cover
390/768/1440 pixels, exact report text, keyboard search, continuation and overflow.
Physical Windows/Mac collection remains endpoint acceptance.

## Legacy administrator rendering

The existing server-administrator network adapter page shows agent-reported DNS
servers and the DNS domain as visible, labeled text. IPv4/IPv6 strings, domain
names, markup-like text and long values are preserved with normal template
escaping. The table scrolls inside a keyboard-focusable region on narrow screens.
No DNS value is passed to an HTML tooltip or another markup interpreter.

The previous page escaped the tooltip attribute during server rendering, but the
bundled UI library subsequently interpreted its value as HTML. An owned browser
fixture reproduced this second interpretation: before showing the tooltip there
were no injected elements or executed marker; afterwards two synthetic elements
were present and their harmless error handler had run. The fixture used an inert
data URI and never read credentials or contacted a device or external service.

The regression renders the actual network adapter page and loads the repository's
production UI assets. Ordinary, injected, long and empty reports are checked at
390, 768 and 1440 pixels. Reported values remain literal readable text, no injected
elements or script marker appear, narrow tables remain reachable and the page
does not overflow. Before the layout correction, ordinary and long reports made
the 390-pixel page 810 pixels wide and the 768-pixel page 874 pixels wide. All twelve
network cases now pass, and the complete browser suite passes 333 cases. The
computer-view race tests also pass.

Server administrators retain this legacy view on the existing alias; delegated
roles use the scoped page described above. Remaining legacy detail/action
authorization work stays part of SEC-01.
See [access control](access-control.md), [scoped desktop reports](desktop-console.md)
and the [implementation ledger](implementation-status.md).

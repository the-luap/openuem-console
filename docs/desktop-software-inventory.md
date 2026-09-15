# Scoped desktop software inventory

Open a computer's inventory and select **Reported software**. Viewers, operators
and organization administrators can read reports for their permitted devices.
The dedicated `/computers/:uuid/inventory/software` page also serves server
administrators. The existing `GET /computers/:uuid/software` URL opens the scoped
page for delegated roles; server administrators keep its existing legacy view.
All three organization/site URL prefixes are supported.

The page shows only reported name, version, publisher and installation date,
together with the device name, organization/site and last agent-report time.
Installation dates remain the strings supplied by the agent: the console does
not invent a timezone or precision. These observations do not establish the
device's current state or verify a software deployment. Missing entries also do
not prove that the device has no installed software.

Search matches literal text in the name or publisher, ignoring case. Percent
and underscore characters are ordinary search text. Queries accept only `q`
and an optional positive `after` cursor, each at most once. Ambiguous parameters,
control characters, invalid UTF-8 and overlong search values are rejected. Search
is limited to 256 UTF-8 bytes and query strings to 4 KiB. Searching starts at the
first page and pagination preserves the search and selected URL scope.

Each page contains up to 25 entries ordered by their stored report-entry ID.
The continuation cursor avoids offset pagination and cannot grant access to a
different device. A new agent report can replace entries between page requests;
the page does not promise an immutable inventory snapshot. Use **First page**
or clear the search to start again.

Inventory migrations add the `(agent_apps,id)` index used by per-device
continuation. For a large existing database, operators can create it before
upgrading, outside a transaction, to avoid doing the index build inside the
console's bounded startup migration:

```sql
CREATE INDEX CONCURRENTLY uem_inventory_software_cursor ON apps(agent_apps,id);
```

The normal migration recognizes an existing index. Check that any pre-created
index completed successfully before starting the upgraded console.

The database checks current `devices.read` grants in the same transaction as
the read audit. A single SQL statement projects the permitted device and its
software page, so a concurrent site move cannot mix two membership snapshots.
Waiting, unassigned, foreign and ambiguously assigned devices return 404.
`inventory.software.read` records actor, actual scope and device ID before data
is returned. Audit failure returns a redacted unavailable response. Search text
and software contents are excluded from the audit event; the existing inventory
audit source, export permissions and retention rules apply.

No deployment or removal is performed by this page. Legacy software mutations
retain their server-administrator boundary while scoped deployment authorization
and verified endpoint outcomes remain separate roadmap work.

PostgreSQL tests cover real Ent reports, literal search, bounded continuation,
empty pages, 50,000 foreign report entries, hidden devices, moves between pages, revoked grants, cancellation,
audit rollback and repeated migrations. Router tests cover scoped roles and URL
aliases, malformed queries, response privacy and audit failures. The permanent
Chrome suite covers viewer/operator first/next/empty/long-report states at
390/768/1440 pixels, keyboard search, exact continuation URLs, markup escaping
and page overflow. Physical Windows/Mac collection remains endpoint acceptance.

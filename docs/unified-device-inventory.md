# Unified device inventory

The shared **Devices** page searches admitted desktop agents, native Apple
devices, linked Mac management channels and native Windows enrollments in the
selected organization or site. Search covers names, serial numbers, models and
reported OS versions. Platform filters distinguish iOS, iPadOS, macOS, Windows,
Linux, all Apple devices and unidentified platforms.

Choose names in ascending or descending order, or last contact with the newest
or oldest report first. Devices without a reported contact time always follow
devices with a known time. PostgreSQL applies the filter and order before
returning 25 rows; name, source and identity resolve contact-time ties. Equal
names do not collapse identities or repeat entries on an unchanged dataset.
**Next page** retains the scope, filters and sorting; **First page** restarts the
query. Submitting the filter form also restarts pagination. The count describes
the displayed page, not the entire
inventory. Native Windows search includes older enrollments beyond the former
100-entry preview.

Each request reads a fresh database snapshot. Changing a name, scope or channel
association between requests can change its position; pagination is not a frozen
export. Cursor values only identify a position and are bound to the original
scope, filters, sorting and enabled sources. They do not grant access. Requests reject
unsupported filters, duplicate/unknown query fields, malformed cursors and
oversized or invalid search text. The raw query is bounded to 16 KiB and malformed
URL encoding is rejected rather than silently discarding a filter. Reads have a
ten-second deadline.

The server rechecks current permissions and commits an `inventory.devices.list`
audit event before returning data. Scope membership and the safe inventory
projection are read together; passwords, enrollment credentials, push material,
private keys, signed-in users and full report JSON are excluded. Disabled source
stores contribute no rows. The response prohibits caching.

Delegated readers cannot see unadmitted agents or agents with ambiguous site
assignments. Server administrators retain the existing ability to inspect an
ambiguous assignment; the list shows one row and uses a deterministic matching
site. Linked Macs keep their canonical navigation and historical channel
suppression. Native Windows and desktop identities remain separate without a
verified association. Native Windows status uses the current certificate after
confirmed renewal and checks disconnection/revocation consistency.

**Download CSV** and **Download JSON** export all matching devices in the selected
order, including matches beyond the visible page. A CSRF-protected POST supplies
the filters and format; query parameters, repeated fields and page cursors are
rejected. The export uses the same safe projection and current read permission
as the list. File preparation and the audit share one transaction, so an audit
failure returns no file. The response is an attachment with caching and MIME
sniffing disabled.

Exports are limited to 5,000 entries and 16 MiB, with two preparations per console
process and the same ten-second transaction deadline. Individual metadata fields
are bounded to 4 KiB before database delivery; IDs are bounded to 255 bytes.
Oversized results fail without partial output or silent truncation. Narrow the
filters when a result exceeds these bounds.

Both formats include the management source, device/organization/site IDs, name,
platform, OS version, serial, model, management status, separate Mac agent status
and last contact. Source/platform/status values are stable codes. Contact times
use UTC with retained subsecond precision; missing times are blank in CSV and
`null` in JSON. JSON is an array of objects and preserves original field values.
CSV adds a visible `[text] ` prefix to formula-shaped or multiline text, using
the same cell protection as audit exports.

Audit migrations 11 and 12 add list and export actions to the existing inventory
source. Site zero is allowed for organization-wide list/export events; other
inventory actions still require a positive site. Successful export preparation
records `inventory.devices.export_csv` or `inventory.devices.export_json`; this
does not assert that a browser finished downloading the file. These events use
the existing scoped viewer, export and explicit retention workflow. Search text
is not copied into audit records.

Owned PostgreSQL evidence covers 55 equal-name entries, 105 native Windows
enrollments plus a separate agent, literal wildcard/injection-shaped searches,
platform projections, equal contact times, missing-time pages in both directions,
hidden assignments, current permissions, audit failure
and organization scope. Existing registered console routes cover linked Macs,
native Windows lifecycle and scope boundaries. Chrome cases cover first, next,
empty and long-metadata pages at 390, 768 and 1440 pixels, keyboard activation,
retained filter links, keyboard export submission and page overflow. Export
tests cover all matching rows, exact JSON values, CSV cell protection, UTC/null
times, current role/scope checks, failed audit, cancellation, concurrent capacity,
encoded-size limits, oversized metadata and the 5,000/5,001-entry boundary.

Bulk actions, dynamic groups and
production-scale database performance acceptance remain separate roadmap work.

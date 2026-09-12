# Unified device inventory

The shared **Devices** page searches admitted desktop agents, native Apple
devices, linked Mac management channels and native Windows enrollments in the
selected organization or site. Search covers names, serial numbers, models and
reported OS versions. Platform filters distinguish iOS, iPadOS, macOS, Windows,
Linux, all Apple devices and unidentified platforms.

PostgreSQL applies the filter and sorts by case-insensitive name, source and
identity before returning 25 rows. Equal names do not collapse identities or
repeat entries on an unchanged dataset. **Next page** retains the scope and
filters; **First page** restarts the query. Submitting the filter form also
restarts pagination. The count describes the displayed page, not the entire
inventory. Native Windows search includes older enrollments beyond the former
100-entry preview.

Each request reads a fresh database snapshot. Changing a name, scope or channel
association between requests can change its position; pagination is not a frozen
export. Cursor values only identify a position and are bound to the original
scope, filters and enabled sources. They do not grant access. Requests reject
unsupported filters, duplicate/unknown query fields, malformed cursors and
oversized or invalid search text. Reads have a ten-second deadline.

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

Audit migration 11 adds the list action to the existing inventory source. Site
zero is allowed only for organization-wide list events; other inventory actions
still require a positive site. These events use the existing scoped viewer,
export and explicit retention workflow. List searches themselves are not copied
into audit records.

Owned PostgreSQL evidence covers 55 equal-name entries, 105 native Windows
enrollments plus a separate agent, literal wildcard/injection-shaped searches,
platform projections, hidden assignments, current permissions, audit failure
and organization scope. Existing registered console routes cover linked Macs,
native Windows lifecycle and scope boundaries. Chrome cases cover first, next,
empty and long-metadata pages at 390, 768 and 1440 pixels, keyboard activation,
retained filter links and page overflow.

Configurable sorting, shared device exports, bulk actions, dynamic groups and
production-scale database performance acceptance remain separate roadmap work.

# Desktop tag assignments

The existing agent and computer lists now use a shared transactional tag
assignment operation. The agent update list uses the same removal operation;
the legacy admission flow uses it when applying an organization's default tag
after enabling an agent. These actions retain their server-administrator
boundary. Delegated organization catalog access does not grant access to legacy
desktop actions.

## Scope and atomicity

Each request changes one device/tag membership. The device must have exactly one
site across the entire database and belong to the selected organization and,
when specified, site. Admitted enabled, disabled and non-contacting devices are
eligible; waiting, orphaned and ambiguously assigned devices are rejected.
Adding a tag requires the tag's current organization to match the device.

A server administrator can remove an existing legacy association to a foreign
or unscoped tag to repair old data. A foreign tag without such an association is
not an available target. Errors do not disclose foreign tag names or database
details. Other memberships survive concurrent additions and removals. Repeated
operations on an organization's own tag are idempotent and audited.

Authorization, the organization/site, complete site membership, device and tag
remain locked through the audit commit. The ten-second transaction bound and
request cancellation apply while waiting for locks. Audit failure rolls back
the membership change. Legacy writers that acquire locks in another order may
cause a transaction conflict; refresh and retry instead of assuming success.

This operation changes tag metadata without sending a device command. It does
not make the rest of legacy admission, device moves or profile assignment
transactional. Those workflows retain their own implementation and permissions.

## Forms, audit and upgrade

The bundled HTMX client sends additions in a URL-encoded POST body and removals
in DELETE query parameters with a CSRF header. Identity fields must be single,
canonical values in the expected source. Duplicate or mixed query/body targets,
malformed values and oversized requests are rejected. Pagination and filter
fields remain available; a filter-only POST does not change tags. Rendering a
list after another action does not replay a tag mutation from that action's
form. The existing global CSRF and origin checks remain required.

Audit migration 15 adds `inventory.tags.assign` and `inventory.tags.unassign` to
the existing inventory source. Every event records the actual organization/site,
actor and `device ID/tag ID/current tag revision`. Resource references accept up
to 320 characters for these two actions so the longest supported legacy device
ID is retained in full. The exact target filter accepts the same bound. Other
inventory event limits remain unchanged. Existing
scoped audit browsing, export and retention apply. An event identifies the tag
revision used; it does not copy historical tag fields.

Apply the migration and stop older console writers before enabling the new
actions. Existing assignments are preserved. The old unscoped model mutation
methods have been removed from all tag-action callers.

## Verification

Owned PostgreSQL/race tests reproduce the original cross-organization assignment
and verify its rejection, legacy repair, organization/site/status restrictions,
administrator-only authority, concurrent membership preservation, no-op retries,
rollback, cancellation, current-source waits and locks held through final audit.
Long device references remain searchable and exportable in their recorded site.
Registered console routes exercise both lists and the update-page removal, with
the production CSRF middleware covering valid and invalid header/cookie tokens.
Browser checks use the bundled HTMX script and shared tag components to inspect
keyboard-triggered method, path, identity, CSRF, pagination and filter parameters.
The update list also handles absent installed-release evidence, with or without
an available release catalog, without crashing or claiming devices are current.

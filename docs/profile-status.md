# Legacy profile status

Enabling or disabling an existing desktop task profile now requires current
server-administrator authority and the profile's exact selected audience. The
global, organization and site routes use the same audience checks as
[profile tag assignments](profile-tag-assignments.md). A profile belonging to
another organization, a different site or an ambiguous audience cannot be
changed through the current URL.

The status action changes only `disabled`. It preserves the name, type,
apply-to-all mode, tasks, tags and audience associations. Repeated requests for
the same state are idempotent and audited. The ten-second transaction holds
permission, organization/site, complete audience and profile locks through audit
commit. Failed audit, cancellation or conflicting scope changes leave no partial
status update. The tag action shares the same profile-authority transaction.

The list now uses native buttons that work with the keyboard. Each button sends
its current page, page size and sorting in an HTMX POST, with the existing CSRF
header. Status and target come exclusively from the registered route. Strict,
bounded forms reject additional target/status fields, duplicates, query values
and malformed input. Legacy empty POST bodies and native form CSRF tokens remain
supported. The production CSRF and origin middleware runs before the action.

Audit migration 17 adds `inventory.profiles.enable` and
`inventory.profiles.disable` with the exact original scope, actor and profile ID.
Global profile events use organization/site zero; organization readers do not
gain access to global events. Existing scoped audit browsing, filtering, export
and retention apply. Apply the migration and stop older console writers before
enabling these actions; the old direct model status method has been removed.

The saved status controls eligibility in the existing worker workflow. It is not
proof that tasks have executed, and this operation sends no device command.
Task definitions and other profile mutations remain separate workflows; changing
status does not capture an immutable review of task contents or add delegated
access to the legacy editor.

Owned PostgreSQL/race tests cover all three scopes, role restrictions, unchanged
definition/task/tag data, no-op retries, rollback, cancellation, changed audience
edges and final audit locks. The actual console route test reproduces the former
foreign-organization enable and verifies rejection. Registered enable/disable
routes also check CSRF, strict forms, saved state and scoped audit events. Browser
tests use the real component and bundled HTMX to verify keyboard activation,
route targets, CSRF, preserved pagination/sorting and narrow-screen rendering.

# Legacy profile audience moves

Server administrators can move a site profile to its organization, or an
organization/site profile to the global scope. Each action now verifies the
profile's complete current audience against the selected route. Foreign,
ambiguous, orphaned or mismatched audience associations prevent the move. The
destination is derived from the current organization and the registered action;
forms cannot nominate another organization or site.

Moving a profile preserves its name, type, enabled state, tasks, tags and
apply-to-all setting. A global move removes its organization and site edges. A
site-to-organization move removes the site edge and retains its one verified
organization edge. A retry through the old source URL returns not found once the
profile has moved. An already global profile cannot be moved by these actions,
and the organization action requires a site source.

The existing worker uses these associations when selecting eligible profiles.
An enabled profile can therefore apply to more devices after a move, subject to
its existing assignment rules. Native keyboard-accessible buttons ask for browser
confirmation and explain the wider scope. Canceling sends no request. These
actions preserve list pagination and sorting in the existing HTMX POST, with
the production CSRF header or form token. Strict forms reject duplicate values,
query fields, destination overrides and bodies exceeding 8 KiB, including wire
padding before CSRF parsing.

The ten-second transaction holds current server authority, the source
organization/site, the complete audience tables and the profile row through
commit. Audience writers acquire `SHARE ROW EXCLUSIVE` before reading, avoiding
an upgrade deadlock between concurrent moves. Status and tag actions retain
their existing shared audience lock. Concurrent audience or permission changes
cannot bypass the final checks; cancellation and failed audit leave the original
audience intact.

Audit migration 18 adds `inventory.profiles.move_global` and
`inventory.profiles.move_organization`. Each successful transaction writes two
receipts, one in the source scope and one in the destination scope, with the actor
and `profileID/from/tenant/site/to/tenant/site` reference. Existing audit browsing,
export and scope-specific retention apply independently to each receipt. A
source organization retains its own evidence after a global move; its readers do
not gain access to global events. A failure writing the destination receipt also
rolls back the source receipt and both audience changes. Apply the migration and
stop older console writers before enabling the new actions.

Owned PostgreSQL/race tests cover all three moves, role restrictions, exact
audience validation, unchanged profile definitions, stale source retries,
parallel moves, cancellation, destination-audit rollback and final permission,
profile, audience and site locks. Actual registered console tests reproduce and
reject both former foreign-organization moves, and verify CSRF, strict forms,
saved state and both audit receipts. Real component/browser tests exercise
keyboard confirmation and cancellation at 390, 768 and 1440 pixels.

This operation changes the current audience; it does not capture an immutable
review of task definitions or prove execution on a device. Profile definition
editing, cloning, deletion and task lifecycle changes remain separate workflows.

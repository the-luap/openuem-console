# Legacy profile name and assignment mode

Saving an existing desktop task profile now verifies current server-administrator
authority and the profile's exact global, organization or site audience. The
dedicated POST handler validates the request before loading the editor. A foreign,
ambiguous or moved profile cannot be changed through the selected scope's URL.
The former direct `Model.UpdateProfile` method has been removed.

The transaction changes the name and one explicit assignment mode:

| Mode | Apply to all | Existing profile tags |
| --- | --- | --- |
| `useTags` | False | Preserved |
| `applyToAll` | True | Removed |
| `dontApplyToAll` | False | Removed |

These are the existing worker semantics. Unknown or omitted modes now fail
validation instead of silently clearing assignments. Names must contain
non-whitespace text, be valid UTF-8 and fit 2,048 bytes. Multiline names and tabs
remain supported; other control characters are rejected. The strict 8 KiB form
accepts one name, one mode and optional single CSRF/pagination/sorting values.
It rejects query values, duplicate fields and alternative profile identities.
The production CSRF middleware enforces the wire limit before token extraction,
including bodies padded with repeated separators.

The shared profile transaction holds permission, organization/site, complete
audience and profile locks for at most ten seconds. The name update, assignment
flag, tag removals and audit event commit together. Cancellation, audit failure
or changed scope leaves the prior definition and tags intact. Tasks, profile
type, enabled state and audience associations are preserved. Accepted concurrent
saves serialize at the profile row; this workflow does not yet provide revision
conflict detection for an editor opened before another change.

Audit migration 19 adds `inventory.profiles.update`, with the original scope,
actor and `profileID/assignment/mode` reference. Global events retain the same
server-only visibility as the other legacy profile actions. Existing inventory
audit browsing, export and retention apply. Repeated accepted saves are audited.
Apply the migration and stop older console writers before enabling this path.

The editor now selects exactly one mode. An existing apply-to-all profile with
retained legacy tags displays apply-to-all, rather than allowing the browser to
choose between two selected options. Tag controls are initially visible only in
tag mode. Shared real components retain multiline names, use the available width
on narrow screens, and send the two edited fields through the existing HTMX and
CSRF mechanism. Saving remains keyboard accessible.

Owned PostgreSQL/race tests cover all scopes and modes, current roles, unchanged
tasks/type/status/audience, tag preservation or removal, no-op saves, name/form
bounds, audit rollback, cancellation, pending audience changes and final audit
locks. Actual registered console tests reproduce and reject the former
foreign-organization update, and check saved state, strict forms, CSRF and audit.
Browser tests render the actual editor components across three scopes and four
stored states at 390, 768 and 1440 pixels, including the mixed legacy state.

Saving changes worker eligibility; it does not prove task execution. Profile
creation, cloning, deletion, editor reads, task lifecycle and immutable definition
history remain separate workflows.

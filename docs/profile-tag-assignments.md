# Legacy profile tag assignments

Adding and removing tags from existing desktop task profiles now use a bounded,
audited transaction. These profile actions remain restricted to server
administrators. Organization tag-catalog permissions do not grant access to the
legacy profile editor or its tasks.

## Exact profile audience

The selected route must match the profile's complete current audience:

- A global profile has no organization or site associations.
- An organization profile has exactly that organization and no site association.
- A site profile has exactly that organization and that site, whose current
  parent must be the same organization.

Multiple, crossed or incomplete associations cannot be edited through a smaller
route. The operation preserves these associations instead of normalizing them.
A global profile may use tags from any existing organization, preserving the
worker's global-template semantics. An organization or site profile may add only
tags from its own organization. Unscoped tags cannot be newly assigned.

An administrator may remove an existing foreign or unscoped tag association from
the correctly selected profile. A foreign or unscoped tag with no such association
is not a valid repair target. Other memberships are preserved, including when
different tags are changed concurrently.

Adding a tag disables `apply_to_all` in the same transaction, matching the existing
tag-selection behavior. Removing a tag preserves the current assignment mode.
An audit failure or canceled request rolls back both membership and any mode
change. This operation does not send a device command or change profile tasks.

## Authorization, forms and audit

Current server authority, organization/site rows, both complete profile-audience
relations, the profile and the tag stay locked through the audit commit. The
transaction has a ten-second bound. Concurrent scope or permission changes wait;
completed changes are checked again when an operation acquires the source locks.
Conflicts with older writers fail without applying a partial assignment.

The existing HTMX forms retain POST-body additions and DELETE-query removals,
with the global CSRF header/cookie and origin checks. The hidden target must
exactly match the canonical profile ID in the route. Duplicate, mixed-source,
malformed and oversized identities are rejected. The [scoped editor](profile-editor.md) now uses independent bounded panel forms
with applied-tag paging and available-tag search. Native panel changes read
their response before the same mutation/audit commit; cached whole-editor forms
redirect after commit. Metadata and task paging are not submitted with panel
changes.

Audit migration 16 adds `inventory.profile_tags.assign` and
`inventory.profile_tags.unassign`. Events record the exact global, organization
or site scope, actor and `profile ID/tag ID/current tag revision`. Only these
actions may use organization/site zero for a global profile. Other inventory
event scope limits remain unchanged. Global events are available to server
administrators; organization audit views do not include them. Scoped browsing,
exact-reference filtering, export and retention continue to apply.

Apply the migration and stop older console writers before enabling the actions.
Existing profile scopes and tag memberships are preserved. The old direct model
methods have been removed from both tag-action callers. Profile definition edits,
task changes, cloning, deletion and audience moves remain separate legacy
workflows; this change does not grant them delegated permissions or add their
missing transactional audit coverage.
[Profile status changes](profile-status.md) now share the same bounded authority
and audience transaction while preserving tags and assignment mode.

## Verification

Owned PostgreSQL/race tests reproduce the original cross-organization write and
cover global/organization/site matching, foreign and unscoped repair, ambiguous
audiences, assignment mode, concurrent membership changes, audit rollback,
cancellation, current-source waits and locks held through the final audit.
Scoped audit and JSON export tests verify that organization views exclude global
profile events. Registered console routes use the production CSRF middleware
and cover all three route scopes, hidden-target equality, duplicate/mixed fields,
foreign objects and retained assignment behavior. Real-browser checks use the
bundled HTMX script and shared tag components to inspect keyboard-triggered
methods, paths, target IDs, CSRF headers and list context.

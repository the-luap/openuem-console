# Apple updates from organization groups

Select a target site, open an [Apple update plan](apple-update-plans.md), choose
**Assign to a dynamic group**, then **Organization groups**. The chooser lists
organization-level groups. The preview evaluates the selected group's current
rule only within the selected site and shows eligible native Apple enrollments,
current policies that would be replaced, and exclusions within that site.
Devices belonging to other sites are outside this action.

Review the complete selection and explicitly confirm the immediate assignment,
or save a [scheduled activation](apple-update-organization-schedules.md) for a
future UTC window.
The same organization rule can be used in another site after a separate review.
This action does not continuously reconcile membership or automatically assign
updates across sites. **Site groups** retains the existing site-group workflow.
Organization-source previews also offer a schedule form with the same reviewed
selection. Pilot promotion destination selectors currently use site groups.

## Scope, authority and confirmation

Every action route requires an explicit target site. Organization-only URLs
cannot use a default site. Source kind is retained in chooser and preview links
and in the confirmation's `group_source` field. Missing source kind continues to
mean `site` for existing callers; an organization group ID cannot become a site
source by omitting that field. Unsupported, unknown or duplicate fields and
query overrides are rejected. The 16 KiB URL-encoded form includes body CSRF,
plan/group revisions, source kind, request UUID, device/policy-token lines and
explicit confirmation; it accommodates the complete 100-device selection.

Organization targeting requires current organization-wide `devices.read` plus
target-site `updates.manage` and `devices.read`. The inventory intersection
validates the common organization and holds source group, organization, target
site and permission locks through the transaction. SQL scopes the query to the
target site before applying the rule and the complete 100-member bound. More
than 100 matching members elsewhere do not block a smaller site intersection.
More than 100 members in the selected intersection return 422 without a partial
cohort. Canonical Mac channels and runtime-enabled inventory sources retain
their ordinary mapping and ambiguity rules.

The backend shares [site-group update admission](apple-update-groups.md): exact
plan/group revisions, current eligible native selection, configured-policy
tokens, enrollment identity, platform prerequisites, temporary exceptions and
current catalog eligibility are rechecked together. Source edits, target-site
movement, device changes and grant replacement cannot overtake the held locks.
Preview writes only read audits. Confirmation commits policies, declarative
notifications, original evidence and audits atomically. A late audit failure
rolls back all new device work and its receipt.

An exact retry requires the same source kind, request intent, authenticated
actor and current permission revision. It returns original evidence before
consulting mutable group, plan or device state and cannot restore subsequently
removed policies. The current organization source grant is required even for
that replay. Reusing the request UUID with a site source returns 409.

## Original evidence and subsequent actions

New update-group receipts use encrypted intent version 2, retaining original
group scope separately from the target site. Version-1 receipts remain readable
with their original target site as source. No database migration or historical
rewrite is needed. Missing, foreign or invalid version-2 source scope is rejected;
the authenticated encrypted intent protects source scope alongside original
plan/group metadata and target evidence. All console instances reading new
receipts need this reader. Profile receipts keep their existing version-2 format.
Schedule parent intents now retain source scope as described in
[organization-source scheduling](apple-update-organization-schedules.md); child
source scope must match its parent. Promotion parent formats remain unchanged
and reject a substituted organization-source destination receipt.

History and [cohort progress](apple-update-progress.md) retain the original
organization group name, rule and revision. Original target-site authority is
sufficient to read this saved evidence after source archival; it does not confer
access to the live organization group. The source link uses the organization URL
and appears only with current organization-wide read authority. Device and result
links remain in the original target site.

[Matching policy removal](apple-update-group-removals.md),
[console monitoring](apple-update-escalations.md) and acting as an original
[pilot cohort](apple-update-promotions.md) continue to use the retained native
selection. They do not require the old organization rule to remain active or
unchanged. A reviewed pilot promotion still requires fresh evidence from every
original device and a freshly admitted site-group destination. A saved update
assignment establishes admission; later device reports determine OS results.

## Verification

Owned PostgreSQL 17/race tests pass in 15.208 seconds, including excluded
other-site enrollments, current organization rights, concurrent exact retries,
native declaration retrieval, fresh authenticated OS reports, archived-source
progress/monitoring/removal and pilot use, late audit rollback, source/site/device/
grant locks, legacy receipt compatibility, malformed source scope and rejection
of substituted schedule/promotion children. The initial shared profile/update/
schedule/promotion regression passes in 155.403 seconds.

Registered Linux console routes pass for explicit site/source selection,
role boundaries, preview-derived confirmation fields, malformed source inputs,
current source links, archival, replay and exclusion of other-site devices.
The relevant Chrome matrix passes 192 cases, including 36 new organization-update
cases at 390, 768 and 1440 pixels. The full 1,206-case Chrome matrix also
passes, followed by the 36 organization-update cases after the final progress
fixture correction. A separate 2.994-second PostgreSQL/race test verifies
composed organization-read and target-site update grants. Keyboard confirmation retains exact source,
revisions, native IDs, current-policy tokens and body CSRF. Mobile preview and
original receipt were visually inspected. These owned fixtures do not establish
physical update/restart, APNs or live provider acceptance. Linux and macOS view,
handler, router middleware and Linux webserver race checks pass, as does the full
Linux build.

The immediate-source increment's complete Apple PostgreSQL/race suite passed in
723.608 seconds; subsequent scheduling evidence is recorded separately.

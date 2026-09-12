# Scheduled Apple updates from organization groups

Select a target site and open an Apple update plan's dynamic-group chooser.
Choose **Organization groups** and review the eligible native devices, exclusions
and current policies in that site's intersection. **Schedule this update** saves
the reviewed source and selection for an absolute UTC activation window.
**Confirm update assignment** remains the separate immediate action.

The schedule form retains organization source kind, plan/group revisions, exact
native IDs and reviewed policy tokens. It adds the UTC start and activation
window to that same selection. Saving creates no policy or notification. The
ordinary limits remain: 100 complete site-intersection members, 256 pending
schedules per site, a start up to 90 days ahead and a one-minute to seven-day
activation window. The plan's enforcement deadline remains local to each device.

## Current rights and activation

Creation and exact replay require organization-wide `devices.read` and target-site
`updates.manage`/`devices.read`. Those rights may come from organization viewer
and target-site operator grants; organization administration is unnecessary.
Dropping `group_source` continues to select the old site-only API and cannot
reclassify an organization group or an existing request. Unknown source values,
duplicates, query overrides, missing body CSRF and unconfirmed forms are rejected
within the existing 16 KiB bound. Organization-only routes require an explicit
target site instead of silently choosing a default site.

Before locking a due schedule, the worker rechecks the original actor's current
target rights and organization source read grant. It retains the grant locks,
then verifies the saved permission revision, enabled sources, timing and current
group admission. Source archival or revision changes, different eligible target
membership or configured policies require a new review. Grant replacement blocks
activation even if equivalent rights are later restored. New members outside the
selected site do not alter the reviewed intersection.

The ordinary schedule savepoint and lifecycle remain in effect. Device policies,
declarative notifications, the original assignment receipt, schedule activation
and final audits commit together. A late audit failure rolls all of them back.
Source edits, target-site changes, policy replacement, grant revocation and
cancellation cannot overtake locks held through the final activation audit.
Concurrent workers admit a due schedule once. An expired window cannot activate
later. Installation and compliance still depend on subsequent device reports.

## Retained source and historical access

New encrypted schedule intents use version 2 and retain source scope separately
from the target site. Version-1 schedules retain their original site source and
remain readable. No schema change or rewrite of old schedules is needed. Missing,
foreign or invalid version-2 source scope is rejected. Lifecycle state remains
bound to the exact encrypted original intent, including source scope, through
authenticated encryption. Every console instance that reads or activates new
version-2 schedules needs this reader.

An activated schedule accepts only a child assignment whose source scope matches
its retained source, alongside the existing plan/group, actor, request, selection
and activation-time checks. Both site-to-organization and organization-to-site
child substitutions are rejected.
[Organization-source pilot promotions](apple-update-organization-promotions.md)
apply the same source matching to their separate destination receipts.

Current target-site operators can read original schedules and cancel pending
ones without acquiring organization-wide source visibility. The source name,
rule and revision remain available after archival or later owner grant loss.
The link to the current organization group appears only with organization-wide
read rights and uses the organization route. Original device and activation
receipt links stay in the target site. History labels the retained source kind.
Repeating a canceled or activated schedule cannot rearm it or restore removed
policies; changed source kind under the same request UUID returns a conflict.

## Verification

The complete existing and organization-source schedule regression passes with
PostgreSQL 17 and the race detector in 41.795 seconds. It covers current source and
target rights, concurrent activation, other-site membership, retained source,
native declaration retrieval, cancellation by site operators, source/archive/
membership/policy/grant/site changes, final audit rollback and source/target/grant/
cancellation locks. Legacy intent compatibility, invalid version-2 source scopes,
lifecycle-state binding and both directions of child source substitution pass.

Registered Linux routes cover preview-derived form fields, current role
boundaries, malformed source kinds, future creation without device work,
site-operator cancellation, actual due activation, source-preserving receipt and
history, and replay after archival and policy removal. The relevant Chrome matrix
passes 183 cases, including 33 new organization schedule cases and organization
preview keyboard confirmation for both immediate and scheduled work. UTC start,
window, source kind, revisions, policy tokens and CSRF remain intact.

A separate PostgreSQL/race test passes in 2.958 seconds for actual activation of
a correctly authenticated legacy version-1 schedule. The full 1,239-case Chrome
matrix passes. Mobile pending and activated schedules were visually inspected.
macOS/Linux view, handler and router middleware race checks, Linux webserver
checks and the full Linux build pass. These owned fixtures do not establish
physical update/restart, APNs or live provider acceptance.

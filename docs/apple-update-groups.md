# Apple update assignments from dynamic groups

Open a site-specific [Apple update plan](apple-update-plans.md), choose **Assign to
a dynamic group**, and review a current site group. The preview retains the exact
plan and group revisions, checks all members and shows eligible native Apple
devices, current policies that would be replaced, and exclusions. An archived
plan or group cannot start a new assignment. Original assignment history remains
available after archival.

## Review and atomic confirmation

The complete group may contain at most 100 members across enabled inventory
sources. Larger groups return 422 without taking a partial cohort. Canonical Mac
records resolve to their current native MDM channel. Desktop-only and native
Windows identities are excluded. The plan's platform must match; enrollment,
OS support, Mac supervision/update authorization, downgrade rules and current
release eligibility retain the ordinary Apple policy admission checks.

One locked catalog document is decoded for the whole inspection, with an 8 MiB
normalized document bound. A catalog older than 48 hours or a release unavailable
for a member makes that member ineligible. A database or catalog decoding failure
withholds the complete preview. Device and channel locks preserve the selected
inputs during each transaction. Preview commits only read audits; it changes no
policy and queues no notifications.

Each eligible target includes a scope/device-bound SHA-256 token over its current
configured version, build, deadline and information URL, or explicit absence of a
policy. Observation status, errors and timestamps are excluded: a progress report
alone does not invalidate configuration review. The comparison concerns configured
values; it does not count intervening writes that restore identical values.

Confirmation rechecks current `updates.manage` and inventory-read authority,
organization/site ownership, the exact plan/group revisions, complete current
eligible membership and every configured-policy token. Any difference returns 409
and saves nothing. Existing policies shown in the review are explicitly replaced.
Policy writes, declarative notifications, original request evidence and all audits
commit together. A late failure rolls back every target.

The submitted request is limited to 100 unique canonical native IDs and 64-character
lowercase policy tokens. Its strict URL-encoded form has a 16 KiB wire/parsed bound,
which accommodates the complete 100-device selection. Only the seven declared
fields are accepted: body CSRF, expected plan revision, group ID/revision, request
UUID, target lines and explicit confirmation. Duplicate fields, query overrides,
unsupported encoding and header-only CSRF credentials are rejected. Global CSRF
extraction applies this wire limit before normalizing either token path. Existing
small console forms retain their 8 KiB limit.

## Original request and results

Migration 045 adds immutable group update receipts. A bounded 32 KiB authenticated
encrypted intent retains the complete original plan definition and source actor/time,
group ID/revision/name/rule, eligible native IDs, reviewed policy tokens and original
notification IDs. Associated data binds it to the receipt/request, organization,
site, plan/revision, authenticated actor/permission revision and confirmation time.
Foreign keys retain the original plan and scoped revision; SQL rejects receipt
updates and deletion. Public serialization and ordinary formatting omit protected
receipt contents.

The exact same request returns the original receipt before consulting mutable
plan, group, catalog or device state. Concurrent identical confirmations create one
receipt and one set of notifications. Later plan/group archival, manual policy
replacement/removal or device progress cannot make an exact retry restore older
state. Reusing its UUID with another actor, permission revision, source revision,
selection or reviewed policy token returns 409.

The receipt records admission. It does not establish installation, pin later
availability indefinitely or introduce a separate delivery-time group authorization
mechanism. Normal declarative management, availability reconciliation and device
observations continue to determine the current policy and compliance. Receipt
links open current device state while retaining original source and notification
identities. [Current cohort progress](apple-update-progress.md) separately
assesses fresh OS observations, configured-policy changes and original
notification state for the exact retained selection. Current-state changes do not
rewrite historical requests.

History requires current update authority in the original scope and a successful
read audit. It uses 25-entry timestamp/UUID pages; cursors belong to the selected
site and plan. Responses prohibit caching. Original source metadata remains
readable after later source edits and archival.

## Scope and validation

This workflow applies one reviewed plan immediately.
[Scheduled activation](apple-update-schedules.md) also retains the same review for
a future UTC window and rechecks it before admission. Neither workflow continuously
recalculates membership, promotes pilot cohorts, provides exceptions, performs
automatic group removal or provides aggregate historical compliance.
[Reviewed removal](apple-update-group-removals.md) can now remove the current
matching policies from an original receipt's complete eligible selection, with
its own immutable replay evidence. Manual device policy removal also remains
available. Only eligible target state is
retained; excluded members are not a frozen historical snapshot. New plan revisions
and later group edits do not change already assigned policies. Organization-group
intersections and richer predicates remain separate work.

Owned PostgreSQL 17/race tests cover preview preservation, exact configured-policy
tokens, progress-only changes, platform/prerequisite/release exclusions, complete
membership limits, read audit failure, competing confirmations, changed sources,
new members/current policies, late audit rollback, exact replay after later removal
and archival, changed permission revisions, immutable receipts, protected history
pagination and ciphertext substitution. A synthetic native command cycle retrieves
the exact declared version/build/deadline and submits a matching fresh OS report;
ordinary compliance becomes satisfied. The targeted regression passes in 29.461
seconds and the complete Apple PostgreSQL/race suite passes in 483.258 seconds.

Registered Linux console routes cover chooser/preview/history rights, missing
confirmation, a real intervening policy change, explicit replacement, archival,
exact retry and unchanged queues after rejection. Tests verify that 100 reviewed
IDs/tokens fit the new form bound and that raw padding cannot evade it. Linux and
macOS handler, middleware, view and locale race tests and the full Linux build pass.
Twenty-seven Chrome cases cover chooser/empty, new/replacement previews,
all-excluded, original receipt, populated/empty history and long metadata at
390/768/1440 pixels. The eighteen plan and twelve navigation cases also pass.
These owned synthetic checks do not establish physical update/restart, APNs or
live provider acceptance.

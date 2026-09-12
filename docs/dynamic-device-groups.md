# Dynamic device groups

Open **Management pages → Dynamic device groups** in an organization or site.
A group stores a name, description and two rules: platform and literal inventory
search. Both rules must match. Search ignores case and matches the device name,
serial number, model or reported OS version; `%` and `_` are literal characters.
Blank rules match the available inventory. Platform choices match the shared
[device inventory](unified-device-inventory.md), including separate iOS, iPadOS
and macOS selections.

Each group belongs to exactly the selected scope. Organization groups and site
groups have separate lists. An organization URL always requires authority over
the whole organization; the console's usual fallback to an accessible site
cannot silently change the scope of group creation. A group cannot be moved by
editing its form or changing its URL. If its site is moved to another
organization, the old group becomes unavailable; it is not transferred with the
site.

Viewers can read definitions, history and membership. Operators, organization
administrators and server administrators can create and revise groups within
their grants using `devices.groups.manage`. Every operation rechecks current
permissions in its transaction. Permission replacement, site changes and group
definition writes are serialized against the relevant reads.

## Definitions and membership

Saving creates a new numbered revision and retains the previous name,
description, rules, archive state, actor and timestamp. Updating, archiving and
reactivating require the displayed current revision. A stale submission returns
409 and cannot overwrite a newer definition. Archiving leaves history available
and makes the preview empty; clearing the archive checkbox reactivates the group
as a new revision. Definitions are not hard-deleted through this workflow.

Membership is recalculated when the group is opened. The definition stays locked
while the shared SQL inventory query reads one current inventory snapshot. It
uses the enabled server stores, the canonical Mac identity projection and
separate native Windows and desktop identities. Unadmitted or ambiguously
assigned desktop agents are excluded for every role, including administrators.
This preview does not establish that a device supports a future management
action. Disabled stores contribute no devices; changing store enablement can
therefore change membership.

Groups, members and definition history each use 25-entry pages. Member and
history links carry the current group revision. A changed definition requires
reloading the group, while member cursors also bind scope, rule and enabled
sources. Inventory changes between requests may reposition devices; these pages
are not a frozen target snapshot. A group definition or preview queues no device
commands and creates no policy assignment.

## Bounds and evidence

Operations have a ten-second transaction deadline. Names are limited to 120
UTF-8 bytes, single-line descriptions to 1,024 bytes and searches to 256 bytes.
Forms accept only bounded URL-encoded POST bodies with an exact CSRF token;
duplicate or unknown fields, URL query overrides and unsupported rules are
rejected. The limit is 1,000 group identities per exact scope, including archived
groups. Reusing a group remains possible at the limit. Revisions are retained
independently of timeline retention; there is no automatic revision pruning.

Inventory migration 9 installs group identities and revision history. The
existing inventory startup migration runs it without changing refresh-worker
behavior. Audit migration 13 adds `inventory.groups.list`, `.read`, `.create`
and `.revise` to the inventory audit stream. Detail and change events identify
`group UUID@revision`; list events identify `groups`. A failed audit rolls back
the write or withholds the read response. Console responses prohibit caching.

Owned PostgreSQL race tests cover fresh membership, literal search, native
Windows beyond the former 100-row preview, Apple platform projection, enabled
sources, ambiguity, scope moves, removed grants, competing revisions, canceled
locked writes, atomic audit failure, the 1,000-group limit and list/member/history
pagination. The registered Linux console suite covers all four roles, scoped
routes, archive/reactivation, stale revisions, malformed forms and CSRF.
Eighteen Chrome cases cover list, empty, detail, archived, viewer and long text
at 390, 768 and 1440 pixels, including keyboard submission and revision links.
The twelve existing device-list and twelve navigation cases also pass.

[Immediate and scheduled native Windows ring assignments](native-windows-update-groups.md) now
capture reviewed site group revisions and exact native Windows target sets, with
other management identities shown as exclusions. Scheduled activation rechecks
the original revision, native membership and enabled sources.
[Immediate Apple System-profile assignments](apple-profile-groups.md) now preview
current action eligibility, resolve canonical Mac channels, confirm exact native
targets and retain immutable original request evidence.
[Apple update plan assignments](apple-update-groups.md) additionally compare
reviewed current policy values and explicitly confirm replacements. Software
assignments, Apple scheduling, exceptions, broader conflict previews, pilot
promotion and richer predicates remain roadmap work. Those operations must establish their own action eligibility,
current authorization and revision-bound target evidence. Production-scale
database acceptance and physical-device acceptance remain separate.

# Apple profile targeting from organization groups

Select a target site, open an Apple System profile's dynamic-group chooser, then
choose **Organization groups**. The chooser lists organization-level definitions;
the next page evaluates the selected group's current rule only inside the chosen
site. Other sites' devices are outside the action and are not displayed as
exclusions. **Site groups** retains the existing exact-site workflow.

The preview shows the source organization group, target site, exact profile and
group revisions, eligible native Apple enrollments and exclusions within that
site. Apply and removal actions require explicit confirmation of the complete
selection. A group can be reused separately in other sites after another review;
there is no implicit cross-site fan-out or continuous membership reconciliation.

## Scope and current authority

Every profile-group console route requires an explicit site in its URL. An
organization-only URL cannot silently use the console's default site, including
for confirmation or original receipts. The organization source is a separate,
explicit choice carried through chooser links, preview and confirmation.

An organization source requires current `devices.read` authority covering the
whole organization, as well as `profiles.assign` authority at the target site.
A site-only operator cannot list or inspect organization groups through these
action routes. The inventory intersection API separately authorizes source and
target reads, validates their common organization and holds the source group,
organization and target-site locks until the caller's transaction ends.

The SQL inventory query is scoped to the target site before applying the source
rule and complete 100-member bound. More than 100 organization members elsewhere
do not block a smaller site intersection. More than 100 matching members inside
the selected site return 422 without a partial result. Ambiguous agent placement
is excluded even for administrators. Runtime-enabled sources, canonical Mac
channel mapping and ordinary Apple profile admission rules remain in effect.

Changed source revisions, archival, current membership or target eligibility
require another review. Site movement, permission replacement, native-device
changes and group edits cannot overtake a confirmed transaction's held locks.
The new action does not change the source organization's membership definition.

## Confirmation and original evidence

The confirmed form retains the source kind (`site` or `organization`) alongside
the profile/group revisions, action, request UUID, eligible native IDs and body
CSRF token. The existing 8 KiB URL-encoded form limit accommodates the complete
100-device selection. Unknown or duplicate source fields, unsupported source
kinds and query overrides are rejected. Omitting the source continues to mean
`site` for existing clients; an organization group ID cannot thereby become a
site source.

The backend uses the same profile admission probes, savepoints, resource-conflict
checks and exact-target comparison as [site-group assignments](apple-profile-groups.md).
Preview rolls back its staged commands and reservations. Confirmation retains
all device work, the original receipt and audits together. A late audit failure
rolls everything back. An exact retry validates source kind, current actor/grant
revision and the original request before returning its saved receipt; it cannot
restore a subsequently removed profile or overwrite later state.

New profile-group receipts use encrypted intent version 2 and retain source scope
separately from target scope. Existing version-1 receipts remain readable: their
source is the recorded target site, as required by the original site-only
workflow. No receipt or database schema is rewritten. Missing, foreign or invalid
version-2 source scope is rejected, and authenticated encryption protects the
source scope with the original intent. Console instances reading newly written
version-2 receipts need this reader. [Organization-source updates](apple-update-organization-groups.md) now use their
own version-2 group receipts. Schedule and pilot-promotion parent formats remain
unchanged.

History and detail retain the original organization group name, rule and revision
while keeping target-site authorization. A site operator can read an assignment's
retained evidence without acquiring access to the current organization group.
The current organization-group link appears only with organization-wide read
permission. Original source links use the organization URL; device/result links
remain in the original target site. Future group edits do not rewrite a receipt.

As with ordinary profile assignment, a saved command is distinct from delivery
and verified installation/removal. The later authenticated device report provides
that evidence. Group assignment does not establish physical-device acceptance.

## Verification

Owned PostgreSQL 17/race inventory tests pass in 5.390 seconds, including scoped
intersections, organization authority, ambiguous placement, changed site/group
state, concurrent source/target/grant locks, failed audits and the 100-member
boundary on the selected intersection. Apple profile-group tests pass in 16.664
seconds with verified native profile reporting, excluded other-site enrollments,
concurrent exact retries, retained source history, version-1 compatibility,
version-2 validation and complete rollback on a late audit failure. A gated final
audit also proves that source edits, target-site/device movement and permission
revocation cannot overtake admission. The earlier profile-group/pilot-promotion
regression passes in 53.801 seconds.

Actual registered Linux routes pass source selection, scoped permissions,
organization-URL rejection, strict source intent, confirmation, original history
and replay after archival/removal. All 156 relevant Chrome cases pass, including
30 new organization-source cases at 390, 768 and 1440 pixels. These cover apply,
removal, exclusions, source/target links, exact keyboard confirmation, old site
flows, historical site-operator access and long escaped metadata. Mobile preview
and original receipt were inspected visually. The complete 1,170-case browser
matrix also passes. Its global limit is now eight minutes after the growing
matrix exhausted the former three-minute deadline in CI; individual operation
limits and assertions remain unchanged. macOS/Linux package race checks and the
full Linux build pass. The complete Apple PostgreSQL/race suite passes in
723.216 seconds. Broader evidence is recorded in
[implementation status](implementation-status.md).

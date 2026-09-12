# Apple profile assignments from dynamic groups

Select a site, open **Apple profiles**, and use **Apply to a dynamic group** or
**Remove from a dynamic group** beside a System profile. The chooser retains the
current profile revision and lists that site's [dynamic groups](dynamic-device-groups.md).
Archived groups cannot start new work. Group assignment history remains available
from the profile catalog and each saved request's URL.

## Review and confirmation

The preview checks the complete group against the selected action. It shows
eligible native Apple enrollments and excluded members with fixed explanations.
Canonical Mac records resolve to their current native MDM channel; desktop agent
identities and native Windows identities are excluded. Missing channels, profile
prerequisites, ADE-owned assignments and existing resource reservations remain
subject to the ordinary Apple admission rules. User-channel profiles are outside
this workflow.

A group may contain at most 100 members across all enabled inventory sources.
Larger groups return 422; they are never silently truncated. Narrow the group's
rule before continuing. Evaluation uses ascending native enrollment UUIDs so
conflicts between members have a stable order. For example, a certificate client
identity that cannot be shared makes later conflicting members ineligible.

Preview runs the real assignment admission inside database savepoints. It rolls
back all probed commands, assignment changes and reservations before committing
only read audits. Workers cannot see this uncommitted work. There are no provider
calls or device deliveries during preview.

Confirmation submits the exact profile revision, group revision, action, request
UUID and eligible native enrollment IDs. The server rechecks current assignment
and inventory-read authority, scope, group definition, fresh membership and action
eligibility in one transaction. A changed eligible selection or source revision
returns 409 and saves nothing. Newly excluded members cannot silently reduce the
confirmed target set. An empty eligible selection has no confirmation form.

Only the reviewed eligible selection is fixed by confirmation. Excluded members
are not captured as a retained snapshot. Group membership and device reports can
change after confirmation; this is an immediate assignment, not ongoing dynamic
group reconciliation. Organization groups, scheduled Apple profile assignments,
profile exceptions and richer rule predicates remain separate work.
[Apple update groups](apple-update-groups.md), [scheduled updates](apple-update-schedules.md),
[temporary update exceptions](apple-update-exceptions.md) and
[reviewed pilot promotion](apple-update-promotions.md) now provide separate update
workflows; they do not schedule or exempt these profile assignments.

## Original request and device results

Apple migration 043 adds immutable group assignment receipts. An encrypted,
authenticated intent retains the original profile name, group ID/revision/name/rule
and exact native device/command IDs. Associated data binds that intent to its
request, receipt ID, organization, site, actor, permission revision, profile
revision, action and recording time. SQL rejects receipt updates and deletion.
There is no plaintext copy of the group name, rule or target list in the receipt.

Repeating the exact request returns its original receipt, including after later
group edits, archival, catalog revisions or device state changes. It creates no
new commands and cannot restore an earlier assignment. Changing the actor,
permission revision, profile, action, group revision or selection while reusing
the request UUID returns 409. Parallel confirmations of the same request produce
one receipt and one set of commands.

The receipt is original admission evidence. Its device links open current state;
the existing Apple command acknowledgement and subsequent profile report establish
delivery and verification. A receipt does not establish installation, and does
not add another delivery-time group authorization mechanism. Explicit later
catalog saves or restorations can update active assignments through the existing
[profile revision lifecycle](apple-profile-revisions.md).

History reads recheck current assignment authority and scope, retain the original
source after catalog/group changes, and require a successful read audit. History
uses 25-entry pages with a cursor scoped to the site and profile. Responses prohibit
caching. Public structured serialization and ordinary formatting of protected
receipt, source and target values omit their contents.

## Bounds and validation

Operations use ten-second transactions. Confirmation accepts only an 8 KiB
URL-encoded POST with unique allowed fields, a body CSRF token and explicit
confirmation. Duplicate keys, query overrides, unsupported encodings, malformed
UUIDs and noncanonical revisions are rejected. The global CSRF middleware applies
small-form wire limits before parsing, including with a header token, so padding
cannot bypass the endpoint's bound through a cached normalized form. Manual Apple
assignment keeps its separate 64 KiB limit.

Owned PostgreSQL 17/race tests cover preview rollback, existing command retention,
platform exclusions, current canonical Mac association, shared certificate claims,
concurrent confirmation, exact replay after later changes, membership conflict,
late audit rollback, encrypted-source substitution and history pagination. An
actual synthetic Apple command/report cycle verifies the assigned profile. The
complete Apple suite passed in 457.681 seconds; the final group regression,
including current chooser authority and protected read failures, passed in
11.993 seconds.

Registered Linux console routes exercise viewer denial, chooser/preview/history,
confirmation, repeated fields, archived-source conflict and exact replay. Linux
middleware, handler, view and locale race tests pass. Thirty Chrome cases cover
the site catalog, chooser, empty chooser, apply/removal previews, all-excluded
preview, original receipt, populated/empty history and long metadata at 390,
768 and 1440 pixels. The nine existing manual profile assignment browser cases
also pass. No real Apple device, APNs service or certificate provider was used;
physical profile delivery and provider acceptance remain outstanding.

# Scoped, atomic legacy task cloning

Cloning a task now holds current server administrator authority, exact source
and destination profile audiences and both parent rows through one transaction.
The submitted source parent must still own the task, and the selected destination
must retain its displayed organization/site scope. The store locks parent rows
in ID order after a write-compatible audience lock, then the source task and
existing destination tasks. Opposite-direction clones cannot deadlock through a
shared audience-lock upgrade.

A copy receives a new ID and name, version one, a cleared execution time and the
last position in its destination. Existing destination positions are normalized
by stored order and ID, then the copy is appended. This works for empty profiles,
same-profile copies and zero/tied/gapped/NULL legacy positions. Surviving task
configuration remains unchanged; source configuration is copied directly in SQL
using the pinned schema's columns, with nullable values preserved. The shared
column helper is also used by profile cloning. This replaces the old hand-written
copy helper, which incorrectly replaced the APT package name with the new task
label and omitted configuration fields.

Scripts and encrypted values stay within the database copy operation. Tags and
historical reports are not copied. NetBird registration tasks may only be copied
to their configured organization. The destination's assignment is preserved;
a copied task in an assigned profile can therefore run on its devices. No broker
or provider call is made by the clone action itself.

New `inventory.tasks.clone` receipts are recorded in source and destination
scopes, once when both scopes are equal. They contain source/copy/profile/scope
IDs and the new position, without task values. Both receipts, the new task and
normalization commit together. An insertion failure, either audit failure or
cancellation rolls everything back. A successful response redirects to the
selected destination only after commit. An uncertain response asks the user to
refresh that profile before retrying; request deduplication remains separate work.

## Review, search and console

Existing scoped GET/POST `/tasks/:id/clone` URLs remain. Review and the new scoped
GET `/tasks/:id/clone/targets` endpoint hold current source ownership and authority
through an `inventory.tasks.clone_review` audit commit. Search results contain
only bounded profile/organization/site labels and IDs. Ambiguous and orphaned
profile audiences are excluded. Literal name search and canonical numeric ID
lookup return at most 50 options, with an explicit message when more match.
Search strings are limited to 256 UTF-8 bytes and are not included in audit data.
Scripts and credentials are not selected by either read.

The English native form identifies the source task/profile, labels destination
organization/site scope and requires a destination and new task name. A name
must satisfy the shared 2,048-byte profile-name validation; an oversized or
invalid legacy source name leaves the new-name input empty for explicit entry.
A new search clears the prior selection before its request, disables copying
while pending and replaces only the destination selector. Edited names remain.
No matches leave the required selector empty. Cancel returns to the source
profile. The form uses the full available width on mobile.

POST bodies are limited to 8 KiB before CSRF extraction. Only a single source
parent, canonical destination profile/organization/site tuple, new name and
optional CSRF field are accepted. Query targeting, duplicate or unknown form
fields and alternate encodings are rejected. Search accepts only its reviewed
source parent and search string. Mutation fields do not leak into search or
cancellation requests. The old unscoped task-copy/last-order helpers, unused
editor clone dialog and its unnecessary all-profile query are removed.

Audit migration 026 enables scoped review and clone receipts. Both store paths
have a ten-second deadline. Names, scripts, credentials and search text are absent
from audit resources. Production-scale contention from shared audience locks
still needs measurement.

## Verification

PostgreSQL/race tests cover all source/destination scope combinations, same-profile
and empty-target copying, fresh identity/version/time, nullable configuration,
APT package names, encrypted values, absent copied history, unchanged source
history, destination order and scoped audit browsing/JSON export. Current roles,
wrong/moved parents, ambiguous audiences, name/query bounds, NetBird organization
requirements and audit/insertion/cancellation rollback are covered. An audit gate
holds source/destination edits, insertion, reparenting, deletion, review and grant
revocation until commit. Opposite-direction clones both complete.

Actual registered Apple/OIDC routes cover review/search/clone, all scopes,
current roles, CSRF, strict forms, stale source parents, scope labels and the
cross-scope destination redirect. Forty-two browser cases exercise native required
fields and keyboard copy/cancel, isolated search, clearing a previous selection,
rendered target replacement, retained edited names and long/empty states at
390, 768 and 1440 pixels. Mobile normal and empty states were visually inspected.

The full inventory PostgreSQL/race suite passes in 77.350 seconds and the full
audit suite in 11.815 seconds. Registered Apple/OIDC routes, affected macOS/Linux
race checks and the full Linux build pass. The final complete 1,602-case Chrome
matrix passes in 91.762 seconds.

Task creation is covered by the later [creation change](task-creation.md).
Task editing, broader legacy editor read authorization, immutable
profile revisions, delegated access and physical/provider acceptance remain open
in the expanded roadmap.

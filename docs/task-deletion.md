# Scoped, atomic legacy task deletion

Task deletion now requires current server administrator authority, exact profile
scope and current task ownership. The confirmation GET and DELETE both validate
the task's parent. The DELETE carries the reviewed profile ID, so moving a task
to another profile—even one with the same audience—invalidates an old confirmation.
An unknown task, mismatched parent or ambiguous profile audience returns 404;
insufficient current authority returns 403.

The store holds authority, the complete profile audience, the parent and sibling
task rows through deletion, normalization and audit commit. Removing a task
cascades to its stored task reports. Remaining tasks in that profile receive
consecutive positions from one, ordered by their previous stored order and ID.
Zero, tied, gapped and NULL orders therefore have deterministic results. Other
profiles' task order and all surviving task configuration stay unchanged. The
profile, its issue records and tag associations remain. This replaces the old
separate delete and unscoped order update, which could renumber other profiles.

The review reads at most 512 name characters and a truncation flag; it never
loads scripts or credentials. An `inventory.tasks.delete_review` receipt commits
before review data is returned. The destructive transaction records
`inventory.tasks.delete` with task/profile IDs and the number of remaining tasks.
Audit migration 025 enables both actions in all three scopes. Audit failure,
cancellation or failed normalization rolls back deletion, cascading reports and
order changes together. Both operations have a ten-second deadline.

## Console behavior

The existing scoped confirmation URLs remain. A dedicated English confirmation
page identifies the task and its profile by ID, marks a shortened legacy name,
and explains deletion of stored results. It also explains that this action does
not undo device changes, uninstall software or cancel work already sent to a
device. A native keyboard-accessible button disables while its request is pending.
Cancel returns to the displayed profile. A successful delete redirects there only
after commit; uncertain results ask the administrator to refresh before retrying.

The existing DELETE `/tasks/:id` routes now require exactly one canonical
`profile` query parameter, matching the parent shown during review. Body data,
additional or duplicate query fields, noncanonical IDs and encoded bodies are
rejected. The query is limited to 128 bytes. The production CSRF middleware still
requires the request token; bundled HTMX sends it in the header. Confirmation
GETs accept no body or query data. Explicit parameter isolation prevents unrelated
editor fields from entering confirmation or deletion requests. The old editor
confirmation branch and unscoped model deletion helper are removed.

## Verification

PostgreSQL tests cover all scopes and roles, wrong or moved parents, ambiguous
and missing owners, bounded names, scoped audit listing/JSON export, unrelated
profiles and unchanged sibling definitions. They verify cascading report deletion,
retained profile/issue/tag records, empty profiles and deterministic normalization.
A trigger rejects renumbering after deletion to prove rollback of the task and
reports; separate audit failures and cancellation prove the same transaction bound.

An audit gate holds deletion while concurrent sibling edits/insertion, reordering,
review reads, reparenting, task/profile deletion, grant revocation and audience or
organization/site changes attempt to proceed. None can overtake commit. Actual
registered routes exercise all scopes, current roles, CSRF, strict query/body
validation, safe rendered review, repeat deletion and the scoped success redirect.

Twenty-four browser cases cover native keyboard deletion/cancellation, scoped
URLs, query isolation, CSRF, pending-request protection, long names and responsive
layout at 390, 768 and 1440 pixels. The mobile confirmation was visually inspected.

The full inventory PostgreSQL/race suite passes in 77.384 seconds and the full
audit suite in 10.473 seconds. Registered Apple/OIDC routes, affected macOS/Linux
race checks and the full Linux build pass. The final complete 1,560-case Chrome
matrix passes in 89.120 seconds.

Task cloning is covered by the later [cloning change](task-cloning.md).
Task creation/editing, broader legacy editor read authorization,
immutable profile revisions, delegated access and physical/provider acceptance
remain open in the expanded roadmap. Deletion is not request-deduplicated: a
retry after a successful removal returns 404 and creates no additional delete
receipt. Production-scale contention from shared audience locks remains to be
measured.

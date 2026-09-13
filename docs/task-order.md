# Scoped, atomic legacy task ordering

The three existing ordering actions—move up, move down and drag to a position—
now require current server administrator authority, exact profile audience and
current task ownership. They hold the profile and sibling tasks through one
transaction. A submitted starting position must match the task's current
position; a stale position returns a conflict. Destinations outside the current
task count are invalid. The transaction updates only that profile's order fields
and commits them together with an `inventory.tasks.reorder` receipt. It does not
change task version, configuration, ownership, tags, reports or device work.

The [worker follow-up](https://github.com/the-luap/openuem-worker/blob/d61712f/docs/profile-task-order.md)
uses the same stored-order/ID/NULL ordering for all four assigned-profile queries.
It projects consecutive positions only in memory so its WinGet, Ansible and
NetBird generators retain NULL placement despite the nullable column's plain
integer representation in Ent. PostgreSQL tests cover the queries and actual
generated task sequences, with stored task JSON unchanged. Full worker model and
common-package PostgreSQL/race suites pass in 2.680 and 3.269 seconds, and the
complete Linux build passes. This proves generated configuration order;
physical execution and WinGet dependency semantics require separate acceptance.

Positions are defined by stored order followed by task ID, with PostgreSQL's
ascending NULL placement. Gaps, duplicates, zero values and NULL are therefore
displayed deterministically. An accepted ordering action persists consecutive
positions from one, including when the requested position is unchanged. Older
editor and confirmation reads now calculate display positions in memory and no
longer initialize order values in the database. Existing stored values remain
untouched until an authorized mutation normalizes them. The later
[task-deletion change](task-deletion.md) also normalizes only the affected profile.

The registered POST routes retain their URLs in all three scopes. They share
the 8 KiB action form bound before CSRF token extraction, reject alternate
target/from/to fields and query parameters, and require canonical position IDs
and page sizes. A successful response emits a refresh event after commit. Its
profile/task IDs and destination page let the UI follow a task that crosses a
page boundary. An uncertain result asks the administrator to refresh before
retrying. Request deduplication and full immutable profile revisions remain
separate work.

## Task list reads and UI

New scoped GET routes at `/profiles/:uuid/tasks`, with the organization/site
prefixes, return only the task-list region. The store holds current authority,
profile audience and task rows until an `inventory.tasks.list` receipt commits.
It reads only the columns used by the table; scripts and credentials are never
selected. Display text is limited to 512 characters with an ellipsis for longer
legacy values. Pages contain 1–1,000 tasks, with a maximum requested page of
1,000,000; an out-of-range page is clamped to the last existing page. Both read
and reorder operations have a ten-second deadline. Audit migration 024 accepts
the scoped list and reorder actions. Audit resources contain IDs, positions,
page bounds and counts, without task values.

Native keyboard buttons replace the old ordering anchors. Dragging uses the
dedicated move handle, preserving normal pointer interaction with row controls.
After a successful mutation, only the task region refreshes; the rest of the
editor and its unsaved metadata remain in place. Focus follows the moved task's
link. Failed optimistic drag requests refresh the current server order without
creating a loop if that GET also fails. Responses for another profile are
ignored. A newer list refresh replaces an older pending refresh.

The region's GET context does not leak into child status/order forms, which
submit exactly their own paging fields. Task status still swaps only its own
control and indicator. Row menus remain available during these local updates.
The table scrolls horizontally within its region, and scoped pagination styles
keep the page-size value readable on mobile without changing other pages.

## Verification

- The registered-route baseline reproduced a site task moved through the global
  route, returning 200 instead of 404. Actual routes now check all scopes, role
  denial, CSRF, strict and canonical forms, stale starting positions, all three
  actions, destination-page events and partial list reads. Initial editor GET
  tests verify that zero order values are not written.
- PostgreSQL tests cover stable zero/tied/gapped/NULL positions, bounded text,
  omitted credentials/scripts, unchanged task definitions/history, unrelated
  profiles, no-op normalization, scoped audit browsing/JSON export, invalid
  requests, cancellation and audit rollback for both list and reorder actions.
  A paused audit gate proves that sibling edits/insertion, task/profile deletion,
  reparenting, permission revocation, audience changes, competing moves and page
  reads cannot overtake the accepted ordering transaction.
- The full inventory PostgreSQL/race suite passes in 71.781 seconds and the full
  audit suite in 13.009 seconds. Registered Apple/OIDC routes, affected
  macOS/Linux race checks and full Linux builds pass.
- Thirty-six focused browser cases exercise native up/down actions, cross-page
  following, real bundled UIkit/hyperscript drag events, scoped GET refresh,
  rendered partial swaps, retained unsaved metadata/focus, child status requests,
  failed-drag recovery and unrelated-profile/error-loop suppression at three
  widths. The mobile view was visually inspected and its initially clipped
  page-size control corrected with scoped styling.
- The final complete 1,536-case Chrome matrix passes in 89.560 seconds; the
  corrected mobile page-size control was visually inspected after that run.

Task cloning is covered by the later [cloning change](task-cloning.md).
Task creation is covered by the later [creation change](task-creation.md).
Task editing is covered by the later [editing change](task-editing.md).
Broader editor read
authorization, immutable revisions, delegated access and physical/provider
acceptance remain open in the expanded roadmap. Production-scale contention
from the existing shared audience locks also remains to be measured.

# Scoped legacy profile cloning

Cloning a global, organization or site profile now checks its complete current
audience before showing the form and again when creating the copy. A server
administrator remains required. The legacy task editor and other mutation paths
still need their own scoped authorization before delegated access can expand.

The source profile, its tasks, current server authority and destination parent
rows remain locked through one PostgreSQL transaction. The destination must be
global, an existing organization, or a site currently belonging to that
organization. Hidden additional source associations cause a scope mismatch.
Concurrent task edits, insertion, deletion and reassignment cannot change the
definition while it is being copied. Association writers use the existing
write-compatible lock before inspecting the audience. This shared legacy table
lock serializes audience changes; production-scale contention remains to be
measured. The action has a ten-second context deadline.

The copy receives a fresh profile ID and fresh task IDs. It starts enabled with
the existing WinGet profile type and no device assignment. Tasks preserve all
configuration fields from the pinned Ent schema, including nullable settings,
scripts, synthetic-test-verified credential fields and task disabled flags. The
APT package name is preserved separately from its task label. The previous
helper incorrectly replaced it with that label and omitted NetBird settings.
Tasks are ordered by their source order and ID, then numbered from one. Their
version starts at one and their execution time is cleared. Profile/task tag
edges, issues, reports and other historical associations are excluded. Cloning
does not publish broker commands or dispatch work to devices.

NetBird registration tasks load provider credentials using their task-level
organization. A profile containing such tasks can only be cloned into that
configured organization, optionally into one of its sites. Missing or conflicting
task organizations reject the entire operation with a reviewable conflict. The
action does not silently retarget provider settings or copy them into another
organization. Review the copied task configuration before assigning devices.

Audit migration 022 accepts `inventory.profiles.clone`. Both the source and
destination retain a receipt; a same-scope clone produces one receipt. Its
resource identifies the new profile, original profile, both scopes and task
count. Task names, configuration and credentials are excluded from audit. Task,
association or either audit failure rolls back the complete copy. A successful
response redirects to the new profile in its destination. Each accepted request
creates a distinct copy; request deduplication is not implemented. After an
uncertain response, check the destination list before retrying.

The form uses a bounded UTF-8 name, explicit destination labels and native
keyboard controls. Invalid legacy names require an explicit replacement. POST
forms reject ambiguous fields, query parameters, noncanonical IDs, extra
assignment fields and bodies above 8 KiB, including padding before CSRF token
extraction. The site selector submits only its organization and uses the same
current administrator check. Changing organizations replaces the site selector;
the store verifies its current parent even if a stale browser submits an old site.

## Verification

- The registered-route baseline reproduced an out-of-scope clone GET returning
  200 instead of 404. The corrected global, organization and site routes exercise
  read/write role denial, source scope, CSRF, strict forms, all nine source/target
  combinations, retained APT names, new defaults and destination redirects.
- PostgreSQL tests compare every stored task configuration field without
  printing task values. They cover nullable values, deterministic ordering,
  excluded history/tags, both scoped audit views and JSON export, invalid names,
  crossed site parents, cross-organization copying and NetBird restrictions.
- Failure tests reject the second task insertion and the destination audit after
  the source receipt. Concurrency tests hold an audit gate while attempting task
  changes, permission revocation, source audience changes and destination moves
  or deletion. Pending source task changes and destination parent changes are
  rechecked after their transactions finish.
- The complete inventory PostgreSQL/race suite passes in 67.035 seconds and the
  complete audit suite in 10.884 seconds. Registered Apple/OIDC route suites,
  affected macOS/Linux race checks and the full Linux build pass.
- Browser coverage adds 36 cases across three source scopes and three widths,
  exercising required names, exact requests, global/organization/site choices,
  site lookup isolation, clearing old selections and visible keyboard focus.
  The mobile form is visually inspected, including its English labels.
  The complete 1,482-case Chrome matrix passes in 89.348 seconds after correcting
  the locale nesting and adding rendered-label assertions.

This closes the legacy profile cloning path within the broader RBAC, audit and
UI work. It does not close the remaining task mutations, delegation, immutable
profile revisions, provider/device acceptance or the expanded roadmap.

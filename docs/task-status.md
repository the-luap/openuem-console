# Scoped legacy task status

Enabling or disabling a legacy profile task now checks current server
administrator authority, route scope, complete profile audience and current task
ownership in one transaction. Global, organization and site routes retain the
same action URLs. Organization administrators and delegated operators remain
outside the legacy task mutation boundary until the remaining paths are secured.

The transaction resolves a candidate profile, locks its complete audience and
profile row, then locks the task and rechecks that it still belongs to that
profile. This keeps the profile-before-task lock order used by profile cloning
and deletion. A task moved while the action waits for its original profile is
rejected, including moves to another profile in the same scope. Permission,
site-parent and audience changes cannot overtake an accepted transaction. Missing,
orphaned and out-of-scope tasks do not change state.

Only the task's disabled flag changes. Its definition, credentials, version,
order, parent, tag assignments and stored reports remain intact. The operation
does not queue a device command or reset task execution history. Repeating the
same requested state records another accepted action without changing the other
fields. Audit migration 023 allows `inventory.tasks.enable` and
`inventory.tasks.disable`, with a resource identifying task and profile IDs.
Task values are excluded from audit. Status and receipt commit together; audit
failure, cancellation and other transaction errors return no confirmed parent
and roll back the status. The operation has a ten-second deadline.

POST forms share the existing strict action parser and 8 KiB limit before CSRF
token extraction. Scope, task and requested status come from the registered
route. Body/query overrides, duplicate parameters and unrelated fields are
rejected. Optional paging/sorting fields preserve editor context; the response
does not impose a different page-size limit or run a list query.

The native button updates its own form and the task's status indicator through
the bundled HTMX out-of-band mechanism. It then offers the inverse action.
Stable button IDs preserve keyboard focus; the indicator has an accessible
status label and the form announces the confirmed result. Pending requests
disable the button. The existing editor and its unsaved profile fields stay in
place. [Scoped task ordering](task-order.md) also removes the former editor GET
order initialization and refreshes its task region separately.

## Verification

- The actual route baseline returned 200 for disabling a site task through the
  global route; the corrected test requires 404. Registered routes exercise all
  six scope/action combinations, role denial, CSRF, strict forms, scoped audit
  receipts and unchanged task version/order. An original zero task order remains
  zero after the response, proving the legacy editor initialization was avoided.
- PostgreSQL tests retain full task configuration without printing credentials,
  verify reports/tags and repeated actions, exercise audit JSON export, and reject
  orphaned tasks, invalid IDs/scopes and ambiguous or changed profile audiences.
  Audit failure and cancellation leave status and history unchanged.
- Concurrency tests pause at audit insertion while attempting permission
  revocation, task reassignment/deletion, profile deletion, audience changes and
  site moves/deletion. Another test moves the task after parent discovery while
  the action waits for its original profile, then verifies the stale attempt
  fails and a fresh request audits the new owner.
- The complete inventory PostgreSQL/race suite passes in 72.363 seconds and the
  complete audit suite in 13.666 seconds. Affected macOS/Linux race checks,
  registered Apple/OIDC routes and the full Linux build pass.
- Eighteen browser cases cover both states in all three scopes at three widths.
  They use real rendered responses with the bundled HTMX swap API to verify the
  out-of-band indicator, inverse action, stable keyboard focus, retained unsaved
  input, accessible feedback and exact request fields. The mobile controls were
  visually inspected. These fixture requests do not contact a writable provider.
  The final complete 1,500-case Chrome matrix passes in 85.856 seconds, including
  accessible state labels and preservation of a 50-item page size.

Task deletion is covered by the later [deletion change](task-deletion.md).
Task cloning is covered by the later [cloning change](task-cloning.md).
Task creation is covered by the later [creation change](task-creation.md).
Task editing still needs its own atomic scoped mutation. This change does not complete legacy delegation,
immutable revisions, device acceptance or the expanded roadmap.

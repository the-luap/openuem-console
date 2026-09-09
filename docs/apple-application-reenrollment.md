# Mac application operations across enrollments

Mac application mutations now check earlier enrollment records before creating an
attempt and immediately before delivering its command. A nonempty, case-folded
UDID identifies the Mac within its organization. Unknown earlier attempts for the
same package remain blocking after checkout or revocation; reenrollment alone
does not authorize replay. An active duplicate enrollment blocks all package
mutations for that identity, including legacy records with different UDID casing.

The per-identity PostgreSQL transaction lock serializes app mutation decisions
and stopping-evidence records after the current device lock. Reads of other
enrollment rows do not acquire their device locks. A failed creation rolls back
its assignment and command; ADE uses its existing savepoint for the same atomic
behavior. A queued command that becomes unsafe before delivery is cancelled with
the `previous_enrollment_unresolved` reason. Read-only application observations
can continue.

## Explicit stopping evidence

An organization administrator opens the current Mac's **Managed applications →
Review previous enrollments** page. It lists unresolved earlier attempts and
recorded stopping evidence, with at most 100 operations per page. Cursor lookup
remains bound to the same organization and Mac identity.

One confirmed action records evidence for one dispatched, uncertain attempt on a
retired enrollment. Supported assertions are confirmation that the earlier
installer/removal operation stopped, or erasure of the Mac after that operation
was sent. The operator describes the observation in 1–1000 characters. Elapsed
time, checkout, reenrollment and a restart alone are insufficient evidence.

This action records the operator's assertion; it does not stop or erase the Mac,
independently verify the observation, or claim the earlier installation succeeded.
The earlier attempt remains uncertain. The receipt retains its actor, reason,
evidence kind, old attempt, replacement enrollment and time. Database constraints
bind both enrollments to the same identity, allow one receipt per attempt and
reject subsequent updates or deletion. A receipt never resolves a later unknown
attempt on another enrollment.

The current Mac must be enrolled and ready for application management. No other
enrollment with that identity may remain active. Permissions are checked in the
transaction: organization-wide certificate and software management, plus device
enrollment and software assignment in the selected scope. The audit event is
committed with the receipt and retains the current device's site.

Ordinary software readers see only a generic conflict indication on the current
device. Previous device identifiers, names, other-site history and receipt actors
require the organization-level review permissions. All recovery pages use
`no-store`; read models omit encrypted package source URLs. Mutations require CSRF
and explicit confirmation, reject duplicate or query-supplied inputs, and use the
bounded ADE form parser.

## ADE continuation

The existing required-application policy waits with the
`previous_enrollment_unresolved` reason while a previous attempt remains blocking.
Recording evidence schedules the current admission for reconsideration. It does
not enqueue a package or release Setup Assistant in the receipt transaction.
The previously authorized ADE requirement may enqueue its first attempt during
reconciliation if it has no assignment yet. Existing cancelled or failed
assignments still require an explicit new request.

Setup release continues to require post-acceptance observations of the managed
app and exact approved version. Stopping evidence alone never satisfies that
requirement. Unattended Platform SSO additionally needs immutable profile/app
binding and its managed-administrator sequence; provider registration occurs
after release and remains separate work.

## Validation and acceptance boundary

The local PostgreSQL check applies all 28 actual migrations in an isolated
transaction and prepares 164 production application/ADE statements. The schema
is rolled back after the check. An additional execution check verifies the actual
trigger accepts a valid receipt, rejects update/deletion and preserves the old
uncertain attempt. Twelve browser scenarios against the actual
rendered templates cover unresolved, resolved, active-duplicate and reader states
at widths 390, 768 and 1440 pixels. They pass keyboard interaction, required
confirmation, scoped form/CSRF values, hidden unavailable actions and horizontal
overflow checks.

Native tests exercise synthetic signed reenrollment and checkout, case folding,
package/tenant/identity isolation, delivery cancellation, immutable receipts,
audit rollback, 102-entry pagination, later unknown attempts and ADE continuation
through exact-version verification. Route tests cover organization/scoped roles,
CSRF, strict forms, target scope, escaping and credential privacy. The source at
[`9e898d6`](https://github.com/the-luap/openuem-console/commit/9e898d6dec953d520882c777a1b55b1ab1424938)
passes both complete
[push CI](https://github.com/the-luap/openuem-console/actions/runs/34329722520) and
[PR CI](https://github.com/the-luap/openuem-console/actions/runs/34329728451) workflows,
including Linux/Windows builds, console/native race tests, gateway/access/audit
checks, existing Windows deployment models and desktop command services.
The rendered templates and assets used for browser checks are unchanged from
`15261be` through this validated source revision.

No installer is executed and no Mac is stopped or erased by these tests.
Physical reenrollment, installer stopping evidence and Apple/ADE acceptance still
require real-device validation. This milestone does not complete the roadmap.

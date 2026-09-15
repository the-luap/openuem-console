# Scoped, atomic legacy task creation

Task creation now requires current server administrator authority and the exact
profile audience. The transaction holds the destination parent and its existing
tasks, normalizes their positions by stored order and ID, then appends the new
task. The new row, normalization and scoped `inventory.tasks.create` receipt
commit together. Audit or insertion failure and cancellation roll them back.
Other profiles, surviving definitions and historical results are unchanged.

The new task has a fresh identity, version one, no execution time or history and
is enabled. Its profile retains its assignment; a new task in an assigned profile
may run on its devices. The action makes no broker or provider request. Successful
POST returns a redirect to the destination only after commit. An uncertain
response asks the user to refresh that profile before retrying; request
deduplication remains separate work.

The old model creation method has been replaced by a configuration mapper that
uses the held transaction and request context. It supports the existing Windows,
Linux, macOS and Any task families, with platform compatibility checked before
creation. This does not add APT or the legacy WinGet update task type. Registry
default values now retain the selected value type. NetBird registration uses the
same common creation defaults, including its position and ignore-errors setting,
and requires a destination organization recorded as its provider tenant.

Nonempty local-user passwords and SSH key passphrases require configured server
encryption and are encrypted after authorization, before insertion. A missing or
unusable key prevents creation. The [task secret upgrade](task-secret-storage.md)
covers coordinated worker compatibility and legacy migration; broader secret
rotation and recovery remain open.

## Form and request boundaries

The existing scoped GET/POST `/tasks/:profile/new` routes remain. GET holds current
profile ownership and authority through an `inventory.tasks.create_review` audit
commit. It reads only the profile ID and a label limited to 512 characters, with
an explicit truncation notice. The form identifies its destination and explains
the effect of adding a task to an assigned profile.

POST accepts URL-encoded form data with a 256 KiB wire limit before CSRF
extraction. Query targeting, duplicate or unknown fields and alternate encodings
are rejected. Scripts are limited to 128 KiB, task names to the shared 2,048-byte
name validation and other fields to explicit limits. The existing task-family
validators still validate their configuration. NetBird accepts at most 100
nonempty, distinct group IDs of at most 128 UTF-8 bytes; IDs are JSON-encoded for
the existing stored representation. The native multiple selector submits IDs
separately from labels and retains stored selections. This fixes the previous
name/ID concatenation and splitting, which corrupted values with hyphens.

The full-width English form uses native required selectors, a required task name,
a submit button and a scoped cancellation link. Pending requests disable the
form controls. Changing a platform or category removes the previous dependent
fields, including scripts and hidden required subtype selectors, while preserving
the edited task name. Lookup and cancellation requests omit unrelated form values.
The later [task wizard change](task-wizard.md) binds these metadata and NetBird
group lookups to the destination profile and current scope.

Audit migration 027 enables review and create receipts in all three scopes. Audit
resources contain IDs and positions, without names, scripts or passwords. Both
store operations have a ten-second deadline. Production-scale contention from
the shared audience locks remains to be measured.

## Verification

PostgreSQL/race tests cover all scopes, current roles, wrong and ambiguous
profile audiences, 37 mapper/platform combinations, empty and existing profiles,
fresh defaults, deterministic positions, retained configuration/history and
scoped audit browsing/export. Tests also cover name and platform validation,
registry value types, NetBird scope/defaults, password encryption/decryption,
missing keys, mapper/audit rollback and cancellation. A transaction gate proves
that competing creation, parent/task changes, task-list reads and authority
revocation wait until commit; revoked access is rejected afterward.

Actual registered Apple/OIDC routes cover GET/POST, CSRF, strict forms, role and
scope rejection, escaped destination labels, read-only review, atomic append,
exact destination redirects and NetBird group IDs with hyphens. Forty-five
browser cases cover native validation, keyboard script submission, clearing
incompatible dependent fields, preserved names, isolated requests, native
NetBird groups and cancellation at 390, 768 and 1440 pixels. Normal and long-name
mobile states were visually inspected.

The full inventory PostgreSQL/race suite passes in 86.259 seconds and the full
audit suite in 9.658 seconds. Registered Apple/OIDC routes, affected macOS/Linux
race checks and the full Linux build pass. The final complete 1,647-case Chrome
matrix passes in 94.426 seconds.

Task editing is covered by the later [editing change](task-editing.md).
Broader legacy editor and other provider lookup authorization, immutable
profile revisions, delegated access and physical/provider acceptance remain open
in the expanded roadmap.

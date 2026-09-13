# Scoped, versioned legacy task editing

Task editing now holds current server administrator authority, the exact profile
audience and rechecked task ownership through one transaction. A save includes
the reviewed parent ID and task version. A changed parent or scope is rejected;
a stale version returns 409. Of two concurrent edits of the same version, exactly
one commits. Task type and platform cannot be changed through hidden fields.

Configuration changes, the next version and the scoped `inventory.tasks.update`
receipt commit together. An update or audit failure and cancellation roll back
the complete change. Task identity, parent, order, enabled state, last execution
time, profile assignment and historical reports remain unchanged. A task in an
assigned profile may run on its devices after its configuration changes. Success
returns a parent redirect only after commit. An uncertain response asks the user
to reload that profile before retrying.

The extracted mapper updates the locked task through a single SQL statement and
the request context. It retains the existing editable task families. Flatpak edits
now save the selected branch, and removing an MSI file hash clears both the old
hash and its algorithm. Legacy version zero remains editable. Unsupported task
families, invalid version ranges and oversized legacy definitions cannot be
silently loaded or truncated by this form. Adding APT editing remains separate
work.

## Review and secrets

An `inventory.tasks.edit_review` transaction authorizes the current task before
reading its editable configuration. Names are limited to 2,048 bytes, scripts to
128 KiB and other selected values to 16 KiB. Password and SSH-passphrase columns
are excluded from the returned configuration; separate Boolean checks indicate
only whether a value is stored. The old password-decryption-and-display path is
removed. Responses use `Cache-Control: no-store`, and the editor disables HTMX
history snapshots.

The native form defaults to keeping stored passwords and passphrases. Replacement
or clearing must be chosen explicitly. Keeping a value leaves its database column
untouched, without reading it into the application. A replacement password
requires a usable server encryption key and is always encrypted as newly entered
plaintext. Clearing requires an empty input. Conflicting action/value combinations
are rejected instead of silently ignoring a newly typed secret. SSH-passphrase
inputs are masked. Their stored representation remains compatible with the legacy
worker; encrypting and migrating that separate field requires coordinated worker
changes and remains open.

NetBird registration stays in its configured organization. Its edit form now
loads group choices through the bounded, audited [task wizard](task-wizard.md)
provider read. Saved IDs missing from the provider response remain selected with
an explicit saved-ID label. Group selection and the extra-DNS-label setting are
preserved, fixing the old editor's missing NetBird fields. Invalid stored group
representations fail without replacing them. The edit action itself makes no
provider mutation or broker call.

## Console and request boundaries

Existing scoped GET/POST `/tasks/:id` URLs remain. GET accepts no body or query
parameters. POST accepts only known URL-encoded fields, the reviewed parent/version
and explicit secret choices, with a 256 KiB wire bound before CSRF extraction.
Duplicate/unknown fields, query targeting and alternate encodings are rejected.
The creation form shares this parser without accepting edit-only targeting fields.

The English form uses the available width, displays task/profile/version IDs and
requires a task name. Native controls retain keyboard submission, and a fieldset
disables the controls while saving. Cancel returns to the reviewed profile without
sending configuration or secrets. Task-list and report links explicitly omit
inherited paging and form fields when opening the editor. On narrow screens,
Unix user fields are stacked
at full width. The advanced-mode toggle now changes display only and no longer
submits an unknown field; this also fixes creation with advanced mode enabled.

Audit migration 029 enables edit-review and update receipts in all three scopes.
Resources contain task/profile IDs and versions, without task definitions or
secret values. Store operations have a ten-second deadline. Production-scale
contention from the shared audience locks still needs measurement.

## Verification

PostgreSQL/race tests cover all scopes and roles, stale versions and parents,
immutable type/platform, masked secret review, explicit keep/replace/clear,
password encryption and missing keys, audit browsing/export, audit rollback and
cancellation. Further cases cover legacy version zero, oversized review, Flatpak
branches, MSI hash removal and NetBird organization mismatch. A transaction gate
holds competing edits, review, reparenting, deletion, audience changes and grant
revocation through commit. Concurrent versioned saves produce one winner, and
order/status/execution time and profile/issue/report history are preserved.

Actual registered Apple/OIDC routes cover strict requests, CSRF, all roles/scopes,
reviewed identity/version, escaped names, no-store responses, stale 409 responses,
commit redirects, absent secret values, default secret preservation and NetBird
group retention using an owned HTTPS fixture. Owned provider fixtures explicitly
detach their tenant association before cleanup because the legacy settings foreign
key cascades tenant deletion.

One hundred eight browser cases cover native saves and cancellation, required fields,
reviewed parent/version/type/platform, password choices, advanced SSH-passphrase
replacement, NetBird selection and long names at 390, 768 and 1440 pixels. Script
and Unix mobile views were visually inspected, including the corrected full-width
advanced fields. Nine cases open the editor from the real scoped task list and
verify that its inherited paging fields are omitted.

The full inventory PostgreSQL/race suite passes in 89.484 seconds and the full
audit suite in 15.400 seconds. Registered Apple/OIDC routes, affected macOS/Linux
race checks and the full Linux build pass. The final complete 1,755-case Chrome
matrix passes in 92.125 seconds.

Broader legacy profile/editor reads, one-off task dispatch, package search and
other provider/settings routes, SSH-passphrase encryption/migration, immutable
profile revisions, delegated access and physical/provider acceptance remain open
in the expanded roadmap.

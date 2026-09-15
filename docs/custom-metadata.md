# Organization fields and device values

Open **Custom fields** in the management navigation to define text fields for an
organization. A computer's **Custom fields** tab lists those definitions and
whether each value is configured. Open a field to read or edit that computer's
value. Lists contain at most 25 fields per page and preserve literal searches
across field names and help text. They do not load device value contents.

Both definitions and values require `metadata.manage`. Organization
administrators can manage their organization's fields and admitted computers;
server administrators can select any organization. Viewers and operators cannot
read or change these values. Computers must have exactly one site across the
database and be Enabled, No contact or Disabled. Missing, foreign, waiting,
unassigned and ambiguously assigned computers return the same unavailable
response, including on the older root and organization URL aliases.

Field names are case-sensitive and unique within one organization. Names accept
1–255 UTF-8 bytes, excluding blank-only text and control characters. Help text
accepts up to 4096 bytes. Values accept up to 16384 bytes. Help and values may
contain line breaks and tabs. The UI renders all content as escaped text;
quotation marks or markup never become executable form instructions. Invalid or
oversized legacy content requires an authorized data repair; editors refuse it
without silently rewriting a truncated value. Lists show bounded label previews.

## Editing and clearing

Saving a definition or value includes the revisions displayed by the editor.
Concurrent changes, legacy writers and changes away and back invalidate old
revisions. A conflict returns HTTP 409 and preserves the submitted draft beside
the current saved data. The value editor also checks the definition revision,
so a changed field meaning requires another review before saving.

A saved blank value remains configured. **Clear value** removes that computer's
value after a separate confirmation. Clearing checks both revisions and cannot
silently clear a newer value. An absent value has a durable revision: creating
and deleting it between two requests still invalidates an older empty editor.
Unchanged saves retain their revision. These operations update console metadata
and send no command to the computer.

The former direct metadata mutation handlers and model methods have been
removed. Old POST/DELETE list aliases cannot mutate records. New forms use exact
field allowlists, CSRF validation, canonical identifiers and a 64 KiB encoded
request limit. The definition catalog is organization-wide; computer values
retain the selected organization/site route scope.

## Reviewing a field deletion

**Review deletion** creates a ten-minute, actor-bound review containing the exact
field name, help text and number of computers with a configured value. The final
checkbox confirms deletion of the definition and all its values. Confirmation
rechecks current permission, definition revision, complete device ownership and
the reviewed value revisions. Changed values, values created and cleared again,
and changed site membership invalidate the review. Merely opening an unset value
does not invalidate a review.

Values whose organization ownership is foreign, missing or ambiguous prevent
both review and deletion, even for a server administrator. No foreign device
identifiers, value contents or partial affected counts are returned. Resolve the
assignments before making a new review.

The field deletion, cascading value deletion, revision tombstones, completion
receipt and audit event commit together. Audit failure rolls all of them back.
The immutable receipt retains the reviewed field name, help text and affected
count, survives the deleted field and accepts exact retries
without repeating the deletion. Completed, expired and conflicting responses
have no active confirmation form. Receipts require their original actor and
current organization permission to read.

## Transactions and audit

Each operation rechecks live grants inside the database transaction. Permission,
scope, site membership, field and value locks remain held until its audit commits.
Table locks also include absent values and older writers: membership/site reads
use shared locks; metadata writes serialize against other metadata readers and
writers. Operations have a ten-second deadline. This favors consistent review
and bounded failure over concurrent throughput during unusually heavy edits.

Audit migration `040_custom_metadata.sql` enables these inventory actions:

- `inventory.metadata.fields.list`, `field.read`, `field.create`, `field.update`,
  `field.delete_review`, `field.delete` and `field.receipt` use organization scope.
- `inventory.metadata.values.list`, `value.read`, `value.update` and `value.clear`
  use the computer's actual organization and site.

The prefixes in each list are shared: every action starts with
`inventory.metadata.`. Events contain identifiers and revisions, not field names,
help text or value contents. Value resource identifiers include the SHA-256 of
the complete device identifier, field ID and value revision; this also supports
legacy device IDs at the maximum length without exceeding the audit limit.
The hash covers the device identifier only. The existing inventory audit viewer,
exports and confirmed retention include the new events and preserve foreign
organization evidence. Operational deletion receipts and revision tombstones
remain independent of audit retention.

A device transfer review now binds metadata definition and value revisions.
Changing a value away and back after reviewing a transfer invalidates that
transfer. Reviews made before this upgrade must be created again.

## Coordinated upgrade

The pinned upstream Ent schema declares field names globally unique. The
console, worker and certificate manager now share the same small migration
adapter in `internal/models/metadata_schema.go`. It replaces that desired index
with `(tenant_metadata, name)` while retaining additive schema objects. Each
component tests the actual initializer twice with duplicate names in separate
organizations and an unrelated custom column/index.

Deploy [worker `130cb4a`](https://github.com/the-luap/openuem-worker/commit/130cb4a8db1dc9f5b3da6a1c4bcef8e9583ecc5a)
and [certificate manager `731da30`](https://github.com/the-luap/openuem-cert-manager/commit/731da30a3a86b8755410b09b7cc22be47ee1ae30)
or descendants retaining this adapter before upgrading the console. Drain older
console instances before allowing metadata edits.
Inventory migration `042_custom_metadata.sql` removes only global single-column
name uniqueness, creates the organization index and adds revision/deletion
protection. Existing definitions and values are retained and receive revisions.
An old component that still initializes the upstream schema can recreate global
uniqueness or fail once separate organizations reuse a name. Do not restart that
old initializer against the upgraded database. Automatic schema initialization
still follows the existing `ENV != prod` convention; the console inventory
migration and startup protection checks apply independently of that convention.

Console startup rejects missing/disabled revision guards, a missing or altered
organization index, or reintroduced global uniqueness. The organization index is
additive on new installations; upgrades remove the obsolete global invariant
explicitly. This is a coordinated schema upgrade, not an automatic downgrade
path. Retain a database backup when planning deployment or rollback.

PostgreSQL race tests cover migration preservation, restart compatibility,
isolation, pagination, text limits, concurrent writers, revocation, locks through
audit, clear/delete ABA changes, stale and expired reviews, exact retries and
atomic rollback. The real console router covers every alias and rejects legacy
bypasses, malformed forms and CSRF failures. Forty-five Chromium cases exercise
catalogs, drafts, blank values, confirmations and long content at
390/768/1440 pixels, including keyboard submission. The combined browser run
also checks 36 existing device-details/assignment cases and 12 shared-navigation
cases across all four roles (93 passing cases total).

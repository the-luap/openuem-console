# Organization tag administration

The tag catalog now supports delegated organization access. A reader or operator
with a grant for the entire organization can search and inspect definitions.
Organization and server administrators can create, edit and delete unused tags
through the `tags.manage` capability. Site grants, including grants covering
several individual sites, do not authorize this organization-wide catalog.

Open **Organization tags** from **Management pages**. The existing organization
administration URL also opens the catalog. Its organization selector contains
only organizations whose entire catalog the current account can read. Server
configuration remains available only to server administrators.

## Definitions and safe changes

The catalog returns at most 25 definitions per page, with an increasing ID cursor
and literal, case-insensitive name/description search. It does not load device
records, notes, task output or assignment identities. Each page or detail read
requires current permissions and a committed audit event before returning data.

Names are nonblank and bounded to 255 UTF-8 bytes; single-line descriptions are
bounded to 2,048 bytes. Colors retain the original 19-name palette or a six-digit
hexadecimal value. The editor preserves an existing custom color as a selected
option and offers the original palette for new choices. Saving an unchanged
named color preserves both its stored value and the tag revision. Shared device
badges and tag pickers resolve either representation to a bounded color, with
black or white label text chosen for contrast. Unsupported old color strings
display a neutral fallback and cannot inject CSS. Legacy data
exceeding the text transfer limits fails closed instead of being silently
truncated and overwritten. The upstream global name-uniqueness constraint remains
in force; a collision produces a generic unavailable-name error without naming
another organization or exposing its definition.

Opening a tag captures its current random revision UUID. Editing and deletion
must submit that exact revision. A changed definition, organization, hierarchy
or task link rotates the UUID, including changes through existing Ent writers.
Changing a field and restoring its old value does not restore the earlier UUID.
Recreating a deleted numeric ID also gets a fresh UUID. Same-value updates and
rolled-back changes preserve the original review.

Deletion requires an explicit confirmation and an unused current tag. Device,
profile, task and parent/child tag associations block deletion. The final
transaction locks the tag before checking those associations; new foreign-key
references cannot race the check and be silently removed by cascade. The
interface explains existing usage without disclosing assignment identities.
Definition edits preserve assignments. [Desktop tag assignments](desktop-tag-assignments.md)
now check the device/tag organization and commit current authority, membership
and audit together. Their separate creation/removal workflows retain their
existing administrator boundary.
The corresponding [legacy profile tag actions](profile-tag-assignments.md) now
check the profile's complete global, organization or site audience and commit
membership, assignment mode and audit atomically.

## Authorization, audit and upgrade

Every catalog operation rechecks permissions in its database transaction and
locks the selected organization. Mutations also hold the tag row through their
audit commit. Permission replacement waits for an admitted operation. Audit
failure or cancellation rolls back the mutation; the browser receives no success
redirect. Missing or foreign tag IDs do not authorize another organization.

`inventory.tags.list`, `.read`, `.create`, `.update` and `.delete` events use the
existing scoped inventory audit source. Events retain the original organization,
actor, action and relevant tag/revision IDs. Existing audit export and explicitly
confirmed retention apply. These events identify the changed revision; they do
not provide a historical copy of every tag field.

Inventory migration 10 adds the tag revision column and schema-pinned insert/update
guard. Repeated startup preserves revisions and checks the required column and
active guard. Audit migration 14 admits the new organization-scoped events.
Coordinate the upgrade and stop older console writers before enabling these
routes. Reload old tag forms: unversioned edits and the old DELETE submission
cannot bypass current review. New forms use bounded URL-encoded POST bodies,
strict single-valued fields, CSRF checks and explicit deletion confirmation.

## Verification

Owned PostgreSQL/race tests cover organization/site roles, foreign IDs, legacy
writers, restored values, ID recreation, literal search, pagination, current
revisions and grants, audit rollback and migration guards. Assignment tests cover
devices, profiles, tasks and hierarchies, including foreign-key waits. A gated
final audit proves that deletion retains permission and reference locks through
commit. Registered console routes exercise actual sessions, forms, redirects,
CSRF denial, stale review and unavailable deletion.

Responsive browser fixtures cover create/list, empty, edit, used, read-only and
long-content states at 390, 768 and 1,440 pixels. They verify keyboard search,
editing and confirmed deletion, retained revisions, scoped links, text escaping,
theme foreground and permission-aware organization navigation.

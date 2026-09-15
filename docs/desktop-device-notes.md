# Desktop device notes

Open a computer's **Device notes** tab to edit its existing Markdown notes.
Organization administrators can read and edit notes for admitted computers in
their organization; server administrators can select any organization. Viewers
and operators have no access to note contents or the editor. The separate
`devices.notes.manage` capability applies to reads and writes, including all
existing root, organization and site `/computers/:uuid/notes` aliases.

Save submits the version displayed when the editor opened. If another writer
changed the notes, the response is HTTP 409 and preserves the submitted draft.
Review the currently saved notes, merge the changes into the draft and save
again. The server never silently replaces a newer version. Successful saves
redirect to the saved notes; saving identical text leaves its version unchanged.
The editor accepts up to 64 KiB of UTF-8 text, including tabs and line breaks.
Invalid or oversized historical notes are refused without truncating stored text.
Markdown previews strip active markup and embedded images; reading a note does
not fetch image URLs provided by its author.

Inventory migration `039_device_notes.sql` adds an opaque UUID revision to the
canonical `agents.notes` field. A database trigger also advances that revision
when an older Ent writer changes notes. Unrelated agent reports do not advance
it, and replacing only the revision is rejected. Startup checks the trigger.
No note contents are rewritten by migration.

Every operation rechecks the actor's current grants inside its database
transaction and retains permission, device, site and complete membership locks
through audit commit. The device must belong to exactly one site across the
whole database. Waiting, foreign, orphaned and ambiguously assigned devices
return 404; admitted disabled computers remain eligible for notes.

Audit migration `037_device_notes.sql` enables `inventory.notes.read` and
`inventory.notes.update` in the existing inventory audit source. The target is
the device ID and resulting random revision. Events retain the actual
organization/site and actor without note text or a content hash. Reads withhold
content if the audit cannot commit; updates roll back both notes and revision.
Existing inventory audit viewing, exports and guarded retention cover the events.

PostgreSQL race tests cover concurrent edits, stale and legacy revisions,
permission revocation, membership locking through audit commit, hidden devices,
input limits and audit failures. Real console route tests cover all aliases,
both permitted administrator roles, denied viewer/operator access, CSRF, draft
preservation and saved-state redirects. Template tests check escaped drafts and
sanitized Markdown; browser checks exercise editing at mobile and desktop sizes.

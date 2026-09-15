# Desktop display name, description and type

Open a computer's **Device details** tab to edit its display name, description
and device type together. Organization administrators can edit admitted computers
in their organization; server administrators can select any organization.
The editor requires `devices.details.manage` for both reads and writes.
Viewers and operators cannot open or submit it. Other inventory views retain
their existing read permissions.

The display name is a console label, not an operating-system rename. Clearing it
uses the reported hostname in the inventory, computer list and computer detail
headers; when neither name is present, the device ID remains visible. A
description can also be cleared. Saving sends no command to the computer and
does not change enrollment, organization/site membership or installed software.

Names accept up to 255 UTF-8 bytes and cannot contain control characters.
Descriptions accept up to 4096 UTF-8 bytes, including line breaks and tabs. The
device type must be one of the existing seven types shown in the selector. The
editor displays descriptions as escaped plain text. Oversized or invalid stored
values are refused rather than silently truncated; they require correction
through an authorized data repair before this editor can use them.

## Concurrent edits and older forms

Every save includes the revision displayed when the editor opened. A newer
change produces HTTP 409: all three submitted fields remain in the draft and
the current saved values are shown separately. Review those values before saving
again. Saving unchanged values retains the revision, while a successful changed
save redirects to the current editor. Empty fields remain explicit form values.

Inventory migration `041_device_details.sql` adds a protected UUID revision to
the canonical `agents.nickname`, `agents.description` and `agents.endpoint_type`
fields. A trigger changes that revision for any writer changing those fields,
including older Ent writers and changes away and back. Unrelated notes and
hostname updates do not invalidate the edit. Startup checks the revision trigger.
Existing fields are preserved during migration.

The former overview and nickname mutation methods have been removed. Their old
POST aliases retain their server-administrator boundary and redirect to the new
editor without changing any submitted field. Old overview organization/site
forms still redirect to the separate [assignment review](desktop-device-assignment.md).
The new editor is available at all root, organization and site `/computers/:uuid/details`
aliases, with native CSRF forms, exact field validation and a bounded request body.

## Authorization and audit

Every read/save rechecks current grants within its transaction and holds the
permission, selected scope, device and complete site-membership locks until the
audit commits. The computer must have exactly one site across the database.
Foreign, waiting, unassigned and ambiguously assigned computers return the same
404 response. Enabled, No contact and Disabled computers remain eligible.

Audit migration `039_device_details.sql` enables `inventory.details.read` and
`inventory.details.update`. Events retain the actual organization/site, actor,
device ID and resulting revision, without copying names, descriptions or content
hashes into the log. Reads withhold data when auditing fails; writes roll back
all three values and their revision together. The shared inventory audit viewer,
exports and confirmed retention include both actions.

An organization/site transfer review also binds the details revision. Changing
these fields after reviewing a transfer invalidates that transfer's data impact.
Transfer reviews created before this upgrade must be opened again under the new
impact digest.

PostgreSQL race tests cover concurrent edits, legacy changes, empty values,
UTF-8 limits, role/scope isolation, permission revocation and locks through audit
commit. Actual console route tests cover all aliases, CSRF, strict forms,
conflict draft preservation, old-form redirects and audit rollback. Browser
tests cover editing, conflicts, empty names and long fields at 390/768/1440
pixels, including the shared breadcrumb header and keyboard submission.

Custom organization metadata, other legacy device mutations, native hostname
changes and further device action permissions remain separate roadmap work.

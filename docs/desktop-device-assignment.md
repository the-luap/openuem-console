# Desktop organization and site changes

Open a computer's **Assignment** tab, or **Change organization or site** on the
legacy overview. Select a destination, review the source, destination and data
impact, then explicitly confirm the move. Destination search treats `%` and `_`
literally and returns at most 50 sites per page. The destination organization is
derived from the selected site's actual database membership.

The `devices.assignments.manage` capability allows organization administrators
to move an eligible legacy computer between sites in their own organization.
Only a global server administrator can move it to another organization, even
when an account administers both organizations. Viewers and operators cannot
open reviews or submit changes. Every root, organization and site route uses
the same checks; stale overview forms redirect into the review workflow before
saving any submitted description, type or assignment.

## Review and data impact

The source computer must have exactly one site across the entire database and
an Enabled, No contact or Disabled status. Waiting, unassigned, foreign and
ambiguously assigned computers are unavailable. The review lasts ten minutes
and belongs to its original actor, device, source and destination.

Moving within one organization preserves tags and organization metadata values.
Changing organizations permanently removes all of that computer's tag
assignments and organization metadata values. The review displays their counts
without exposing metadata contents. Existing notes and inventory reports follow
the computer and become accessible under the destination's permissions. The
confirmation page explains that transfer. Installed software and device
configuration remain in place; this operation sends no agent command.

Any retained individual enrollment identity prevents this inventory-only move,
including a revoked identity. Its certificate, broker identity and historical
records remain bound to the original organization/site. Use the appropriate
retirement and new-enrollment procedures for those devices. This page does not
implement credential transfer, history merging, automatic re-enrollment or
native Apple/Windows MDM reassignment.

At confirmation, current source and destination authority is checked again.
Changes to membership, destination organization, displayed names, status,
platform, note revision, tags or metadata invalidate the reviewed impact.
The existing permanent device-binding revision also detects moves away and
back. An expired or changed review returns HTTP 409 with a link to start again;
it cannot partially remove metadata or move the device.

The membership change, any tag/metadata deletion, completion receipt and both
scope audit events commit in one database transaction. Permission, device,
organization/site, identity and complete legacy edge-set locks remain held
through audit insertion. An audit or database failure rolls the operation back.
These table locks also cover older writers that do not use the new workflow;
concurrent legacy membership, tag and metadata writes may wait during a review
or confirmation transaction. Requests have a ten-second database deadline.

## Receipts and audit

Inventory migration `040_device_assignments.sql` stores an immutable review and
allows only its first completion timestamp. A completed confirmation retry
returns that same historical receipt without performing another move. It still
requires the original actor and current authorization in both stored scopes.
The receipt identifies the original transfer rather than claiming that the
computer still has that assignment today. Its device link opens the stored
destination, where normal current inventory access applies.

Audit migration `038_device_assignments.sql` enables these inventory events:

| Event | Scope | Resource |
| --- | --- | --- |
| `inventory.assignment.choices` | Actual source | Device ID |
| `inventory.assignment.review` | Original source | Review UUID |
| `inventory.assignment.read` | Original source | Review UUID |
| `inventory.assignment.depart` | Original source | Review UUID |
| `inventory.assignment.arrive` | Original destination | Same review UUID |

Audit records contain no note text, metadata contents or content hashes. The
review's internal impact digest is not exported as an audit event. Existing
inventory audit viewing, export and confirmed organization retention cover
these actions. Removing a source organization's old audit events preserves the
destination's evidence and the immutable review/receipt table.

PostgreSQL race tests cover atomic cross-organization deletion, same-organization
preservation, concurrent confirmation, expiry, changed data, ambiguous sources,
current grants, individual identities and audit failures. Registered console
route tests cover role restrictions, all aliases, strict bounded forms, CSRF,
stale overview submissions and recovery pages. Browser tests exercise eight
states at 390, 768 and 1440 pixels, including long destination names, keyboard
selection, mandatory confirmation, historical receipts and inactive failures.

Description, endpoint type, nickname, custom metadata and other remaining
legacy desktop mutations still require their individual authorization and
audit work under SEC-01/SEC-02.

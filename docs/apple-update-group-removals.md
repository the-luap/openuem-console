# Remove matching policies from an original Apple update assignment

Open an [original group assignment](apple-update-groups.md) and select **Review
matching policy removal**. The preview retains the original native enrollment
IDs. Current group membership, plan revisions, archive state and release catalog
availability do not expand or replace this cohort.

The preview includes only active original enrollments with unexpired identities
whose configured version, build, device-local deadline and information URL match
the original plan. It excludes absent or different policies, inactive/expired
enrollments and devices outside the original site. Details for a device outside
the site are withheld. Each included policy is shown before explicit confirmation.
The original plan definition is labeled as historical; its current availability
is not inferred from the retained assignment.

Confirmation requires the complete reviewed eligible selection, up to 100 native
enrollments. Every configured value and the ability to send a declarative
notification are checked again inside the mutation transaction. A conflict
changes nothing and requires another review. Matching values are not proof of
continuous policy ownership: another action can change a policy away and back.
Confirmation authorizes removal of the currently matching values.

## Removal and device evidence

Removal deletes the server's configured update policy, cancels earlier pending
declarative notifications and queues a new notification when the enrollment's
current capability permits it. The device must retrieve its current declarations
to observe removal. A device that no longer supports declarative notifications
can still have its server policy removed; the preview explicitly identifies this
case and the receipt records that no notification was available.

Server policy removal does not establish device-side removal, undo an installed
OS update or prevent later authorized assignments and scheduled actions from
configuring another policy. The [current cohort progress](apple-update-progress.md)
view continues to separate reported OS evidence from the currently configured
policy. The removal receipt records admission and original notification IDs;
it is not a live delivery or installation result.

## Atomic admission and immutable replay

Migration 048 adds encrypted immutable removal receipts linked by scoped foreign
key to the original group assignment. A receipt retains the request identity,
actor and current permission revision, original assignment, exact reviewed native
selection and its notification IDs. Encryption binds the metadata to the payload;
decoding validates each target against the authenticated original assignment and
its policy/notification comparison. The database rejects receipt updates/deletes.

Current `ManageUpdates` and `ReadDevices` authority and original site ownership
are retained through the transaction. Canonically ordered native device locks
prevent concurrent policy changes. Removing policies, canceling/queuing
notifications, writing the receipt and every audit commit together. A final-audit
failure or an identity that expires while that audit is waiting rolls back all
device and receipt changes. The operation has a ten-second deadline.

A repeated request with the same current actor/permission revision, original
assignment and reviewed selection returns its original receipt before consulting
mutable plan, group, catalog or device state. It does not remove a later policy
or queue another notification. Reusing that request identity with different
inputs is a conflict. A changed permission revision cannot reuse the old request.

## Console and read bounds

All routes require current update authority in the exact original site; store
operations additionally retain current device-read authority through their audit:

- `GET /ios/update-plans/:plan/group-assignments/:assignment/removal`: current preview.
- `POST /ios/update-plans/:plan/group-assignments/:assignment/removals`: confirmed admission.
- `GET /ios/update-plans/:plan/group-assignments/:assignment/removals`: receipt history.
- `GET /ios/update-plans/:plan/group-assignments/:assignment/removals/:removal`: original receipt.

The POST accepts one URL-encoded body up to 16 KiB, with body CSRF, a request UUID,
one exact selection field and explicit confirmation. Duplicate/unknown fields,
query overrides and unsupported encoding are rejected. The wire bound is also
applied before global CSRF parsing, including the header-token path.

Preview loads bounded identity/capability fields and at most 8 KiB of configured
policy values per original enrollment. It does not decode full application,
security or general inventory or consult the release catalog. Status and raw
policy error text are not needed for configuration removal. History returns at
most 25 receipts and authenticates its cursor and each decoded receipt, including
their original assignment binding. A receipt payload is limited to 32 KiB.
Database/audit errors withhold the result and console errors use fixed text.

## Verification

Owned PostgreSQL/race tests cover original target retention after archival and new
enrollments, exclusions, bounded metadata, concurrent exact replay, later policy
preservation, complete-cohort confirmation, unsupported notification capability,
late audit rollback, final identity expiry, immutable history, authenticated
pagination and metadata/ciphertext/parent corruption. They exercise the actual
declarative endpoint after removal. Registered Linux console routes cover current
roles, strict forms, conflicts, replay, history and absent/different-policy previews.

Eleven browser states at 390, 768 and 1440 pixels exercise explicit keyboard
confirmation, exact eligible selection, scope-preserving navigation, long values,
unavailable-device privacy and truthful notification evidence. These synthetic
checks do not replace physical-device removal acceptance.

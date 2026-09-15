# Apple update policy admission

The device page shows a separate [audited update assessment](apple-update-assessment.md)
using fresh packet OS evidence and independently displayed policy status/errors.

The device page applies or removes an Apple declarative update policy using
`SetReviewedDeviceUpdatePolicy`. The authenticated actor's current
`updates.manage` and `devices.read` authority is checked inside the
policy/notification/audit transaction. A missing permission store is denied.
Permission replacement and account changes cannot race past the retained
authorization locks. The in-process batch `SetUpdatePolicyWithAccess` entry point
retains current update authority without a console review precondition.

The transaction locks the organization and checks each selected device's current
site ownership. Moving a site to another organization makes old native inventory
unavailable to the previous scope, including organization-wide requests and
server administrators. A policy update has a ten-second deadline and a consistent
native-device lock order. It accepts 1–1000 distinct canonical native enrollment
UUIDs. The console currently submits a single device.

Application and removal use the same authority boundary. Application retains
existing enrollment, supervision, platform/version, Mac update authorization,
release availability and recent catalog checks. Removal remains possible when
update eligibility is no longer present, provided the device remains enrolled.
Policy changes, declaration notifications and per-device audits commit together;
a failure on the last target rolls back earlier work. The trusted in-process
`SetUpdatePolicy` wrapper is retained for protocol fixtures; console handlers use
the authorized entry point.

## Console form boundary

The action accepts one 8 KiB URL-encoded POST body. Application requires the
selected version/build and device-local deadline, with an optional HTTPS
information URL. Both actions require one canonical `expected_policy` value from
the audited device assessment. Removal accepts only `remove=true`, that comparison
value and body CSRF. It cannot be combined with application fields. Unknown fields, duplicate values, query
arguments, content encoding and header-only CSRF credentials are rejected.
Global CSRF extraction applies the wire limit before parsing, including requests
with header tokens, so padding cannot disappear into a cached normalized form.
Device form templates retain their existing application and removal controls.

The comparison binds the reviewed native enrollment, its actual organization/site
and the configured version, build, deadline and information URL, including policy
absence. The transaction acquires the device's exclusive mutation lock before
reading and comparing current configured values. A changed policy or a move to
another site yields HTTP 409 before mutation. Reload the device to review the
current values and submit again. Device status, error details and observation
timestamps do not invalidate a configuration review. Two concurrent requests
that change the same reviewed values cannot both overwrite them.

This is a value comparison, not an immutable revision or request receipt: changing
away and back to identical values restores the same comparison value. Resubmitting
an unchanged policy can still queue a new notification. No installation result
is inferred from the comparison. [Immediate group assignments](apple-update-groups.md) establish their own
reviewed plan/group revisions, current-policy comparisons, exact eligible selection
and immutable replay evidence. [Scheduled activation](apple-update-schedules.md)
retains an original group review for a bounded UTC window. Exceptions and promotion
remain separate work.
[Versioned Apple update plans](apple-update-plans.md) now provide a separate
reviewed catalog; saving a plan does not assign it. A configured or active policy
does not prove an installed update; the device page
continues to distinguish desired state from reported OS and compliance evidence.

## Verification

Owned PostgreSQL 17/race tests cover viewer/missing-authority denial, scoped and
organization administration, malformed/repeated target IDs, both actions after
site movement, pending permission replacement, concurrent site movement and
rollback after the final target's audit fails. These tests pass in 5.735 seconds.
The broader update/declaration/Mac readiness regression passes in 9.358 seconds.

Twenty-nine form cases cover separate apply/removal intent, repeated fields,
missing fields, query/body conflicts, CSRF, media/encoding and raw/preparsed size
bounds, including missing, duplicate, malformed and noncanonical comparison values.
Current review tests cover concurrent changes, stale application/removal, independent
device progress, original scope/device binding and final-audit rollback.
Middleware, handler and locale race tests pass on macOS and Linux.
Registered Linux console routes exercise actual application/removal, viewer
denial, actual rendered comparison values, stale-form conflicts, malformed forms
and unchanged command queues after rejection. Browser keyboard submissions retain
the reviewed value and scoped CSRF fields for both actions. The full
Linux build passes. These are synthetic local tests; physical update, restart,
APNs and live release-provider acceptance remain separate.

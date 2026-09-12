# Apple update deadline estimates

The individual device update section and original-cohort progress now show an
estimate of deadline timing. The device section uses its current configured
policy. Cohort progress uses the immutable original plan's device-local deadline,
including after policy replacement, removal, source edits or archival.

## Reported time zones

Migration 049 stores one bounded time-zone observation per native enrollment.
Authenticated Device Information processing records a valid time-zone name,
the fixed `device_information` source and database receipt time in its existing
exclusive device transaction. Missing, invalid or unsupported responses clear the
previous projection. Unrelated declarative status does not refresh the zone or
its timestamp. Legacy inventory is not backfilled as fresh evidence. A late
protocol failure rolls the observation back with the command transaction.

The `TimeZone` query is requested on iOS/iPadOS 14 or later and macOS 26 or later.
Apple's pinned query schema lists those versions, but its response schema still
marks macOS unavailable. Consequently, a missing Mac response stays unknown;
query eligibility is not a claim of verified Mac response support. This
implementation consumes a valid actual response without substituting the
organization, site, browser, operator or server's local time zone.
[Apple Device Information schema, revision 67045e2](https://github.com/apple/device-management/blob/67045e2fa06f528b196c01edee6a8bf88b844beb/mdm/commands/information.device.yaml).

Names must resolve through Go's time-zone database and fit the 128-byte storage
bound. Host-local aliases and paths are rejected. The binary embeds a fallback
time-zone database for systems without installed rules; installed or explicitly
configured server rules can take precedence. Keep server time-zone rules current.

## Timing and evidence limits

An estimate requires an active enrollment with an unexpired identity and a valid
zone report recorded no more than 24 hours before the database assessment time.
Missing, stale, future-dated, invalid or unavailable evidence produces **Deadline
timing unverified** with a fixed explanation. OS evidence is assessed independently.

The strict device-local timestamp is resolved against the reported zone's rules.
A local time skipped by a clock change has no corresponding instant and remains
unverified. A repeated hour can have multiple corresponding instants: the view
shows their UTC range and retains **Estimated deadline pending** until the latest
possible instant. At that instant the estimate becomes **Estimated deadline
elapsed**. This avoids choosing an arbitrary side of a daylight-saving fold.

The estimate uses the last reported zone and server-side rules. It cannot prove
the device's current location, clock, future travel, local rule database or actual
enforcement behavior. It does not establish installation or attribute an update
to a particular assignment.

Cohort elapsed, pending and unverified counts partition the original selection.
**Original target still required after estimated deadline** additionally requires
a valid, fresh OS report after admission and at or after the latest possible
deadline instant. A pre-deadline report cannot contribute to this final count,
even if its independent OS result still indicates an update is required. A
compliant or unverified OS result cannot contribute either. These counts do not
send reminders, escalate, retry device commands or promote another update ring.

## Access, display and verification

Both estimates are part of the existing audited assessment transactions and
retain their current device-read/update authority, scope, locking and ten-second
bounds. A device outside the original site exposes no current name, zone,
observation or device link in cohort progress. Read or audit failure withholds
the entire assessment. Protected models omit ordinary diagnostic and
JSON/XML/YAML output; the console renders the authorized zone as escaped text.

Owned tests cover authenticated query collection and version gates, absent and
malformed responses, unrelated status, transaction rollback, freshness, original
versus current policy, moved devices and OS evidence independent of deadline
timing. Time-zone tests cover Berlin gaps/folds, Lord Howe's half-hour fold,
Kathmandu's quarter-hour offset and Kiritimati's skipped day, plus post-deadline
OS evidence. Registered viewer/group routes and Chrome fixtures exercise the
display and permissions. This is protocol and console evidence; physical-device
acceptance and macOS response behavior remain open.

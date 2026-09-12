# Apple device update assessment

The update section on an Apple device page compares its current configured
policy with packet-based OS observations. It shows the OS version, accompanying
build, source and time at which the version was recorded. General inventory
fields remain elsewhere on the device page; they cannot supply a missing OS
observation or build in this assessment.

The assessment uses the same [OS observation rules](apple-update-progress.md#os-observations-and-result-criteria)
as original-cohort progress. An active enrollment with an unexpired identity and
an observation from the last 24 hours can be **Up to date** when its numeric
version is newer than the target, or the version and accompanying build match.
Policies with no target build require only the matching version. A lower version
or a different reported build at the target version means **Update required**.
Missing, stale, future-dated or invalid reports and a missing required build
receive an explanation and cannot establish current compliance.

A version-only report clears the accompanying build. A build-only delta does not
associate that build with an earlier version or refresh its timestamp. Unrelated
incremental status messages do not refresh OS evidence. The existing merged
inventory is never backfilled as a fresh packet observation. A policy's device
status and escaped error details appear independently: a reported policy failure
does not replace the assessment of the reported OS.

The individual assessment concerns the current policy and does not attribute an
OS result to an assignment. Original-cohort progress additionally requires an
observation recorded after the original admission and retains that receipt's
original targets. Neither view proves that a particular assignment installed an
update, nor replaces physical-device acceptance.

## Authority and consistency

`AssessDeviceUpdate` requires current `ReadDevices` authority, including for a
viewer. It accepts an authorized organization or exact-site scope, locks current
authority and organization/site ownership, rechecks the device's site after
acquiring its shared device lock, and reads its current policy and observation.
The update snapshot and its `apple.update.plan.device.assessment` audit commit in
one transaction with a ten-second deadline. Missing authority, moved scope,
database errors and failed audit writes withhold the assessment. The device
route returns fixed permission or availability errors without exposing database
details. Other sections on the device page retain their separate read paths;
the entire device page is not a single snapshot.

Policy configuration fields are bounded to 8 KiB combined before decoding;
status is bounded to 64 bytes. At most 8 KiB of error details are loaded for the
device page and rendered as escaped text. Longer errors produce a fixed notice
without loading their text into the response. Cohort progress continues to read
only the presence of an error. Observation and assessment models suppress
accidental JSON/XML/YAML serialization and formatted diagnostic output.

Existing [policy application/removal](apple-update-policy-admission.md) forms
retain their current permission and scope requirements. Loading this assessment
does not queue device work. The older `UpdateCompliance` function remains an
in-process inventory helper; the console update section uses the audited packet
assessment.

## Verification

Owned PostgreSQL tests exercise partial and complete OS packets, independent
policy errors, report freshness, expired/revoked enrollments, organization/site
authority, moved devices/sites, bounded source reads and audit failures. A held
final audit demonstrates that permission revocation waits until the read commits,
and the following read is denied. Registered console tests exercise the actual
viewer route, missing and complete observations, absent builds, escaped and
oversized errors, fixed source-failure responses and policy removal.

Eleven rendered states are checked in Chrome at 390, 768 and 1440 pixels. These
checks verify separate policy/OS evidence, absence of merged inventory fallback,
bounded long-text layout, scoped CSRF forms and read-only viewer behavior.

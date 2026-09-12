# Reviewed Apple pilot promotion

From an original assignment's **Current cohort progress**, open **Review pilot
promotion**. Review every original pilot enrollment, choose a destination plan
and dynamic group, then confirm the complete eligible selection. The console
records the qualifying pilot evidence and destination assignment together.
Current `updates.manage` and `devices.read` permission in the exact original
organization/site are required for every step, including receipts and history.
[Organization-group destinations](apple-update-organization-promotions.md) also
require current organization-wide source read rights for preview and admission.

This is an explicit promotion action. It does not automatically promote a ring
or continuously reconcile group membership. Existing individual, group and
scheduled assignments remain independent actions; this feature does not impose
a global prerequisite on all update admission.

## Pilot readiness

Every original pilot enrollment must pass, including devices that later leave
the dynamic group. Current plan edits or archival do not alter the original
cohort or its saved target. A ready pilot requires all of the following:

- The original enrollment remains active in the original site with an unexpired
  identity. Moved, inactive, expired or unavailable devices block promotion.
- Current configured version, build, device-local deadline and information URL
  match the original pilot values. The policy has no reported error, and no
  temporary update exception is active.
- An authenticated OS observation was recorded after pilot admission and within
  the last 24 hours. A higher numeric OS version qualifies; the exact target
  version requires its matching build from the same report. Missing, stale,
  future, invalid, incomplete or still-required OS evidence blocks promotion.
- After a temporary exception ends or expires, the OS observation was recorded
  at or after that latest exception's end.

Matching policy values do not prove continuous ownership by the pilot; policies
may have changed away and back. Notification acknowledgments and device-local
deadline timing are independent of readiness. These checks establish observed
OS evidence under current configuration, without attributing an installation
to a particular assignment. See [cohort progress](apple-update-progress.md) and
[temporary exceptions](apple-update-exceptions.md).

## Destination review

The destination plan must be active and use the original pilot's platform,
target version and build. Its deadline and information URL may differ. The
current destination group must be active. Choose either a site group or an
organization group evaluated only within the selected target site. The complete
site intersection may contain at most 100 members across enabled inventory
sources; matching devices elsewhere are outside the action. Ordinary [group admission](apple-update-groups.md)
checks current native channel, platform, prerequisites, release availability,
exceptions and downgrade rules for every member.

At least one eligible destination enrollment must be outside the original pilot.
A destination consisting only of pilot devices cannot broaden a rollout. Pilot
members that also belong to the destination are explicitly included and marked
in the preview. Confirmation applies the destination policy to them again,
including any changed deadline and the displayed policy replacements. No pilot
member is silently removed from the destination's eligible selection.

The confirmation form carries the destination source kind, plan/group revisions, complete
eligible native IDs, every reviewed current-policy token and a request UUID.
It requires a checked confirmation and body CSRF token. Only the nine declared
fields are accepted, with a 16 KiB wire and parsed-body limit sufficient for
100 targets. Duplicate fields, query overrides, unsupported media/encoding and
header-only CSRF credentials are rejected. Plan and group choices use 25-entry
pages with scoped links; a stale revision requires another review. Missing
`group_source` retains the original site-only API. Unknown or duplicate source
kinds are rejected, and dropping the field cannot select an organization group.

## Atomic admission and retries

A bounded ten-second transaction locks current operator authority and site,
source plan/group/catalog and applicable Mac channel mappings. It locks the
canonical sorted union of original pilot and destination native enrollments,
at most 200 IDs, before reading pilot policy/OS evidence or writing destination
policies. This ordering also permits concurrent promotions with overlapping
cohorts without reversing device lock order.

Confirmation assesses the pilot again and compares the entire current eligible
destination selection and policy tokens with the submitted review. Source,
membership or policy changes require a fresh review. Qualifying pilot evidence,
destination policies, declarative notifications, the ordinary group assignment,
promotion receipt and all audits commit together. An expired identity or OS
observation that becomes stale before the final check rolls everything back,
including the destination assignment and its notifications.

Concurrent identical requests create one promotion and one destination
assignment. An exact retry checks current authority, actor/grant revision and
all original request intent, including source scope, then returns the immutable original receipt before
consulting mutable pilot or destination state. It cannot restore a subsequently
removed or replaced policy. Reusing the request UUID with changed intent or
permission revision is rejected.

The destination receipt links to its original notifications and current cohort
progress. Admission is distinct from notification delivery and installation.
The resulting assignment may be reviewed as the next pilot, but each original
device in that new cohort needs qualifying OS evidence after its new admission.
There is no timer or background worker for promotion.

## Saved evidence and history

Migration 052 adds immutable promotion receipts with exact scoped foreign keys
to both the original pilot and resulting group assignment. A unique destination
assignment can belong to only one promotion. SQL rejects receipt updates and
deletion. A bounded 128 KiB encrypted intent binds the complete destination
review, private child request identity and pilot evidence to the promotion IDs,
source IDs, scope, actor, permission revision and recording time. New version-2
intents additionally retain the destination group scope and require the child
assignment to carry that same source. Original version-1 receipts remain
readable and retryable with their original site source. No schema migration or
history rewrite is needed. All instances reading newly written receipts need
the updated reader; the original pilot evidence format is unchanged.

Saved evidence contains each original pilot's native ID, OS version/build,
packet source and timestamp, identity expiry, matching policy token and any
latest exception end time. It retains no raw status document or current name of
a moved device. Reads authenticate both immutable source receipts and validate
the evidence against the recorded admission time, so later expiry, device
movement, policy changes or plan archival do not rewrite history. Protected
models omit their contents from ordinary formatting and public JSON/XML/YAML.

History uses 25-entry keyset pages anchored by an authenticated promotion from
the same original pilot and site. Receipts and history commit their read audit
before returning any result and prohibit response caching. Source integrity or
read-audit failure withholds the result without exposing an internal cause.

## Verification

Owned PostgreSQL 17/race tests cover authenticated declarative OS reporting,
all-original readiness, exception timing, archived pilots, explicit overlap,
new destination members, competing confirmations, current policy/grant locks,
late identity expiry, final-audit rollback, exact retries and immutable evidence
substitution. History tests cover 25-entry pages during later insertions, moved
devices and failed read audits. The combined pilot/promotion tests pass in
54.554 seconds. The complete Apple PostgreSQL/race suite passes in 713.737
seconds. Broader regression evidence is recorded in
[implementation status](implementation-status.md).

All 37 current strict form-boundary cases pass, including explicit and legacy
source kinds, duplicate-source rejection and a complete 100-device selection. Actual registered Linux routes cover selection, stale pilot proof,
changed destination policy, successful admission, retained receipts, replay,
permissions and rejected query overrides. macOS/Linux package race checks and
the full Linux build pass. All 378 relevant browser cases pass. Sixty new Chrome cases cover plan/group choice, blocked readiness,
overlap, exact keyboard confirmation, history, receipts, reader controls and
long escaped metadata at 390, 768 and 1440 pixels. These are owned synthetic
checks. Actual Apple update installation, APNs delivery, reboot behavior and
physical pilot acceptance remain separate evidence.

The organization-source extension and its additional verification are described
in [organization-group pilot promotions](apple-update-organization-promotions.md).

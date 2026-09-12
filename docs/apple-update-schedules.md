# Scheduled Apple update activation

Open an exact-site [Apple update plan](apple-update-plans.md), select **Assign to
a dynamic group**, and review its complete eligible selection and existing-policy
replacements. **Schedule this update** retains that review for a later start.
Enter the absolute UTC time as `YYYY-MM-DDTHH:MM:SSZ`, an activation window of
1–10,080 minutes, and explicitly confirm the source, selection, replacements and
timing. The plan's update deadline remains local to each device.

The server accepts activation up to 90 days ahead, with a one-minute past-time
tolerance for submission. The server checks the activation window again after
the creation audit, immediately before commit. Saving a schedule changes no device policy and reserves no queue slots.
Each site permits at most 256 pending schedules, including entries waiting to retry.

## Original intent and current authority

Migration 046 stores immutable schedule identity, exact organization/site, client
request UUID, original plan revision, creator and permission revision, creation
time and activation window. A bounded 32 KiB authenticated encrypted intent
retains the full original plan definition, group revision/name/rule, enabled
inventory sources and 1–100 canonical native target IDs with their reviewed
configured-policy tokens. The ordinary complete-group limit of 100 members still
applies, including excluded management identities.

Each intent contains a separate random activation request UUID. This private key
is never exposed in the schedule model, forms or history. It is not derived from
the public schedule ID or client retry key. It becomes visible only as the
ordinary receipt's request ID after a successful activation.

Creation uses current `ManageUpdates` authority and shared permission/site locks,
then serializes site admission counts and request identity. Exact retries return
the original record before consulting mutable plan, group, device, catalog or
server source configuration. They still require current authority and the original
creator's permission revision. A changed actor, source revision, selection,
policy token or timing under the same client request UUID returns a conflict.
Replaying a canceled or activated request cannot rearm it.

## Activation and atomic outcomes

The maintenance loop resumes immediately after native Windows initialization
fixes the enabled inventory sources at console startup, then every minute. It
runs independently of push-reminder SMTP, the public Apple listener and NATS.
Each pass selects at most 25 due records and has a 30-second context. Each selected
record has its own transaction bounded to ten seconds. Competing servers use
shared authority locks followed by `FOR UPDATE SKIP LOCKED` on the schedule.
Shutdown cancels and joins both Apple maintenance workers.

Before admitting any device work, the worker rechecks the creator's current
permission revision, original site ownership and enabled sources. The ordinary
group assignment path then rechecks the exact current plan and group revisions,
complete eligible native selection, current configured-policy tokens, native
channel identity, prerequisites and a fresh locked release catalog. Changed
sources or review inputs block the schedule; no subset is silently activated and
no newly matching members are added.

Policy changes, declarative notifications, their original group receipt, every
audit and the authenticated schedule transition share one transaction. The
worker checks the database clock after admission and again after the final audit.
If the activation window expires during those waits, a savepoint rolls back all
admission work and records an expired schedule. A final audit failure rolls back
the entire attempt. No committed device work can be separated from its activated
schedule state by a process restart.

Recoverable PostgreSQL serialization, deadlock and lock-contention errors roll
back admission and record a one-minute retry. Other processing failures roll back
the attempt; the maintenance loop reports a fixed message without underlying SQL
errors, decrypted sources or target IDs. A malformed record does not prevent other
records selected in the same batch from being processed. Persistent corrupted
records require storage investigation; they are not silently rewritten.

Activation receipts are checked against the original schedule's exact scope,
source definition, group, creator/revision, targets and private activation key.
Their creation time must fall after schedule creation and the requested start,
and no later than the schedule's completion inside its activation window. This
binding is checked again when reading an activated schedule.

## History and cancellation

**Scheduled activations** on the plan page opens 25-entry timestamp/UUID history
pages. Original sources remain readable after later revision or archival.
Details show UTC timing, fixed lifecycle reason, original targets, attempts and
current state revision. An activated schedule links its original receipt; device
links open current reports and compliance. Protected reads require current update
authority in the original scope and a successful audit, and prohibit caching.

Any currently authorized operator in the site can explicitly cancel a pending
schedule, including one created by an operator whose access has since changed.
Cancellation locks current authority and the schedule and requires its exact state
revision. It cannot undo activation. Terminal states cannot be rearmed or deleted;
changing intent requires a new review and client request. Authenticated lifecycle
state binds phase, revision, timestamps, attempts, receipt identity and original
intent ciphertext. SQL also freezes original inputs and enforces monotonic state
progression and terminal shape.

Both schedule creation and immediate confirmation enforce a strict 16 KiB
URL-encoded wire/parsed bound, including before global CSRF token extraction.
Cancellation retains an 8 KiB bound. Duplicate/unknown fields, query overrides,
unsupported encodings, missing body CSRF, invalid UTC values and unchecked
confirmation are rejected. Scheduling timing fields are rejected by the immediate
assignment route.

## Evidence and limits

Owned PostgreSQL 17/race tests cover future preservation, exact and concurrent
creation, competing activation, restart, current authority and scope changes,
source flags, plan/group/member/policy/catalog changes, ciphertext substitution,
processing another selected record after corruption, pending limits, keyset
history, terminal immutability, cancellation, retry backoff and audit rollback.
An expiration test reaches the final activation audit and verifies that every
staged device change and receipt is rolled back. Synthetic registered console
routes exercise actual future creation, cancellation and due activation. Browser
tests exercise UTC timing, confirmation, history and cancellation at 390, 768 and
1440 pixels. The complete Apple PostgreSQL/race suite passes in 523.030 seconds;
registered Linux console routes, macOS/Linux package race checks and the Linux
build pass. Eighty-four relevant Chrome cases cover scheduling, group review,
plans and navigation. The owned PostgreSQL SMTP shutdown/maintenance lifecycle
test passes in 2.105 seconds. These fixtures do not contact Apple or physical
devices.

Scheduling establishes admission intent and evidence. Normal declarative
management, release reconciliation and device reports determine delivery and
installation. It does not freeze release availability until device delivery or
introduce a separate delivery-time group authorization mechanism. Configured
policy tokens compare values, not a durable generation; changing a policy away
and back to the same values is not detected as a distinct generation.

Continuous group reconciliation, group removal, exceptions, automatic pilot
promotion, aggregate historical cohort compliance and physical-device acceptance
remain separate work.

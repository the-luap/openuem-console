# Native Windows ring assignments from dynamic groups

The immediate and scheduled ring assignment forms offer **Choose devices from a dynamic
group**. The chooser lists groups in the exact selected site, 25 per page.
Archived groups cannot be selected. An operator chooses a numbered revision;
the form loads its native Windows members and shows the other management
identities as exclusions. These may be desktop agents, native Apple devices or
linked Mac identities. No agent ID is converted to a Windows enrollment ID.

The complete group must contain at most 100 members across all enabled sources,
not just 100 native Windows targets. Over-limit groups fail without truncation.
Inventory metadata uses the same per-field and cumulative bounds as device
exports. There must be at least one native Windows target. Organization-wide
groups are not available in this site assignment flow.

The target field is read-only when it comes from a group. Selecting the group
again starts a new draft with fresh membership. **Review revision and devices**
shows the original group name, revision and rules, the native Windows device
list and all exclusions. It retains the existing per-device identity checks and
explicit confirmation checkbox. Manual target entry remains available through
the original assignment flow. Scheduled drafts also retain the selected UTC
activation time, activation window and device admission lifetime.

## Admission and provenance

New immediate assignments and future plans authorize `updates.manage` in the concrete site,
resolve the current group under the admission transaction and require the exact
reviewed native Windows target set. A changed/archived group or different native
Windows membership returns 409 and requires a new review. The group head stays
locked until the transaction ends. Membership is evaluated from one current
inventory query; later inventory changes do not automatically add or remove
targets from the admitted cohort. Source eligibility, each device's lifecycle,
creator grants, command admission and audits retain the existing
[ring safeguards](native-windows-update-rings.md).

The cohort captures the group UUID, revision, original name and platform/search
rules inside its authenticated encrypted target intent. No new plaintext source
columns are needed. The current reader accepts legacy version-1 explicit-target
intent and version-2 group intent. It rejects mixed/invalid versions, invalid
source definitions and changed ciphertext. Scheduled group intent additionally
captures the enabled inventory sources; explicit-target plans remain version 1.
Older console versions cannot read version-2 group cohorts or plans.

An exact confirmed retry reuses the original cohort, even after the group is
changed or archived. It still rechecks current actor authority and original
request equality. Omitting/changing the group reference or changing the reviewed
targets cannot reuse the committed request UUID as another operation. A later
group edit does not cancel admitted work or substitute a newer definition during
delivery. The assignment history displays its original encrypted group evidence
and offers a separately labeled link to the current group and its history.

## Scheduled group evaluation

Saving a plan rechecks the group revision and exact reviewed native Windows
membership, and creates no device commands. Its encrypted intent retains that
source and the server's enabled inventory stores. The maintenance worker checks
the same revision, native membership and enabled stores when activation is due.
A changed/archived group or changed target set becomes terminal `blocked` with
reason `group_changed`; a changed source configuration uses
`group_sources_changed`. Neither outcome creates a partial cohort. The operator
must review a new plan; restoring a definition or server setting cannot rearm
the old plan.

Exact request retries return the original plan and its current state, including
after a group or server configuration change. Once activation commits, the
cohort retains the plan's exact original group source. Delivery checks this
binding, while subsequent group edits do not rewrite or recall admitted work.
The [schedule history](native-windows-update-schedules.md) shows the original
group source, blocked reason and activated cohort link. Existing ring, creator,
device, queue, cancellation and activation-window safeguards still apply.

Preview and grouped admission have ten-second deadlines. Shared membership
reads require a committed inventory group read audit; an audit failure withholds
the preview or rolls back admission. Group fields are accepted on immediate and
scheduled assignment POSTs within the existing 8 KiB body, unique-field and CSRF limits.
The chooser and initial form reject unknown/duplicate query fields and malformed
URL encoding. No group field expands the URL's site authority.

## Verification and remaining work

Owned PostgreSQL 17 tests run with the actual Linux binary and race detector.
They exercise native and excluded identities, new-member conflicts, removed
permissions, audit rollback, exact replay after archive, source/delivery
provenance, protected formatting, invalid encrypted versions and the
100/101-member boundary. The existing ring and schedule tests also run against
the changed admission and decoding paths. The registered console suite tests
the chooser, readonly form, review/confirmation, source replay, malformed group
references, viewer denial and the separate immediate/scheduled confirmation fields.
Scheduled cases cover activation, archived definitions, added native members,
changed source configuration, exact replay, late audit rollback, invalid protected
intent and original group proof during the full seven-step device exchange.

Thirty-six Chrome cases cover immediate chooser, empty, form, preview, historical
source and long metadata, plus scheduled chooser, form, preview, history and both
group-related blocked outcomes at 390, 768 and 1440 pixels. They verify exclusions, scope/revision
links, readonly targets, explicit keyboard confirmation and exact submitted
source fields. Browser form submissions are intercepted in the fixture; the
registered route tests exercise actual admission in the disposable database.

Organization-group/site intersections, larger
target cohorts, exceptions, automated pilot promotion, Apple/software group
assignment and physical Windows patch/restart acceptance remain separate work.

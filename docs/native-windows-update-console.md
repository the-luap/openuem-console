# Native Windows update policies, rings and history in the console

Open a native Windows device, then **Windows update policy runs** to inspect its
immutable update intent and historical device evidence. A current `ManageUpdates`
grant in the device's exact site is required for both reads and cancellation.
Readers without that capability do not receive protected policy details.

## Configure and review policy

Choose **Configure update policy** in a device's update history. The form exposes
all 13 settings supported by the typed compiler: quality/feature deferrals,
deadlines and grace periods, restart behavior, active hours, notification level
and driver exclusion. Blank values or **Unmanaged** omit that setting from this
run. They do not remove previously managed configuration. Numeric zero and
boolean **No** are explicit values and survive preview, editing and persistence.

Select **Apply selected settings** or **Remove selected settings from this
management source**, a short policy name and an admission lifetime of 1–168 whole
hours. Removal uses the explicit setting selection; numeric values displayed in
that selection are not applied by the removal action. The lifetime starts on
confirmation and bounds admission of new steps; it does not schedule a Windows
restart or undo configuration when it expires.

**Review policy and device** validates ranges, matching deadlines for grace and
restart options, both active-hours endpoints and the allowed nonzero span.
Validation errors preserve the draft and return an HTML error page. The preview
shows the device UUID, organization/site names, action, lifetime and every setting.
**Edit selected settings** returns to the same draft. Neither preview nor editing
queues a command. A confirmation checkbox is required before final admission.

The form's random request UUID stays stable through preview and editing.
Identical confirmed retries return the original run. Changing intent while
reusing a committed request UUID produces a conflict instead of replacing or
duplicating work. Every confirmation revalidates the complete typed policy and
live actor/site/device permissions; an earlier preview confers no lasting authority.
The form endpoints reject enrollment metadata already marked revoked or expired.
Admission and delivery retain their independent lifecycle checks.
The existing store performs atomic intent/command/audit admission and retains its
delivery-time platform, identity, permission and source checks. Queue acceptance
still requires later Windows contact and device evidence.

## Versioned update rings

Choose **Windows update rings** from native Windows management in a concrete
site. Operators with `ManageUpdates` can list the current revisions, create a
ring, inspect immutable history and edit the latest revision. Lists contain 25
rings per page; history contains 25 revisions with an exclusive revision cursor.
Disabled rings remain visible. Run provenance links to its exact historical
source revision instead of substituting the current ring settings.

The editor shares all 13 optional typed settings with the per-device form. It
also captures the ring name, enabled state, stable ring UUID, a fresh request UUID
and the expected base revision (zero for creation). **Review ring revision**
displays the site, proposed revision, enabled state and every setting without
writing a ring or queue entry. Editing from preview preserves the same draft.
**Confirm and save ring revision** requires a checked confirmation and calls the
existing transactional `SaveUpdateRing` service after fresh authorization and
validation. Identical retries return the original revision, including after a
later edit; changed requests and competing editors receive HTTP 409. Conflict
pages preserve the draft and direct the operator to review the latest revision.
No handler silently replaces the expected revision or merges concurrent changes.

Every saved revision retains its original policy and enabled state. Saving or
disabling a ring does not assign devices, cancel admitted work or remove Windows
configuration. A later apply assignment requires the current enabled revision.
Historical source removal and already admitted work retain the backend's existing
[ring semantics](native-windows-update-rings.md). The separate assignment form below
creates device work; ring creation alone never creates commands. The separate
[schedule flow](native-windows-update-schedules.md#schedule-from-the-console)
saves reviewed future intent and activates it through the existing worker.

These additional routes use the same prefixes and require a concrete site and
`ManageUpdates` throughout:

| Method and path | Behavior |
| --- | --- |
| `GET /windows/update-rings` | Current ring revisions, including disabled rings |
| `GET /windows/update-rings/new` | Start a new ring draft |
| `GET /windows/update-rings/:ring` | Audited revision history; optional `before` cursor |
| `GET /windows/update-rings/:ring/edit` | Load the current revision into a new draft |
| `POST /windows/update-rings/preview` | Validate/review or return to editing |
| `POST /windows/update-rings/save` | Confirm and save exactly one immutable revision |

Ring bodies retain the shared 8 KiB / 24-field ceiling, body-only CSRF, no-query
rule and per-action unique-field allowlists. Site ownership and permissions are
rechecked by the store; a sibling site cannot read or overwrite a ring. Protected
history/current reads return only after auditing commits. A failed save audit
rolls back both its revision and any new ring head. Generic failures do not
expose SQL errors or protected names.

## Assign an exact revision to devices

Open ring history and choose **Assign this revision** on the current enabled
revision, or **Remove this revision's settings** on a saved revision. The latter
supports explicit source cleanup after the ring was changed or disabled. The
editor shows the original revision name, policy and enabled state; it never
silently substitutes a newer revision.

Enter 1–100 distinct native Windows UUIDs, one per line, from the selected site's
native Windows inventory. This explicit list is separate from agent identities,
reported hardware IDs. The immediate assignment form can also
[select a reviewed dynamic group](native-windows-update-groups.md). Blank internal lines, duplicate IDs,
noncanonical UUIDs and more than 100 targets are rejected. The field is bounded
to 4,000 bytes inside the existing 8 KiB body limit. LF and CRLF lists and ordinary
surrounding line whitespace produce the same canonical sorted target set.
Choose apply or source removal and an admission lifetime of 1–168 whole hours.

**Review revision and devices** resolves every ID through an audited scoped
metadata read and shows the complete device list, names, site, revision, action,
lifetime and all original settings. Invalid target drafts remain editable. New
apply previews require the current enabled revision. The preview rejects device
metadata already marked revoked or expired, without treating enrollment metadata
as current device or policy evidence. Preview and editing create no commands.

**Confirm and assign revision** requires explicit confirmation and submits the
entire selection to `AssignUpdateRing`. The store rechecks current source/target
and actor authority and atomically creates the rollout, each device run, commands
and audits. A missing target or late audit error leaves no partial cohort.
Competing ring changes produce a conflict. Identical confirmed retries return
the original rollout even after its ring is edited or disabled; the handler does
not apply new-work eligibility checks ahead of that exact replay path. Changed
targets, mode, lifetime or source under a committed request UUID cannot become new
work. Preview does not preserve authority after permission replacement.

Confirmation redirects to **Windows ring assignment history**, which links each
original device run to its protected evidence and per-device cancellation flow.
The source link selects the exact historical ring revision. Per-device run pages
link back to the cohort, including cohorts created by the scheduled backend.
History uses audited rollout, device and run services. Device phases are separate
historical observations, not a simultaneous compliance snapshot or evidence of
patch installation/reboot. Assignment details do not offer a blanket cancellation
that could bypass the existing sent/uncertain step boundaries.

| Method and path | Behavior |
| --- | --- |
| `GET /windows/update-rings/:ring/assign/groups?revision=N&mode=apply` | Choose an exact site group revision for immediate assignment |
| `GET /windows/update-rings/:ring/assign?revision=N&mode=apply` | Draft an explicit revision/device assignment; mode may also be `remove` |
| `POST /windows/update-rings/:ring/assign/preview` | Validate/review all selected devices or edit the draft |
| `POST /windows/update-rings/:ring/assign/create` | Confirm atomic cohort admission |
| `GET /windows/update-rollouts/:rollout` | Audited original cohort and per-device historical evidence |

All assignment routes require a concrete authorized site and `ManageUpdates`, under
the same three console prefixes. The unique-field/CSRF/no-query POST boundary
also applies here. Names are escaped, and failed audited reads expose neither
protected payloads nor internal SQL messages.

## Schedule a reviewed cohort

Choose **Schedule this revision** or **Schedule source removal** from ring
history. The form shares explicit source/device selection with immediate
assignment and adds a UTC activation time and bounded activation window.
Preview shows both UTC boundaries, every target and current certificate expiry;
editing preserves the draft. Confirmed creation saves the original plan without
queuing device work. Exact retries preserve its identity and cannot rearm it.

**Update schedules** provides protected, paginated history and original intent,
worker state/reason and links to activated cohorts. Pending cancellation requires
the reviewed state revision and retains canceled history. The
[schedule guide](native-windows-update-schedules.md#schedule-from-the-console)
describes routes, timing limits, permissions, audit boundaries and verification.
Activation timing governs cohort creation; installation and restart behavior
remain separate Windows policy and acceptance concerns.

## Review a run

The list displays 25 runs per page, with bounded offsets and links to exact
device/run identities. Details use the existing audited
[`UpdateRunDetails` service](../internal/mdm/windows/update_details.go); the
handler does not infer success from enrollment metadata or command acknowledgments.

The page shows:

- The original policy, action, creator, admission window and optional ring
  revision/cohort provenance.
- Separate platform, configuration and policy read-back steps, with delivery
  and completion times.
- Historical platform/SKU evidence, dated release-catalog support information
  and the distinction between unestablished support and unassessed ESU status.
- Each observed setting's reviewed, configured and effective values, protocol
  status codes, outcome and batch receipt time.

Unmanaged settings, explicit zero and explicit false remain distinct. A missing
readable value never becomes zero. Removal means this management source's
configuration was absent in the observation; an effective value from another
source may remain. Partial verification retains earlier drift while reporting
that the collection is still incomplete. Separate batch times do not imply a
simultaneous snapshot or current continuous compliance.

**Policy values verified** does not establish patch download, installation or
reboot. The UI links to Microsoft's
[Update Policy CSP definitions](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-update)
for setting meanings. Policy changes create new immutable runs; existing run
history is retained. Actual update/restart evidence remains separate work.

## Cancel undelivered work

The cancellation disclosure appears only when undelivered steps remain and no
step is sent or uncertain. Its checkbox explicitly confirms cancellation of those
remaining steps. The store rechecks all steps under the device lock; a delivery
race returns a conflict instead of claiming cancellation. The transaction cancels
all eligible steps and records its audit together. Failed auditing rolls back
every transition. Already applied settings remain, and cancellation does not
remove policy from Windows. Terminal retries return a conflict.

The routes are registered under the same default, organization and
organization/site prefixes as the [enrollment console](native-windows-console.md):

| Method and path | Behavior |
| --- | --- |
| `GET /windows/:id/updates` | Paged policy-run history |
| `GET /windows/:id/updates/new` | Start a policy draft for this device |
| `POST /windows/:id/updates/preview` | Validate/review or return to editing |
| `POST /windows/:id/updates/create` | Confirm and admit an immutable apply/removal run |
| `GET /windows/:id/updates/:run` | Protected intent and historical evidence |
| `POST /windows/:id/updates/:run/cancel` | Confirmed cancellation of undelivered steps |

All require a concrete site. Unknown UUIDs, foreign devices/runs, ambiguous
offsets and invalid forms are rejected. POST bodies retain the 8 KiB limit and
at most 24 fields, with a per-action allowlist that rejects unknown/repeated names,
unique body CSRF token, exact form fields and no-query rule. Responses remain
non-cacheable. The Windows HTML referrer policy is `strict-origin`: ordinary
same-origin form POSTs preserve their Origin header for CSRF validation, while
credentials never enter a URL. Using `no-referrer` for these form pages causes
browsers to send an opaque `null` Origin, which the server correctly rejects.

## Validation

Real console/session and PostgreSQL tests cover admin/operator access, reader
denial, exact site isolation, invalid UUIDs/pages/forms, escaped policy names,
unaudited read denial, full cancellation rollback, CSRF, confirmation and terminal
conflicts. Render tests cover partial drift, verified values, source removal,
explicit zero/false, missing values and sent/uncertain cancellation suppression.
The CI view-test step includes the new Windows view package.

Policy-form parser and real console tests additionally cover all 13 typed fields,
unset/zero/false distinctions, canonical numbers and UUIDs, cross-field validation,
preview/edit with no queue writes, HTML error headers and retained draft values,
apply and removal mode, full seven-step compilation, repeated POST idempotency,
changed-intent conflicts, revoked identities, sibling-site isolation, live
permission loss after preview and full rollback after audit failure. The complete
browser flow uses a separate opt-in fixture before synthetic identity revocation:
set `OPENUEM_WINDOWS_POLICY_BROWSER_FIXTURE` to a private URL-file path and the
existing `OPENUEM_DESKTOP_BROWSER_HTTP=1` option for owned loopback HTTP. Creating
the URL-file's `.stop` sibling stops the fixture and permits schema cleanup.
Both apply and source-removal forms pass real browser cookie/Origin CSRF checks;
390/768/1440-pixel inspections preserve values and keep every control contained.

Browser acceptance uses an owned loopback console and synthetic queue state.
The real cancellation form passes cookie/Origin CSRF validation, redirects to
the retained history and removes its confirmation form after cancellation.
Generated partial/removal evidence pages also pass browser inspection at 390,
768 and 1440 pixels, with contained keyboard-focusable tables and no outer page
overflow. No test installs policy or contacts a physical Windows device.

The subsequent policy-form extension passes the full local handler/race suite
in 9.673 seconds, with Windows/shared view suites passing in 1.823/1.977 seconds.
The separate live browser-fixture run also passes, including its manual UI wait.
Vet and Linux/Windows builds pass. Both complete workflows pass for policy
form commit `f10b60b`
([push](https://github.com/the-luap/openuem-console/actions/runs/34427128033),
[pull request](https://github.com/the-luap/openuem-console/actions/runs/34427131094)).

The ring extension passes the full local handler/race suite in 8.919 seconds;
Windows/shared views pass in 1.913/1.872 seconds. Parser and real console tests
cover typed edit round trips, revision bounds, scope and capability isolation,
preview/edit without writes, confirmation and CSRF, exact retries after later
edits, competing editors, disabled history, cursor/list pagination, lost authority
and complete read/write audit failure handling. A queue-count assertion verifies
that ring edits never admit device work. Vet and Linux/Windows builds pass.
The pull-request workflow for ring commit `d716bee` failed at Chrome startup,
before the scoped-console suite
([run](https://github.com/the-luap/openuem-console/actions/runs/34428496587)).
Its Windows persistence/fuzz tests and both builds passed. The artifact recorded
no completed browser cases and omitted startup stderr, so it does not establish
the reason Chrome failed to publish a port within the previous polling budget.
Commit `7d80f5f` observes the same browser for at most 45 seconds, tolerates partial
port files and retains bounded startup diagnostics. Four synthetic child-process
tests and all 81 existing Chrome form cases pass locally; no browser sandbox flags
or form assertions were weakened. The ring commit's
[push workflow](https://github.com/the-luap/openuem-console/actions/runs/34428494432)
passed. Both complete workflows for subsequent cohort commit `d6fb091` pass with
the startup correction included; see the cohort validation below.

Set `OPENUEM_WINDOWS_RING_BROWSER_FIXTURE` to a private URL-file path to use the
same opt-in loopback fixture for rings. Browser checks exercise invalid dependent
settings, retained drafts, confirmed creation and disabling, and the unchanged
original revision. Forms remain contained at 390/768/1440 pixels; the narrow ring
list scrolls inside its keyboard-focusable table region. The final stylesheet
also wraps a 128-character unbroken ring name at 390 pixels. The separate live
browser run passes in 135.491 seconds, including the manual inspection wait.
A fresh fixture verifies the final long-name stylesheet and passes in 55.476 seconds.

The explicit-cohort extension passes the full handler/race suite in 8.503 seconds;
Windows/shared views pass in 1.984/2.028 seconds. Tests cover bounded normalized
UUID sets, real route permissions, previews without writes, retained invalid
drafts, two-device atomic admission, rollback after a late missing target or audit
failure, exact retries after ring changes, changed-target conflicts, historical
removal, sibling-site isolation and authority lost after review. Vet and both
Linux/Windows builds pass. Both complete workflows pass for cohort commit
`d6fb091`
([push](https://github.com/the-luap/openuem-console/actions/runs/34429700762),
[pull request](https://github.com/the-luap/openuem-console/actions/runs/34429703551)).

The opt-in `OPENUEM_WINDOWS_ASSIGNMENT_BROWSER_FIXTURE` uses the same loopback
fixture lifecycle. Browser acceptance rejects stale apply intent, preserves two
newline-separated targets through preview/edit and confirms historical source
removal through the real cookie/Origin CSRF middleware. Both resulting run links
retain the exact source revision and cohort backlink. Forms at 390/768/1440 pixels
remain contained, as do the narrow preview/history tables inside their focusable
scroll regions. The complete browser-fixture handler/race run passes in
107.525 seconds, including manual inspection; Windows/shared views pass in
1.913/1.891 seconds. These fixtures never install policy or contact physical devices.

The previous enrollment-console CI runs exposed a timing assumption in the
gateway schedule test: its repeated protected read could hold a shared lock when
the worker intentionally used `SKIP LOCKED`, delaying activation until the next
15-second pass while the test allowed only five seconds. Commit `55ffd76` observes
committed fixture metadata without that lock and validates the protected read
after activation. Twenty race-test repetitions with `GOMAXPROCS=1` pass in
20.172 seconds. This changes test observation, not worker cadence or locking.

Both complete workflows pass for test correction `55ffd76`
([push](https://github.com/the-luap/openuem-console/actions/runs/34424858851),
[pull request](https://github.com/the-luap/openuem-console/actions/runs/34424861695))
and history/cancellation commit `9f33aae`
([push](https://github.com/the-luap/openuem-console/actions/runs/34425352621),
[pull request](https://github.com/the-luap/openuem-console/actions/runs/34425355677)).
The subsequent policy, ring and cohort validation is recorded above. Schedule
console validation is recorded in the [schedule guide](native-windows-update-schedules.md#verification).

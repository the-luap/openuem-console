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
[ring semantics](native-windows-update-rings.md). Assignment and scheduling forms
remain separate work; ring creation alone never creates device commands.

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
history is retained. Ring assignment/scheduling forms and actual update/restart
evidence remain separate work.

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
Vet and Linux/Windows builds pass. The complete push workflow passes for policy
form commit `f10b60b`
([push](https://github.com/the-luap/openuem-console/actions/runs/34427128033));
the corresponding pull-request workflow is still running.

The ring extension passes the full local handler/race suite in 8.919 seconds;
Windows/shared views pass in 1.913/1.872 seconds. Parser and real console tests
cover typed edit round trips, revision bounds, scope and capability isolation,
preview/edit without writes, confirmation and CSRF, exact retries after later
edits, competing editors, disabled history, cursor/list pagination, lost authority
and complete read/write audit failure handling. A queue-count assertion verifies
that ring edits never admit device work. Vet and Linux/Windows builds pass.
Full CI for this extension is pending.

Set `OPENUEM_WINDOWS_RING_BROWSER_FIXTURE` to a private URL-file path to use the
same opt-in loopback fixture for rings. Browser checks exercise invalid dependent
settings, retained drafts, confirmed creation and disabling, and the unchanged
original revision. Forms remain contained at 390/768/1440 pixels; the narrow ring
list scrolls inside its keyboard-focusable table region. The final stylesheet
also wraps a 128-character unbroken ring name at 390 pixels. The separate live
browser run passes in 135.491 seconds, including the manual inspection wait.
A fresh fixture verifies the final long-name stylesheet and passes in 55.476 seconds.

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
The subsequent policy-creation form extension still awaits its own complete CI.

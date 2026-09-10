# Native Windows update history in the console

Open a native Windows device, then **Windows update policy runs** to inspect its
immutable update intent and historical device evidence. A current `ManageUpdates`
grant in the device's exact site is required for both reads and cancellation.
Readers without that capability do not receive protected policy details.

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
for setting meanings. Policy creation/editing, ring/schedule administration and
actual update/restart evidence remain separate work.

## Cancel undelivered work

The cancellation disclosure appears only when undelivered steps remain and no
step is sent or uncertain. Its checkbox explicitly confirms cancellation of those
remaining steps. The store rechecks all steps under the device lock; a delivery
race returns a conflict instead of claiming cancellation. The transaction cancels
all eligible steps and records its audit together. Failed auditing rolls back
every transition. Already applied settings remain, and cancellation does not
remove policy from Windows. Terminal retries return a conflict.

The three routes are registered under the same default, organization and
organization/site prefixes as the [enrollment console](native-windows-console.md):

| Method and path | Behavior |
| --- | --- |
| `GET /windows/:id/updates` | Paged policy-run history |
| `GET /windows/:id/updates/:run` | Protected intent and historical evidence |
| `POST /windows/:id/updates/:run/cancel` | Confirmed cancellation of undelivered steps |

All require a concrete site. Unknown UUIDs, foreign devices/runs, ambiguous
offsets and invalid forms are rejected. POST bodies retain the 8 KiB limit,
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

Browser acceptance uses an owned loopback console and synthetic queue state.
The real cancellation form passes cookie/Origin CSRF validation, redirects to
the retained history and removes its confirmation form after cancellation.
Generated partial/removal evidence pages also pass browser inspection at 390,
768 and 1440 pixels, with contained keyboard-focusable tables and no outer page
overflow. No test installs policy or contacts a physical Windows device.

The full local handler/race suite passes in 61.585 seconds, including the live
browser-fixture wait; Windows/shared view suites pass in 2.075/2.008 seconds.
Vet and Linux/Windows builds pass. Full CI for this console extension is pending.

The previous enrollment-console CI runs exposed a timing assumption in the
gateway schedule test: its repeated protected read could hold a shared lock when
the worker intentionally used `SKIP LOCKED`, delaying activation until the next
15-second pass while the test allowed only five seconds. Commit `55ffd76` observes
committed fixture metadata without that lock and validates the protected read
after activation. Twenty race-test repetitions with `GOMAXPROCS=1` pass in
20.172 seconds. This changes test observation, not worker cadence or locking.

# Native Windows CSP evidence and queue controls

Open a native Windows device and choose **Windows CSP commands**. The list,
payload details and both actions require the current `windows.csp.manage`
capability in that device's concrete site. Organization and server administrators
have this capability. Inventory readers and update operators cannot read arbitrary
CSP payloads or results, including custom Get data.

## Inspect original intent and device evidence

The list contains 25 commands per page with bounded offsets. It includes custom
requests and steps owned by typed update runs. Each row preserves the command
identity, authenticated phase, creation/admission times and optional owning run.
Details use the audited `CSPCommandDetails` service and show the immutable request,
state revision, creator, delivery identity, terminal time and latest correlated
device outcomes. Opening these pages does not enqueue or deliver work.

**Original command intent** preserves group order and nesting through operation
numbers such as `1`, `1.1` and `1.1.1`. Each leaf shows the exact target, value
format, MIME and original data. **Correlated device evidence** preserves parent
and child dispatch IDs, target nodes, numeric status and original device errors.
The latter are diagnostic text and do not override the protocol status.

XML and text data are escaped and displayed in keyboard-focusable, bounded scroll
regions. XML is never inserted as executable markup. Complete empty values remain
different from missing results. Incomplete Get objects have no visible partial
value. A complete result's format, MIME, byte count and escaped text/XML are shown;
base64 data is displayed in its received encoding rather than decoded as a file.

**Command acknowledged** means the required protocol evidence was received. It
does not prove effective configuration, compliance, installed patches or reboot.
Status 202 is asynchronous acceptance, while 516 reports failed rollback. Failed
groups can leave other operations applied. The view shows the latest correlated
snapshot, not an observation-by-observation timeline or a continuous compliance
assessment. The backend retains its separate append-only observation history.

## Cancel an undelivered custom command

**Cancel undelivered command** is available only for queued or blocked custom
requests. Confirmation includes the displayed state revision. The store rechecks
that revision and delivery phase under its device/command locks. A concurrent
delivery or revision change returns a conflict. Successful cancellation retains
the request and terminal history and removes the cancellation form.

Typed update steps link to **Open owning update policy run**. Their remaining
work must be canceled through that run's existing all-step workflow, which also
checks for another step's sent or uncertain outcome. The raw command cancellation
route rejects attempts to bypass this immutable ownership boundary.

## Resolve uncertain effects

An unknown command prevents subsequent queue delivery until its uncertainty is
resolved. **Record resolution and release queue** requires a resolution note,
explicit acknowledgment of uncertain effects and the displayed state revision.
The note accepts 1–320 UTF-8 bytes on one line, without surrounding whitespace or
control characters. Current permissions are checked again on submission.

The existing `AbandonCSPCommand` transaction accepts only an unknown outcome.
It records the note and abandoned state together with the audit, then releases
the command's queue barrier. It does not undo or retry the operation, declare
success or immediately deliver another command. Subsequent work retains all
normal eligibility and authenticated device-contact checks. A changed revision
or already terminal outcome cannot be overwritten. Typed steps retain their
owning run link and historical uncertain evidence after release.

## Routes and failure boundaries

All four routes exist without a prefix and under `/tenant/:tenant` and
`/tenant/:tenant/site/:site`, with a concrete selected site:

| Method and path | Behavior |
| --- | --- |
| `GET /windows/:id/commands` | Audited 25-command history page |
| `GET /windows/:id/commands/:command` | Protected intent and latest correlated outcomes |
| `POST /windows/:id/commands/:command/cancel` | Revision-checked cancellation of undelivered custom intent |
| `POST /windows/:id/commands/:command/abandon` | Revision-checked resolution of an unknown outcome |

The common Windows form boundary enforces body-only CSRF, a unique per-action
field allowlist, no query parameters, an 8 KiB body and at most 24 fields. Reads
return no protected data if required auditing fails. Cancellation and abandonment
fully roll back if their final write audit fails. Errors expose neither storage
details nor protected payloads. Responses use `no-store` and `strict-origin`.

## Verification and remaining work

The console integration fixture uses the public enrollment store and SyncML HTTP
handler to produce acknowledged Get results and asynchronous Exec uncertainty.
It uses a synthetic CSR and database identities; its `httptest` TLS state is not
a real network handshake. No host certificate, device policy or account is changed.
The existing Windows transport suite separately tests real loopback TLS.

Route tests cover actual administrator/operator/viewer permissions, lost authority
after review, sibling-site isolation, malformed IDs/pages/forms, CSRF, confirmed
cancellation, stale revisions, explicit uncertain resolution and terminal history.
Audit failures are tested both for reads and after mutation has reached its final
write audit. Typed-step cancellation cannot bypass the owning run. Pagination
retains old completed evidence. Render tests cover all nine states, request nesting,
escaped XML/errors/notes, incomplete-result suppression and empty/absent values.

The full handler/race suite passes in **9.566 seconds**; Windows/shared views pass
in **3.050/2.017 seconds**. Vet and Linux/Windows builds pass. The complete browser
fixture/handler race run passes in **67.919 seconds**, including manual inspection;
Windows/shared views pass in **3.033/2.049 seconds**. Full CI for this extension
is pending.

Browser acceptance uses actual cookie/Origin CSRF to record an uncertain outcome's
resolution, inspect the escaped retained note, then cancel its queued successor.
Both terminal pages retain history and remove their mutation forms. The resolution
form remains contained and preserves its text at 390/768/1440 pixels; a 768-pixel
screenshot passes visual inspection. At 390 pixels the history table scrolls inside
its keyboard-focusable region without outer page overflow. The browser reports
only the fixture's missing favicon, with no form or script errors.

The opt-in `OPENUEM_WINDOWS_CSP_BROWSER_FIXTURE` takes a private URL-file path;
`OPENUEM_DESKTOP_BROWSER_HTTP=1` permits the owned loopback HTTP console fixture.
It prepares a separate synthetic unknown command and a queued successor. Creating
the URL-file's `.stop` sibling releases the fixture and cleans its schema.

Custom command creation/review forms, an observation timeline, retention/export,
broader typed policies and physical Windows acceptance remain implementation work.
The full WIN-02 roadmap also retains lifecycle, integration and deployment work.

# Native Windows CSP commands, evidence and queue controls

Open a native Windows device and choose **Windows CSP commands**. The list,
payload details and all command actions require the current `windows.csp.manage`
capability in that device's concrete site. Organization and server administrators
have this capability. Inventory readers and update operators cannot read arbitrary
CSP payloads or results, including custom Get data.

## Create and review a custom command

Choose **Create custom CSP command** from the device's CSP history. The editor
accepts one bounded JSON command tree and an admission lifetime of 60–604800 whole
seconds. Its initial example is a Get for `./DevInfo/DevId`. Creation is available
for a current, non-revoked enrollment identity; current metadata does not establish
device contact, CSP support or compliance.

The JSON field names are exact, lowercase and unique:

| Field | Meaning |
| --- | --- |
| `kind` | Required Get, Add, Replace, Delete, Exec, Atomic or Sequence |
| `uri` | One canonical target per leaf |
| `format` | `chr`, `int`, `bool`, `b64`, `xml`, `null` or `node`, where supported by the operation |
| `mime` | Optional MIME type without parameters, where data is supported |
| `text` | Exact character data as a JSON string, including canonical integer, Boolean or base64 text |
| `xml` | Nonempty self-contained XML markup as a JSON string; requires `format: "xml"` |
| `commands` | A nonempty ordered array for Atomic or Sequence |

Groups contain only `kind` and `commands`. Text and XML cannot coexist. An empty
`text` string is explicit data; an omitted field supplies no data. For a null
value use `format: "null"` and `text: ""`; for an interior node use Add with
`format: "node"` and omit data. JSON nulls, unknown or repeated fields, numeric
values outside strings, malformed UTF-8 and unpaired UTF-16 escapes are rejected.
Valid surrogate pairs decode normally. Whitespace inside values is preserved.

For example, this tree reads a synthetic node before an Atomic replacement:

```json
{
  "kind": "Sequence",
  "commands": [
    { "kind": "Get", "uri": "./Device/Vendor/MSFT/Test/Value" },
    {
      "kind": "Atomic",
      "commands": [
        {
          "kind": "Replace",
          "uri": "./Device/Vendor/MSFT/Test/Value",
          "format": "int",
          "text": "0"
        }
      ]
    }
  ]
}
```

The example's synthetic node does not assert support on an actual Windows device.
The editor accepts up to 256 KiB of JSON. `PreviewCSPCommand` compiles the same
canonical request used by admission, retaining the existing 128 KiB encoded
request, 32-operation and four-child-level limits. Target exclusions, value
representation, Atomic and Sequence restrictions remain in the shared compiler.
It does not verify whether each CSP is supported by the selected Windows version
or edition. Typed policy forms retain their separate guided validation.

**Review command and device** shows the exact native UUID/site, enrollment type,
current certificate expiry, request UUID, lifetime, compiled size and every
operation/value with disclosures initially open. User targets require Full
enrollment; their eventual delivery also requires an eligible enrolled-user
session. Invalid drafts retain their original text and request UUID. **Edit
command tree** preserves the draft. Neither preview nor editing queues work.

**Confirm and queue command** requires an explicit checkbox and calls the existing
`EnqueueCSPCommand` transaction after fresh scope/permission validation. The store
recompiles the complete tree and commits the command and audit together. The
request UUID remains stable through preview/edit and identical retries, including
equivalent JSON formatting and field ordering. Changed intent or lifetime under
a committed UUID produces a conflict. Exact retries continue to identify the
original request after device revocation or queue saturation; the handler does
not add new-work identity checks ahead of the store's replay branch. New work
still requires current authority, enrollment and queue capacity.

Confirmation redirects to the protected command detail. It queues intent only;
delivery requires later authenticated device contact. Custom commands are not
automatically retried when their effects become uncertain.

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

All seven routes exist without a prefix and under `/tenant/:tenant` and
`/tenant/:tenant/site/:site`, with a concrete selected site:

| Method and path | Behavior |
| --- | --- |
| `GET /windows/:id/commands` | Audited 25-command history page |
| `GET /windows/:id/commands/new` | Start a custom command draft |
| `POST /windows/:id/commands/preview` | Compile/review or return to editing without queue writes |
| `POST /windows/:id/commands/create` | Confirm atomic, idempotent command admission |
| `GET /windows/:id/commands/:command` | Protected intent and latest correlated outcomes |
| `POST /windows/:id/commands/:command/cancel` | Revision-checked cancellation of undelivered custom intent |
| `POST /windows/:id/commands/:command/abandon` | Revision-checked resolution of an unknown outcome |

The common Windows form boundary enforces body-only CSRF, a unique per-action
field allowlist, no query parameters and at most 24 fields. Bodies remain limited
to 8 KiB except the exact custom-command preview/create routes. Those accept up
to 794624 bytes, allowing percent encoding of a 256 KiB JSON document and bounded
form metadata. The decoded command field has its own 256 KiB limit. Declared and
streaming bodies are both bounded; cancellation, abandonment and typed policy
forms retain their existing 8 KiB limit. Reads
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
Windows/shared views pass in **3.033/2.049 seconds**. Both complete workflows pass
for evidence-console commit `999d890`
([push](https://github.com/the-luap/openuem-console/actions/runs/34432831838),
[pull request](https://github.com/the-luap/openuem-console/actions/runs/34432834523)).

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

Custom creation adds parser and real PostgreSQL route tests for all operation and
value kinds, nested intent, zero/false/empty values, Unicode, malformed/duplicate
fields, body limits on all prefixes, protected roots, invalid groups, retained
previews, confirmed atomic admission, equivalent retries, changed intent, authority
loss, wrong-site targets, Full-enrollment checks, final audit rollback and queue
capacity. A 100,000-byte backslash value exercises a valid large form through both
preview and admission. Revoked identity rejects new work while exact replay keeps
its original command. The backend preview is checked against canonical admission
compilation and redacted serialization.

The creation extension passes the full handler/race suite in **10.463 seconds**;
Windows/shared views pass in **2.903/1.980 seconds**. The complete Windows PostgreSQL
race suite passes in **86.255 seconds**, with its protocol package passing in
**1.289 seconds**. The JSON editor fuzz target passes **111,393 executions** in
**31.993 seconds**, and CI now includes a bounded 15-second run. Vet and
Linux/Windows builds pass.

Set `OPENUEM_WINDOWS_CSP_CREATE_BROWSER_FIXTURE` for the creation fixture, using
the same `.stop` lifecycle. The browser corrects duplicate JSON fields, preserves
a nested tree through preview/edit, displays all six operations open and retains
numeric zero, Boolean false, whitespace, literal script text and Unicode. Real
cookie/Origin CSRF confirmation redirects to the queued command's protected
history with no delivery or invented device evidence. Forms and previews remain
contained at 390/768/1440 pixels; the edited 768-pixel form passes visual inspection.
The complete browser-fixture handler/race run passes in **80.036 seconds**, with
views passing in **3.045/1.883 seconds**. Its earlier duplicate-field rejection
returns the expected HTTP 400; the final page has no console warnings/errors.
Complete CI for the creation extension is pending.

An observation timeline, retention/export, broader typed policies and physical
Windows acceptance remain implementation work.
The full WIN-02 roadmap also retains lifecycle, integration and deployment work.

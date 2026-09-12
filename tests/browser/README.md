# Console form browser regression

Run the real rendered console templates and repository assets in a disposable
headless Chrome session. The runner covers 828 cases:

| Form | Case matrix | Cases |
| --- | --- | ---: |
| Enterprise Wi-Fi | System/User × existing/copied trust × three TLS ranges × three widths; reader at each width | 39 |
| Active Directory certificates | System/User × omitted/explicit options × three widths; reader at each width | 15 |
| IKEv2 certificate VPN | System/User × machine/EAP-TLS × existing/copied trust × three widths; reader at each width | 27 |
| Desktop inventory | Complete/incomplete and missing/zero-number reports × three widths; viewer/operator × six refresh states × three widths | 48 |
| Desktop software | Viewer/operator × first/next/empty/long reports × three widths | 24 |
| Desktop network | Four legacy DNS states and eight scoped report states × three widths | 36 |
| Desktop storage | Physical/logical × viewer/operator × first/next/empty/long reports × three widths | 48 |
| Desktop peripherals | Monitors/printers × viewer/operator × first/next/empty/long reports × three widths | 48 |
| Desktop memory modules | Viewer/operator × first/next/empty/long reports × three widths | 24 |
| Desktop shares | Viewer/operator × first/next/empty/long reports × three widths | 24 |
| Desktop security | Viewer/operator × first/next/empty/long/missing/negative reports × three widths | 36 |
| Management navigation | Four roles × three widths; native disclosure and scoped links | 12 |
| Unified device list | First/next/empty/long metadata × three widths; scoped filter links, keyboard pagination and export forms | 12 |
| Dynamic device groups | List/empty/detail/archived/viewer/long metadata × three widths; scoped revision links and keyboard saves | 18 |
| Windows group assignments | Six immediate and six scheduled states × three widths; exclusions, source revisions, blocked-plan causes and explicit keyboard confirmation | 36 |
| Apple profile assignments | Catalog, older assignment and unavailable source × three widths; exact source revision and keyboard apply/removal | 9 |
| Apple profile groups | Site catalog, chooser, empty chooser, apply/removal previews, exclusions, original receipt, populated/empty history and long metadata × three widths; immutable fields and keyboard confirmation | 30 |
| Apple update plans | List, empty, detail, archived, viewer and long metadata × three widths; exact revisions, retained history and keyboard saving | 18 |
| Apple update groups | Chooser, empty chooser, new/replacement previews, exclusions, original receipt, populated/empty history and long metadata × three widths; exact policy tokens and keyboard confirmation | 27 |
| OpenID account identities | Unlinked/active/disabled/ineligible/long/disabled provider × three widths; explicit keyboard confirmation | 18 |
| Account language | Seven catalogs, browser default, unavailable storage and long profile × three widths | 30 |
| Report timestamps | Seven catalogs × three widths | 21 |
| Windows precise timestamps | Seven catalogs × three widths | 21 |
| Windows health and update evidence times | Eleven states × three widths | 33 |
| Approved Windows software | WinGet/MSI/EXE approval and detail, reader, withdrawn and filtered catalog × three widths | 27 |
| Windows device requests | Prepared, reader, cancelled, expired, withdrawn and empty × three widths | 18 |
| Windows dispatch | Install/remove review, pending, delivered, observed, restart, uncertain, reader, cancelled, expired, failed and rejected start × three widths | 36 |
| Windows software checks | Install/remove review, empty, pending, delivered, observed, drifted, unknown, waiting, unavailable, cancelled, expired, reader and paged × three widths | 42 |
| WinGet sources | Empty, pending, other owner, reader, site, expired, withdrawn, approved, focused, paged, compatible/incompatible review, expired/withdrawn/approved review and derived revision and authority changes × three widths | 51 |

Widths are 390, 768 and 1440 pixels. The tests check browser validation, clearing
incompatible certificate selections, exact form values, required review, keyboard
confirmation/submission, repeated JavaScript initialization, reset, reader access
and horizontal overflow. Each suite captures a narrow screenshot. Assertions use
actual browser state; they do not replace the production scripts or mock the DOM.
Inventory checks also preserve read-only views, distinguish broker acceptance from
report completion, and check the refresh form's scope, CSRF token and request ID.
Software check cases preserve the original execution outcome after a verified
reservation release, validate exact review and cancellation fields, and check
scoped pagination and reader controls. They run no installer or endpoint query.
WinGet source cases preserve the exact original revision, selected installer and
approval hash, enforce separate keyboard confirmation, restrict controls by
ownership/deadline/scope and retain the derived revision's source evidence link.

## Run locally

Use Node.js 22.4 or newer and an installed Chrome/Chromium on macOS or Linux.
The CI workflow selects Node.js 24 and uses the runner's installed Chrome.
The runner uses Node's built-in WebSocket; no npm dependencies are needed.
Set `CHROME_BIN` when Chrome is outside the usual macOS or Linux locations.

From the repository root, render the synthetic states using the existing Go test:

```sh
go tool templ generate
APPLE_MDM_UI_ARTIFACTS=/tmp/openuem-ui go test -count=1 ./internal/views/...
APPLE_MDM_UI_ARTIFACTS=/tmp/openuem-ui node tests/browser/run.mjs
```

Alternatively, extract the `apple-mdm-ui` artifact from the same commit as the
checkout and pass that directory as `APPLE_MDM_UI_ARTIFACTS`. No database is
required for these rendered-view/browser checks. The separate protocol and
handler integration tests exercise persistence, authorization and actual routes.

`BROWSER_TEST_ARTIFACTS` optionally selects the result directory. Otherwise the
runner creates a temporary directory and prints its path. `results.json` records
the browser/Node version, timestamps, each completed case and the overall result.
`chrome-startup.json` records the startup outcome, elapsed time, exit/signal and
at most 8,192 characters of browser stderr, including when Chrome never opens a debugging
port. A failure exits nonzero and attempts to save `failure.png`. The workflow preserves
results and screenshots as `apple-mdm-browser`, including on failure.

## Isolation and limits

The runner starts a loopback server on a free port, serves only the allowlisted
synthetic pages and repository assets, and creates a temporary browser profile.
Page requests outside that read-only origin are blocked and fail the run; form
submissions are captured and prevented. Startup, protocol commands, navigation and
the overall run have time limits. Startup observes the same owned process for at
most 45 seconds and tolerates a temporarily empty or incomplete port file. It does
not retry by spawning another browser. `node --test tests/browser/chrome-startup.test.mjs`
checks delayed/partial port publication, early exit diagnostics, a live-process
timeout and interruption using synthetic Node child processes. Cleanup terminates only the spawned browser
process group and removes its temporary profile, including after test failures.
The browser sandbox is not disabled.

The suite uses native keyboard events for review and submission. Select values
are assigned with change events, so operating-system select menus are not covered.
These tests do not establish Safari, assistive-technology, provider or physical
device acceptance. They do not install profiles or contact a CA or VPN service.
Screenshots support visual review; they are not image-difference assertions.

Implementation references: [Node WebSocket](https://nodejs.org/api/globals.html#class-websocket),
[Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/),
[GitHub's Ubuntu runner inventory](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md).

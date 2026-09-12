# Native Windows update policy runs

The [CSP command service](native-windows-csp.md) now supports an immutable typed
update assignment with three separate stages: platform preflight, configuration
and read-back. `EnqueueUpdatePolicy` creates all stages atomically; authenticated
SyncML exchanges advance them. Apply and removal runs retain their original
intent and device evidence. The backend also provides audited detail/list reads
and cancellation of undelivered remaining steps.

This is update-policy management. A verified run confirms the values returned by
the device's policy CSP. It does not prove update download, installation, restart,
patch compliance, licensing or physical device acceptance. The
[listener](native-windows-operations.md) registers device protocol routes;
[run history and cancellation](native-windows-update-console.md) now have console
routes. [Scheduled cohorts](native-windows-update-schedules.md) are implemented;
[Typed policy forms](native-windows-update-console.md) now preview and confirm
per-device apply/removal intent. Ring/schedule administration forms remain
separate work.
[Versioned update rings and explicit cohorts](native-windows-update-rings.md) now
reuse these device runs with protected source provenance.

## Typed intent and authority

`UpdatePolicy` exposes the following optional fields. Omitted fields remain
unmanaged; explicit zero and false values are preserved. Configuration uses one
Atomic group of Replace commands. Removal uses Delete for exactly the selected
Config nodes. No arbitrary URI, XML payload or Exec operation is accepted by this
API.

| Settings | Accepted values and dependencies |
| --- | --- |
| Quality / feature deferrals | 0–30 / 0–365 days |
| Quality / feature deadlines | 0–30 days |
| Quality / feature grace periods | 0–7 days; corresponding deadline required |
| No automatic reboot before deadline/grace expiry | Explicit Boolean; corresponding deadline required |
| Active hours start / end | Paired hours 0–23, including overnight intervals |
| Active hours maximum | 8–18 hours; configured interval must fit, using 18 if omitted |
| Notification level | 0, 1 or 2; Windows default notifications, restart warnings only, or all suppressed |
| Driver exclusion | Explicit Boolean |

Per-setting build floors and servicing revisions follow Microsoft's
[Update Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-update).
The two no-auto-reboot settings require Windows 11 22H2. Feature grace periods
include published build-specific backports; every selected setting's own floor
and its dependencies must also pass. Notification suppression is an explicit
choice. A future editor must explain it and the fact that deadlines can cause
restarts outside active hours.

The existing `updates.manage` capability authorizes typed runs for scoped
operators and administrators. It does not grant arbitrary CSP access. Each step
is bound to the immutable update run, creator permission revision, scope and
timestamps. Before delivery and replay, the server decrypts the intent and
compares the stored CSP request with a newly compiled expected tree. An altered
or substituted command cannot borrow update authority, even if its ciphertext is
otherwise valid. Custom CSP APIs retain their administrator-only capability.

The caller supplies a stable request UUID and a name of at most 128 UTF-8 bytes.
Reusing the UUID is idempotent only for the same device, creator/revision, name,
mode, policy and lifetime. New policy intent requires a new UUID. Lifetimes use
the CSP range of one minute through seven days. A device's unresolved queue is
bounded at 256 commands. Admission reserves the actual number of generated steps:
three through seven for new runs, including preflight and configuration. An
idempotent retry does not reserve new queue slots.

## Preflight and platform catalog

The first stage queries current, authenticated device results for:

- `./DevDetail/SwV`: four-part OS version.
- `./Device/Vendor/MSFT/WindowsLicensing/Edition`: numeric Windows product SKU.
- `./DevDetail/Ext/Microsoft/OSPlatform`: product caption.
- `./DevDetail/Ext/Microsoft/ProcessorArchitecture`: architecture evidence.

These are device-reported facts with transport/command correlation, not hardware
attestation. Enrollment-time OS hints do not authorize a later configuration.
The licensing node provides an unambiguous numeric edition mapping, unlike a
free-form edition caption. Sources are
[DevDetail](https://learn.microsoft.com/en-us/windows/client-management/mdm/devdetail-csp),
[WindowsLicensing/Edition](https://learn.microsoft.com/en-us/windows/client-management/mdm/windowslicensing-csp#edition),
[GetProductInfo](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getproductinfo)
and [SYSTEM_INFO](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-system_info).

Known Pro, Enterprise, Education and IoT Enterprise variants are classified
explicitly. Server, unknown editions, unknown architectures and unknown future
builds do not pass preflight. The architecture catalog accepts x86, AMD64 and
ARM64 representations, with Windows 11 x86 and pre-1709 ARM64 rejected. Actual
Windows interoperability for these reported values still needs hardware evidence.

The release catalog was reviewed on **September 10, 2026** and recognizes Windows
10 releases through 22H2 and Windows 11 releases through 26H1. Known release does
not mean every policy is applicable. Preflight checks each selected setting.
IoT Enterprise on Windows 11 26H1 and unrecognized LTSC/build combinations are
rejected. The 26H1 entry is platform identification, not an instruction to upgrade
existing 24H2/25H2 devices to that release.

Support dates are separate from compatibility. The catalog distinguishes general
servicing from Enterprise/IoT LTSC dates and evaluates the published end date in
the Pacific calendar, with embedded timezone data. It reports ended standard
support separately; ESU entitlement remains `not_assessed`. An ended support date
does not prevent managing an otherwise compatible policy on a device that may
have separate extended servicing. Unknown future releases require a catalog
update. The reference date remains visible so it cannot masquerade as a live
provider lookup. Sources are
[Windows 10 release information](https://learn.microsoft.com/en-us/windows/release-health/release-information),
[Windows 11 release information](https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information),
[Windows 11 Home/Pro lifecycle](https://learn.microsoft.com/en-us/lifecycle/products/windows-11-home-and-pro)
and [Windows 11 Enterprise/Education lifecycle](https://learn.microsoft.com/en-us/lifecycle/products/windows-11-enterprise-and-education).

Configuration needs an acknowledged, compatible preflight result less than
15 minutes old. The database clock is checked before delivery/replay and again
after audit waits before commit. Stale or failed prerequisites retire dependent
undelivered work with a reason. A new run is required for fresh preflight.

## Read-back and outcome meaning

After configuration is acknowledged, separate Sequence batches query both
`Policy/Config/Update/...` and `Policy/Result/Update/...` for each selected setting.
Config identifies this source's value; Result identifies the effective value
after policy conflict resolution. This distinction follows the
[Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-configuration-service-provider).

New runs persist compiler version 2. Each verification batch contains at most
three settings, keeping each Config/Result pair together. All 13 supported fields
produce five read batches after one preflight and one Atomic configuration step.
The full synthetic apply/drift/removal exchanges fit the default 5,000-byte
response limit, including an exchange through real loopback TLS. Smaller client
budgets or unusually long protocol headers can still block delivery with
`message_size`; configuration is never silently split or changed to fit.

Only a completed configuration unlocks verification. A completed read batch with
404 or other failed Get statuses still permits later read-only batches, so the
run retains evidence for the remaining settings. Sent or unknown work keeps the
existing queue barrier. Until all batches complete, the run remains pending or
reports its actual terminal interruption, with completed setting outcomes still
available. Later matches cannot erase earlier drift or unreadable values.

Each setting carries `EvidenceReceivedAt`, the server's completion time for its
batch. This is neither a device timestamp nor a simultaneous snapshot. For
version-2 runs, the whole collection must finish less than 15 minutes after the
first verification delivery, with ordered delivery/receipt times. Otherwise a
result that would be verified, removed or drifted is `verification_stale`; an
existing failed/incomplete result remains failed/incomplete. All collected values
remain available. This bounds gaps between sessions without pretending to
provide continuous compliance. Reading historical evidence later does not age a
completed run out of its original result.

| Run outcome | Evidence |
| --- | --- |
| Preflight/configuration/verification pending | The named step still awaits delivery or complete device evidence |
| Unsupported | Current preflight evidence does not satisfy the catalog or selected policy |
| Verified | Every selected Config and Result value matches the explicit intent |
| Drifted | A configured/effective value differs, is absent, or remains configured after requested removal |
| Removed | Every selected Config node returns 404; effective values or absence are recorded separately |
| Verification failed/incomplete | Required values/statuses cannot establish the result |
| Verification stale | Version-2 observations exceed the collection window or lack ordered receipt/delivery times |
| Failed, unknown, canceled, expired or abandoned | The underlying step retains its corresponding transport/lifecycle evidence |

Removal does not claim that all effective policy disappeared. Another source or
a Windows default may still supply a Result value after this source's Config
node is absent. Typed verification interprets those individual Get statuses;
the generic CSP group's failed phase for a 404 does not turn a proven removal
into a fabricated configuration success.

Asynchronous or otherwise unknown mutation outcomes retain the CSP queue barrier.
No automatic mutation retry follows uncertainty. A final status can still arrive
within an active session; cross-session asynchronous reconciliation remains
future work. `CancelUpdateRun` stops undelivered remaining stages atomically. It
rejects a currently sent/unknown stage and does not remove already applied
settings; removal requires an explicit removal run.

All request/result data remains protected. `UpdateRunDetails` and paginated
`UpdateRuns` authenticate immutable intent and each generated command/result,
check live scope/capability and commit read audit before returning values. Pages
contain at most 100 runs, with offset at most 100,000. Views must escape names,
captions and device data. These methods are not public HTTP routes yet.

## Persistence and verification

Migration 006 adds immutable encrypted update runs and append-only run audit.
Composite foreign keys bind each CSP step to its run's device, scope, creator,
permission revision and exact creation/expiry timestamps. Step numbers preserve
preflight/configuration/verification order for the common creation timestamp.
Old custom CSP ciphertext keeps its original purpose and authority across upgrade.
Migration 007 widens the step constraint from 0–2 to 0–6 without rewriting any
run, request or result. Version-1 runs retain their original three command trees
and result semantics. Retrying their original intent returns the same run after
upgrade; it does not change the compiler version or repartition queued/sent work.
Every version-2 batch is recompiled from protected intent and its exact step
number before delivery, replay and protected reads. Swapping valid read trees
between batches fails this binding just as substituting an arbitrary CSP does.

Synthetic tests cover ranges/dependencies, explicit zero/false, separate apply
and verification trees, removal, current platform/SKU/servicing evidence, support
dates, timezone boundaries and ESU separation. PostgreSQL tests exercise operator
authority, multi-stage delivery, restart/replay, effective-value drift, removal,
incompatible targets, scope/idempotency, cancellation/audit rollback, permission
revision changes, substituted commands and upgrade of an existing CSP delivery.
Additional tests cover all 13 fields at 5,000 bytes, partial evidence, early
404/500 statuses followed by later batches, exact queue capacity, cancellation
with active/blocked reads, collection-window boundaries, reassigned read trees,
and queued/sent legacy runs across migration. A real loopback TLS exchange
advances all seven steps on resumed connections and verifies the full policy.

The batching extension's local PostgreSQL 17/race suite passes in **69.105 seconds**, at **85.5%**
package statement coverage. The extended typed policy fuzz target, including both
compiler versions and exact batch reassembly, passes **23,726 executions** in its
30-second local run. Vet and formatting checks pass.
CI includes the target, PostgreSQL/race tests, native Windows portable tests
and both platform builds. Both complete workflows pass for batching commit `293f062`
([push](https://github.com/the-luap/openuem-console/actions/runs/34416153591),
[pull request](https://github.com/the-luap/openuem-console/actions/runs/34416160052)).

```sh
go test -race -count=1 -timeout=3m ./internal/mdm/windows
go test -run '^$' -fuzz='^FuzzUpdatePolicy$' -fuzztime=30s -parallel=2 ./internal/mdm/windows
```

Use the [reserved PostgreSQL fixture](native-windows-mdm.md#scoped-enrollment-credentials).
No fixture installs a policy/certificate, changes Windows settings or executes a
host command. [Scheduled assignments](native-windows-update-schedules.md) and
[listener/worker registration](native-windows-operations.md) are now implemented.
[Immediate site-group selection](native-windows-update-groups.md) is now available
for ring assignments. Remaining work includes scheduled group evaluation,
pilot promotion gates, outgoing chunking
for large trees, update console workflows,
continuous compliance and async reconciliation, actual update/restart evidence,
renewal/unenrollment, provider integrations and physical Windows acceptance.

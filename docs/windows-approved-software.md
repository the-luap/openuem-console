# Approved Windows software

The organization catalog now records immutable Windows WinGet, custom MSI and
custom EXE approvals alongside [managed Mac packages](apple-managed-applications.md).
Open **Approved software → Approve a Windows package**, choose the package type,
enter its exact requirements and confirm the approval. Organization software
managers can publish or permanently withdraw revisions. Readers can search the
catalog and inspect safe metadata from their authorized organization/site.

This milestone records approval intent. [Windows device requests](windows-software-requests.md)
can now be prepared with an immutable revision, scoped individual identity and a
short deadline. Supported MSI/EXE requests now have a separate, explicit review
and dispatch step with fresh authorization and verified result history. Approval does not verify
an installer, install software or establish an observed device state. The existing
upstream WinGet deployment workflow remains separate.

## Approval requirements

Every Windows revision declares a package identifier, exact package version,
architecture (`x86_64`, `arm64` or `x86`), minimum Windows kernel/build version and
an exact installed-state detection rule. A package version and its reported
installed version can differ, so both are recorded explicitly.

| Package type | Source and installation intent | Removal intent |
| --- | --- | --- |
| WinGet | Fixed `winget` source, exact identifier/version and architecture; custom sources, arguments and hashes are rejected | Exact WinGet identifier/version |
| MSI | HTTPS `.msi` URL, lowercase SHA-256 and bounded public `NAME=value` properties; machine scope, quiet operation and suppressed automatic restart are reserved for the adapter | Exact uppercase braced MSI product code |
| EXE | HTTPS `.exe` URL, lowercase SHA-256 and one literal installer argument per line | Separate HTTPS `.exe` URL, lowercase SHA-256 and one literal removal argument per line |

WinGet approval records a source coordinate. It does not pin a resolved manifest
or installer digest. Immutable source resolution and binary verification remain
delivery prerequisites. Custom package hashes are supplied by the publisher;
the console does not fetch those URLs or independently inspect their signatures.
The [source snapshot reader](windows-winget-resolution.md) now retains a fixed
Microsoft community commit and exact manifest bytes, with bounded HTTPS and
strict binding checks. Exact machine MSI/WiX translation is implemented separately;
immutable approval linkage and console review still need integration before a
WinGet coordinate can execute. Other installer kinds remain unsupported by that
new translation boundary.

Arguments preserve spaces and punctuation without interpreting shell quoting.
Line endings separate arguments; a final line ending terminates the last argument.
MSI properties require unique uppercase names. Properties that alter installation
scope, restart behavior, transforms or the installation action are rejected.
Property values containing double quotes are rejected to match the authenticated
native MSI adapter; approved values are never silently escaped into another value.
There are at most 32 arguments per operation and 32 MSI properties, with 2,048-byte
values and a 32 KiB total encrypted definition. HTTPS sources reject embedded
user/password authority, fragments and invalid ports.

Detection requires either an exact machine MSI product code and reported version,
or an exact subkey and `DisplayVersion` in the 32-bit or 64-bit HKLM uninstall
registration. Arbitrary registry paths and conflicting detection fields are
rejected. Recording this rule does not execute it. An installer acknowledgement,
exit code or a similarly named inventory entry cannot establish successful
installation.

MSI intent fixes success to `0` and restart-required to `3010`; WinGet intent uses
`0` for command success. EXE publishers declare disjoint success/restart-required
code sets, each containing at most 16 unsigned 32-bit codes, with `0` included in
success. These declarations do not establish completed restart or detection.
The native adapter preserves command results and separately verifies the requested
state; catalog approval alone does not invoke it.

## Authorization, privacy and persistence

Publication rechecks current organization-wide `ManageSoftware` authority inside
the same transaction as the immutable revision and audit event. Each form carries
a request UUID. Concurrent retries by the same actor with identical intent return
the original revision; changed intent or another actor conflicts. Revoked
authority also prevents replay. Retrying an approval after withdrawal returns the
withdrawn revision, without restoring approval or creating another audit event.

Source URLs, installer arguments, removal arguments and MSI property values are
encrypted together with a purpose bound to the organization and revision. Page
models contain only detection requirements, result codes, digests, argument
counts and property names. Sensitive values do not enter the catalog, detail page
or audit metadata. Mutations require body-only, unambiguous form fields, CSRF and
explicit confirmation; errors do not echo submitted credentials.

Catalog and detail reads recheck current `ReadSoftware` authority and commit a
read audit before returning data. Read audits preserve the requested site scope.
Search treats percent signs, underscores and backslashes literally. Queries use
at most 101 rows to return a 100-revision page and a tenant-bound continuation;
platform and search filters survive pagination. Withdrawal remains visible in
history. It cannot undo an already delivered installer or remove an application.

Migration 037 extends the existing catalog, retains Mac artifacts and their
immutable history, and checks that each version's adapter matches its package
platform. Mac delivery and ADE prerequisite selection continue accepting only
Mac PKG revisions. Windows publication and withdrawal use
`software.windows.version.publish` and `software.windows.version.withdraw`;
catalog reads use `software.catalog.read`. These records use the existing shared
catalog audit storage, exposed under the audit viewer's Apple source.

## Validation and remaining delivery work

PostgreSQL/race tests cover all three approval types, encryption binding,
concurrent idempotent publication, immutable revisions, permanent withdrawal,
audit failure rollback, revoked rights, literal filtered pagination over 103
Windows revisions interleaved with Mac revisions and foreign cursors. Mac managed
applications and ADE/Platform SSO prerequisite regressions use the expanded
catalog projection. Handler tests exercise real scoped routes, role restrictions,
strict forms, CSRF, redacted details, filtering and withdrawal.

The browser suite includes 27 Windows catalog cases within 270 total cases at
390/768/1440 pixels: all three approval/detail forms, reader and withdrawn states,
keyboard confirmation, exact argument preservation, filtered pagination and
horizontal overflow. These are owned synthetic fixtures, with intercepted form
submissions and no package downloads or endpoint changes.

The agent now has a separate
[exact machine observation helper](https://github.com/the-luap/openuem-agent/blob/7a27844821659ebb44955a366df45bd010d788f3/docs/windows-software-observation.md).
It reads the declared MSI product or exact registry view/key in a bounded local
process. Its [Linux/macOS/Windows CI](https://github.com/the-luap/openuem-agent/actions/runs/34571170520)
passes, including three mandatory native Windows observation fixtures. This helper
provides the native observation boundary used by the new authenticated executor.
The [individual agent service](https://github.com/the-luap/openuem-agent/blob/b6a5a1fb8b3592054b343ae0a4a3cccc00f6ef57/docs/windows-software-delivery.md)
now joins protected current-generation recipient registration, immutable attempt
admission, HTTPS/hash/Authenticode staging, native compatibility checks, MSI/EXE
process ownership and signed durable outcomes. An approved exit requires exact
native state; restart-required and uncertain outcomes do not become completion.

Device preparation is a separate, audited intent record with explicit cancellation
and expiry. It does not invoke this helper or send a package command. A separate
confirmed dispatch creates an authenticated task and closes its preparation in
the same audited transaction. Existing preparations never execute automatically.

An explicit [read-only software check](windows-software-requests.md#read-only-reconciliation-after-uncertainty-or-a-required-restart)
now handles retained uncertainty and restart-required operations. Signed evidence
of a later kernel boot and a definite native observation can release the original
reservation while preserving its original outcome. Unknown state, missing evidence
or the same boot cannot release it. This path has separate review, cancellation,
verified history, protected native receipt recovery and current-certificate proof.

WIN-01 remains in progress. Required next work includes immutable WinGet manifest
resolution and physical install/remove, offline, restart and hibernate acceptance.
Synthetic boot evidence is not physical acceptance. The legacy package subjects must not be enabled for individual agents
as a shortcut. See the agent's
[bounded Windows execution implementation](https://github.com/the-luap/openuem-agent/blob/b87cbce5c5ff6990f9db98ad808b5a8fcc122eae/docs/windows-package-execution.md)
for the existing execution foundation and its limits.

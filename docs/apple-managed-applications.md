# Managed Mac applications

Implementation is in progress. The native backend now has an approved artifact
catalog and a device-channel installation/removal lifecycle. Console approval,
assignment and paginated history workflows are implemented, with their full CI
and browser checks in progress. The complete acceptance matrix, ADE application
prerequisites and Platform SSO integration are still being implemented. This is not yet a completed software
distribution or self-service feature.

## Approved artifacts

The versioned catalog is separate from the upstream WinGet/Homebrew search index.
Package identity includes organization, platform and application identifier.
Every approval records an immutable artifact revision: display name, exact bundle
version, architecture, minimum OS, SHA-256, publisher and publication time.
The native adapter accepts HTTPS PKG sources for macOS 11 and later. For macOS
11–13, the publisher must identify a package containing one signed application
installed in `/Applications`. That declaration is an operator assertion, not a
server-side package inspection or signature verification.

Download URLs can contain signed credentials. They are encrypted with a tenant-
and-version-bound purpose, omitted from page models, and embedded in encrypted
native commands. The server does not fetch arbitrary package URLs. Inline Apple
manifests carry the approved SHA-256, bundle identifier and exact bundle version.
New download credentials require a newly approved revision; existing revisions
cannot silently change their source or artifact. Withdrawal is permanent and
prevents future installation delivery. It does not recall an already sent native
installer or remove an installed app.

Catalog approval/withdrawal requires organization-wide software management rights.
Assignment rights permit operators to select approved revisions within their
device scope. The store rechecks authorization in each transaction and commits
the corresponding audit event atomically. The first adapter is native macOS;
the common catalog still needs its Windows, Homebrew and Apps & Books adapters.

## Native lifecycle

The backend uses `InstallEnterpriseApplication` with `InstallAsManaged`, followed
by distinct `ManagedApplicationList` and filtered `InstalledApplicationList`
queries. Installation acknowledgement means that macOS accepted the command,
not that the app is installed. Verification requires post-acknowledgement reports
of managed status and the exact expected bundle version. Short display versions,
missing Mac identifiers, ambiguous duplicate bundles, pending downloads and stale
queries do not satisfy that requirement. Filtered observations do not replace the
device's complete software inventory.

Removal is a separate operation using `RemoveApplication`. It requires a current
managed-app observation. The backend verifies absence in both managed and installed
app observations after acceptance. Removing an app also removes its app data;
this is not a general uninstaller for all files, services or scripts placed by an
arbitrary package. Explicit takeover of a user-installed app and removal when MDM
is removed are separate installation options.

An unanswered sent mutation is not automatically replayed. An explicit `NotNow`
permits deferred delivery of the same command. Expired sent commands retain an
unknown outcome and block another mutation. An exact late response can resolve
that state. Acknowledged operations continue to require installation observations.
After one day without verification, an accepted operation becomes uncertain even
when the Mac sends no observations. Status queries continue; new mutations remain
blocked. Fresh reports can subsequently establish the requested state.
Old terminal replies cannot reverse a newer operation. Queued/deferred operations
can be cancelled even when device inventory is stale; cancellation does not claim that an accepted installer stopped.
Checkout stops management and preserves attempt history and uncertain outcomes.

## Console workflows

Open **Approved software** from device management to publish or inspect revisions.
Publishing and permanent withdrawal are organization-level actions; scoped
operators can search by name or serial number, select a compatible Mac and request
an approved revision. Device selection reads at most 101 small metadata records
per page and escapes search wildcards; it does not load full device inventories. Publishing,
installation and removal require explicit confirmation and a valid CSRF token.
The server rejects duplicate form fields, query-based mutation input and unapproved
command or download parameters. Download credentials never appear on read pages.

A Mac's **Managed applications** page exposes observed state, explicit status
queries, cancellation before confirmed execution and managed-app removal when
eligible. Its **Operation history** retains each attempt's original revision,
actor, options, timestamps and observations, independently of the latest state.
Read-only users can inspect these records without mutation controls. Retired
enrollments retain history. Catalog and history pages use scoped bounded cursors.

## Validation status

Local protocol tests cover package validation, pinned manifests, management
options, credential exclusion and conservative observation parsing. URL fuzzing
completed 183,084 inputs. All 26 actual Apple migrations and all 59 SQL statements
in the application backend and console reads passed an isolated PostgreSQL migration and
parameter-inference check. These checks roll back their temporary schema.

PostgreSQL integration tests exercise catalog authorization, immutable approvals,
withdrawal, pagination, failed-audit rollback, installation/observation/removal,
late responses, concurrent requests, scope and checkout. The initial backend commit `b0c90af` passed both complete CI runs, including Linux
and Windows builds, native Windows protocol checks and PostgreSQL/race tests.
The subsequent console/history/timeout changes add route authorization, CSRF,
stale-inventory cancellation, read isolation and missing-report recovery tests;
their complete CI is pending. The initial console commit `7777f5a` passed
39 synthetic browser checks across 13 states at 390, 768 and 1440 pixels, including
keyboard confirmation, scoped reader controls and horizontal overflow. The
bounded device search at `f48f2c0` also passed all 39 browser checks, including GET
search submission and cursor navigation. The `7777f5a` PostgreSQL native Apple
suite passed in 499.212 seconds; its route test identified the shared renderer
weakening endpoint `no-store` to `no-cache`. The renderer now preserves explicit
cache policies, with a reproducing regression test covering all eight rendering
helpers. Complete CI for that fix and the added negative tests is still pending. Actual signed-package
installation on an explicitly authorized Mac remains open.
No package is downloaded or executed by these synthetic tests.

## Platform references

- [Install Enterprise Application](https://github.com/apple/device-management/blob/release/mdm/commands/application.install.enterprise.yaml)
- [Managed Application List](https://github.com/apple/device-management/blob/release/mdm/commands/application.managed.list.yaml)
- [Installed Application List](https://github.com/apple/device-management/blob/release/mdm/commands/application.installed.list.yaml)
- [Remove Application](https://github.com/apple/device-management/blob/release/mdm/commands/application.remove.yaml)
- [Manifest asset digests](https://developer.apple.com/documentation/devicemanagement/manifesturl/itemsitem/assetsitem)
- [Unattended Platform SSO](https://developer.apple.com/documentation/devicemanagement/implementing-platform-sso-for-unattended-device-enrollment)

Declarative management is the preferred subsequent macOS 26 path. A Mac custom
package needs a separate package declaration and app management by composed
identifier; `AppManaged.ManifestURL` is not supported on macOS. Apps & Books
licensing, DDM configuration/status composition, provider registration and verified
ADE setup prerequisites remain part of the original roadmap.

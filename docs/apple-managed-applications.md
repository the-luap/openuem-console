# Managed Mac applications

Native macOS PKG distribution includes an approved artifact catalog, scoped
installation/removal, device observations and console operation history.
Automated protocol, database, route and browser checks pass. See the separate
[ADE application prerequisites](apple-ade-required-applications.md) and
[cross-enrollment operation recovery](apple-application-reenrollment.md) milestones.
Unattended Platform SSO integration, declarative app management, unified platform
adapters, Apps & Books, self-service and physical-device acceptance remain roadmap
work.

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
can be cancelled even when device inventory is stale; cancellation does not claim
that an accepted installer stopped.
Checkout stops management and preserves attempt history and uncertain outcomes.
The same package remains blocked across replacement enrollments of that Mac.
An organization administrator can record explicit
[stopping evidence](apple-application-reenrollment.md) for a retired attempt;
the receipt does not rewrite its unknown outcome or prove installation success.

## Console workflows

Open **Approved software** from device management to publish or inspect revisions.
Publishing and permanent withdrawal are organization-level actions; scoped
operators can search by name or serial number, select a compatible Mac and request
an approved revision. Device selection reads at most 101 small metadata records
per page and escapes search wildcards; it does not load full device inventories.
Publishing, installation and removal require explicit confirmation and a valid CSRF token.
The server rejects duplicate form fields, query-based mutation input and unapproved
command or download parameters. Download credentials never appear on read pages.

A Mac's **Managed applications** page exposes observed state, explicit status
queries, cancellation before confirmed execution and managed-app removal when
eligible. Its **Operation history** retains each attempt's original revision,
actor, options, timestamps and observations, independently of the latest state.
Read-only users can inspect these records without mutation controls. Retired
enrollments retain history. Catalog and history pages use scoped bounded cursors.

## Validation status

Both complete CI runs for `3bfc0c9` passed all four jobs:
[push validation](https://github.com/the-luap/openuem-console/actions/runs/34319452738)
and [pull request validation](https://github.com/the-luap/openuem-console/actions/runs/34319456432).
They include Linux and Windows builds, native Windows protocol checks, PostgreSQL
and race tests, scoped console routes, response privacy, gateway/authentication,
existing deployment/SMTP models and desktop service regressions. The native Apple
suite completed in 488.929 seconds and console route tests in 10.703 seconds in
the pull request run.

Integration cases cover immutable approvals, withdrawal before delivery,
transactional authorization and audit rollback, concurrent requests, exact-version
verification, removal, deferred delivery, late responses, missing-report timeout
and recovery, malformed response redaction, stale-inventory cancellation, scoped
readers, strict mutation forms and checkout. Pagination tests include 103 attempts
with equal historical timestamps and 102 matching devices, plus literal wildcard
searches and site isolation. All eight shared HTML render helpers preserve an
endpoint's explicit cache policy, including `no-store`.

Local protocol tests cover pinned manifests, management options, credential
exclusion and conservative observation parsing. URL fuzzing completed 183,084
inputs. All 26 actual Apple migrations and all 59 application SQL statements
passed an isolated PostgreSQL migration and parameter-inference check; the
temporary schema was rolled back.

Browser acceptance passed 39 checks across 13 states at 390, 768 and 1440 pixels,
including keyboard confirmation, GET device search, cursor links, reader controls,
unknown outcomes and horizontal overflow. Screenshots were inspected. The final
browser fixtures came from `f48f2c0`; templates and styles were unchanged through
`3bfc0c9`, whose route tests also cover the subsequent HTTP cache-policy fix.

Actual signed-package installation on an explicitly authorized Mac remains open.
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
licensing, DDM configuration/status composition, provider registration and the
additional unattended Platform SSO prerequisites remain part of the original
roadmap.

# WinGet source review and immutable installer approval

Open an approved WinGet revision and select **WinGet installers**. An organization
software manager can confirm **Save installer source**, review compatible machine
MSI or Burn choices and confirm **Approve this installer revision**. The resulting revision
has its own approval, binary digest and source evidence link. Select its
**Windows device requests** to prepare and explicitly dispatch installation or
removal through the existing individual-agent protocol.

Saving a source and approving an installer do not create device requests or installer
tasks. An unresolved WinGet coordinate remains non-executable. This integration
supports the exact machine MSI/WiX and Burn subsets described below; unsupported installer
kinds or behavior do not become executable by selecting a package name.

## Fixed Microsoft community source

The source reader in `internal/software/winget` is the first boundary for resolving
an approved exact WinGet coordinate. It retrieves the Microsoft community
repository's branch reference once, then reads the exact identifier/version path
at that full commit. Its retained snapshot binds the coordinate, commit, canonical
repository path, original YAML bytes and their SHA-256. Later inspection verifies
the same bytes without contacting a mutable source. This is an HTTPS source
assertion, not verification of a signed Git commit or of an installer binary.

Only `microsoft/winget-pkgs` on `api.github.com` and
`raw.githubusercontent.com` is addressed. Coordinates cannot supply a URL, branch,
repository or traversal component. Reserved URL characters in valid coordinates
are escaped as path data. The reader supplies no authentication token and rejects
redirects. It tries the singleton filename only when the installer filename
returns 404, using the same pinned commit. Invalid content, rate limits, timeouts,
authorization errors and redirects cannot cause fallback to a different source.

Each operation has a total context deadline; its private TLS transport also limits
connection, handshake, response-header and idle-connection lifetimes. API bodies
are limited to 32 KiB and manifests to 512 KiB after decompression. Both declared
and streamed response sizes are bounded. Errors do not expose response content,
installer URLs or redirect locations. The caller owns and closes the source's
idle connections. No installer URL in the manifest is fetched by this component.

Snapshot inspection rejects changed binding fields, duplicate YAML/JSON keys,
extra documents, aliases, anchors, merge keys, custom tags and excessive node,
depth or installer counts. Package identifier/version spelling is exact;
numeric-looking YAML versions retain their original lexeme. Known published
manifest schema versions are recognized explicitly. Every original field remains
available to subsequent inspection, including unknown behavior. Parsing a
snapshot does not validate a complete manifest schema, select an installer,
translate switches or approve ignoring an unsupported field.

The source protocol and parser pass owned HTTPS/race fixtures, cancellation and
redirection checks, exact persistence tests and 530,700 local fuzz inputs. A
separate read-only probe fetched `GoLang.Go` version `1.26.1` from commit
`5630670fa24b40b74bc32038abd26e677ad4b71c` and from a separately resolved source
head; both retained the same 1,917 bytes and three installer entries. The probe
neither downloaded a package nor installed software. Regular tests use synthetic
manifests and an owned TLS server; CI does not depend on the public source.

## Exact machine MSI translation

The separate `MSIPlan` adapter validates an explicitly selected MSI/WiX entry
against a reviewed AMD64 or ARM64 target. Machine scope must be explicit. The
manifest's product code must match the exact native detection rule, and any
declared Apps & Features display version must match its reviewed installed version.
The resulting minimum OS cannot weaken either the manifest or target requirement.
Installation pins the HTTPS MSI artifact and normalized SHA-256; removal uses only
the exact MSI product code. Both produce the existing validated individual-agent
plan, with `0` success and `3010` restart-required semantics.

Root defaults and selected installer fields are considered together. Installer
switch maps merge by key; a selected silent switch cannot erase inherited custom
behavior. An empty dependency or return-code declaration cannot bypass root
requirements. The adapter accepts only its supported quiet/no-restart switches
and the already enforced machine property. Opt-in interactive, progress, custom
location, log and repair switches are not invoked. Unsupported installer kinds,
dependencies, custom actions/codes, required location, market restrictions,
agreements and unknown behavior are rejected before any executable plan is returned.
This subset does not claim complete WinGet manifest or EXE support.

The combined source/translation race suite passes in 1.742 seconds. Translation
tests cover AMD64/ARM64 installation and removal, exact detection and display
versions, stronger OS requirements, per-key switch inheritance, empty dependency
overrides and unsupported behavior. A separate translation fuzz run passes
569,203 inputs; focused vet and Windows compilation also pass.
The previously captured Go manifest also produces valid AMD64/ARM64 installation
and removal plans against its exact product codes. This is translation evidence;
the probe downloads or executes no installer.

## Saved review, approval and history

Migration `041_windows_winget_sources.sql` adds immutable source captures and
approval links. Existing revisions and device preparations remain unchanged.
The source envelope is encrypted with an organization/capture-specific purpose
and authenticates its format, original revision, package, actor, timestamps and
complete snapshot. Reads recompute all source bindings and verify a derived
revision against the retained translated plan and encrypted approval definition.
Update, delete and truncate guards preserve source and approval history.

Capture requires current organization-wide `ReadSoftware` and `ManageSoftware`.
The request audit commits before the HTTPS fetch. No transaction lock spans the
network operation. Current rights and the original approval are checked again
after fetching, before encrypted persistence and its capture audit commit
together. Concurrent exact retries retain the first saved source and never
replace it with a newer upstream commit. An existing capture returns without
another network fetch; another actor or original revision cannot reuse its ID.

The capture's 15-minute deadline comes from the database clock. Only its creator
with current organization rights receives approval choices. Each choice binds
the original exact architecture and detection rule, selected installer index,
manifest digest/commit, translated plan digest, actor and deadline. Confirmation
revalidates those fields and atomically publishes a separate installer revision, its
source link and audit events. A final deadline check prevents a transaction
delayed during auditing from committing an expired approval. Exact approval
retries return the same revision; another request ID cannot reuse the source or
reattribute an existing ordinary catalog approval.

The original WinGet coordinate is retained. Original and derived withdrawals are
independent: withdrawal of the coordinate prevents new captures/approvals, while
withdrawal of the derived installer prevents its future installation. Neither erases
history. Historical retries preserve withdrawal and never restore approval.
Expired, incompatible and withdrawn source reviews expose no approval forms.

Authorized organization/site readers can inspect source evidence and history,
including the originating source from an MSI or Burn detail page. History is bounded to
50 entries per page with an original-revision/organization-bound cursor. Read
audit must commit before data is returned. Views show only repository provenance,
digests, requirements and the compatible download host; installer paths, query
tokens, manifest bodies and switches stay out of page models and audit metadata.
Capture/approval forms are limited to 8 KiB, require CSRF and explicit confirmation,
and reject duplicate, query-supplied or extra fields.

Owned PostgreSQL/race tests cover concurrent capture and approval, revoked rights
after fetch, audit rollback, expiry during approval, immutable authenticated
history, tampered public metadata, scoped pagination and migration from existing
approvals/preparations. Installation and removal tests decrypt a real dispatched
individual-agent task and compare its digest with the exact source-derived plan.
The complete Apple model race suite passes in 435.349 seconds. The final
capture-ID conflict refinement passes the targeted catalog/source regression in
18.432 seconds and the full handler suite; the source/MSI
race suite passes in 1.846 seconds. Full handler tests and rendered-view race tests
pass. All 318 browser cases pass, including 48 source cases for ownership,
permission, expiry, incompatibility, approval, evidence, keyboard confirmation
and 390/768/1440-pixel layouts.

Binary staging still enforces HTTPS, content digest and native trust checks.
These synthetic tests do not download or execute a public installer. Further
WinGet installer formats and physical install/remove, offline, restart and
hibernate acceptance remain open. WIN-01 and the complete roadmap remain in progress.

## Burn EXE translation foundation

The separate `BurnPlan` adapter validates source-declared machine Burn bundles
against an explicitly reviewed AMD64/ARM64 target, exact braced bundle identifier,
64-bit machine uninstall-registry view and displayed version. It emits explicit
`windows-burn` installation and removal plans using the same HTTPS EXE digest.
Their signed kind cannot be substituted with generic EXE intent. Detection remains `uninstall-key`;
the bundle identifier is never substituted for an MSI product code. Removal uses
the pinned executable's uninstall action, without reading or invoking a mutable
machine `UninstallString`.

The shared installer checks retain root requirements and per-key switch
inheritance. Burn accepts its known quiet/no-restart defaults and only matching
overrides; custom actions, properties, dependencies, multiple or nested MSI ARP
identities, manifest `uninstallPrevious` transitions and unknown behavior are rejected.
Both MSI and Burn require literal ASCII switches with space/tab separators.
Unicode case folding, Unicode whitespace and embedded line breaks cannot turn
an unsupported manifest token into an accepted quiet flag.

Console review now offers Burn only for a source-declared `burn` entry matching
the separately approved native architecture, canonical bundle code, exact display
version and 64-bit machine registration. GUID-shaped metadata cannot promote an
MSI or generic EXE manifest to Burn. Public options retain the original index,
explicit adapter kind, digest and download host, without the artifact path or
query. The selection hash binds the complete translated plan.

Migration `042_windows_burn_sources.sql` adds explicit Burn revisions and extends
the existing source and preparation guards. It does not rewrite old approvals or
preparations. The derived encrypted definition pins the same URL and SHA-256 for
both operations, with exact quiet/no-restart and uninstall arguments. Catalog
reads revalidate the retained source against this immutable definition. Direct
HTTP publication of a Burn revision is rejected; it requires saved-source review.

Dispatch requires the current device-signed Burn recipient capability and verified
source provenance. A replaced recipient invalidates an earlier review, including
when support is later restored. Missing or corrupted source history prevents
dispatch. Withdrawing the original coordinate preserves an independently approved
Burn revision and its history. The native agent verifies the retained binary's
embedded bundle code, exact version, machine scope and native architecture in
addition to its approved hash and Authenticode policy. Emulated bootstrappers
remain unsupported, even when their payloads target the native architecture.
Physical endpoint acceptance remains separate.

The agent's separate
[Burn metadata readers and preflight](https://github.com/the-luap/openuem-agent/blob/767bf1a9ec62456807bc783c2cd60db9dbc6f30e/docs/windows-burn-inspection.md)
locate a version-2 `.wixburn` bundle code and bounded UX cabinet without
extracting or executing its contents. At most seven reads and 4,512 requested
bytes inspect standard x86/AMD64/ARM64 PE layouts, overlapping/truncated section
and certificate ranges, exact cabinet length and bounded container declarations.
The bootstrapper architecture is metadata, not authorization to use emulation.
WiX's 48-byte virtual prefix and appended raw container table are preserved.
The corrected reader passes its local race suite in 1.415 seconds and 151,135
fuzz inputs in 16.610 seconds, following the initial 5,276,614-input fuzz run.
The existing Windows software race suite, focused vet, full Linux ARM64 build
and tagged Windows test compilation pass. A separate Windows CI fixture builds
owned bundles with WiX/Bal `4.0.6` and independently extracts their manifests to
compare the header code with the version-specific `Registration/@Id` field.
All three native architecture fixtures pass at agent commit
`383c6fd1d1e31564ede725eac00317d94423959f`. Neither generated bundles nor payloads
are executed.

The separate `ReadRegistration` path now checks every bounded CAB directory entry
and block range, then decodes only the first manifest into memory using the fixed
Windows system FDI API. It binds the header code to the manifest's registration,
exact displayed version, fixed machine/user scope and architecture-consistent
registry view. The known `Id`/`PerMachine` and `Code`/`Scope` shapes cannot be mixed;
flexible scope, duplicate identities, directives and external entities fail.
Archive names never become filesystem paths, and no payload is written or run.
Native callbacks have explicit read, allocation, output and reuse limits. Complete
manifest output must end with the deliberate FDI abort and closed resources;
ordinary I/O errors and partial output cannot become registration evidence.

The final local race suite passes in 1.588 seconds; CAB and XML fuzzing pass
3,412,453 and 629,931 inputs. Native Windows race tests pass in 1.472 seconds,
and the complete reader passes all three generated architectures and changed
header checks in 15.10 seconds. All agent CI jobs pass at
`bf1f80adf9960387f82e414d60263b7054816c23`. These native runtime tests use an AMD64
Windows process; later native ARM64 results are recorded below. Physical endpoint
acceptance remains open.
The bounded preflight subprocess now requires this proof for explicit Burn plans,
comparing exact machine identity, displayed version and native 64-bit registry
view. The retained stage and its approved digest are verified before and after
inspection; parent cancellation and a child exit timer bound FDI work to ten
seconds. Generic EXE inspection cannot silently select this path. The native
helper fixture passes at `767bf1a9ec62456807bc783c2cd60db9dbc6f30e`, including machine
and user scope, foreign architecture, x86, wrong identity/version/digest and closure.
The subsequent complete agent CI run passes at
`68876c30fd6301327b5d3f2e45c82a54c5ce0311`.

The shared protocol at `a4fe1e816a3b7feb051817728536fcd857c97aa1` requires Burn
support in the device-signed recipient registration before sealing a task. A
challenge alone grants no capability. Migration `014` preserves old recipients
at zero, and their JSON wire encoding remains unchanged. Capability changes issue
a new recipient ID, cancel pending old work and preserve delivered uncertainty;
audit failures roll back the complete transition. Full local module/registry race
tests and 814,083 wire-fuzz inputs pass. The agent now negotiates the private
profile hint through a matching device signature before admitting Burn; its
process builder cannot fall through to MSI.

The agent now maps explicit Burn plans directly to the retained EXE process
boundary after native preflight. Owned native fixtures build unique bundles with
pinned WiX/Bal `4.0.6`, fetch their own bytes through a private test HTTPS server,
and bypass Authenticode only through a test seam for these generated unsigned
artifacts. A registry-only MSI proves actual bundle and payload installation and
removal, exact version checks, no-op behavior and repeated use of the same artifact.
Additional bundles carry waiting owned processes; cancellation and an unfinished
child must join those processes and retain an uncertain result without an exit
code. No public installer, existing product identity or managed endpoint is used.

The actual Burn branch passes native race tests at
`39eb6c94d3436f00a24069dc2572be003284910f`: install/remove in 21.26 seconds,
cancellation in 12.88 seconds and an unfinished child in 11.27 seconds.
Portable agent recovery race tests pass in 4.066 seconds. They preserve a signed
restart result byte-for-byte, retry a lost historical receipt without another
installation, and bind later-boot install/removal observations to the original
exact 64-bit registration. These protocol fixtures do not simulate a physical
reboot. Native ARM64 installation/removal, cancellation and unfinished-child
checks pass in 7.66/6.81/6.66 seconds at agent `a1096ed`; all seven jobs pass
([CI run](https://github.com/the-luap/openuem-agent/actions/runs/34628087765)).
The generated execution bundles disable host restore points after diagnostics
identified remaining `SrTasks.exe` and `conhost.exe` processes in a default-restore
fixture. Production child joining and uncertainty remain unchanged. Physical
endpoint acceptance remains open.

The updated source adapter race suite passes in 1.781 seconds and another 368,767
fuzz inputs pass in 21.498 seconds. It rejects 32-bit registry views for both native
architectures. The existing catalog/source/dispatch and migration race suite
passes against isolated PostgreSQL in 95.106 seconds. Existing MSI source approval
and dispatch retain their separate immutable revision contract.

The combined source/MSI/Burn race suite passes in 1.799 seconds. The final Burn
and MSI fuzz runs pass 242,390 and 233,586 inputs respectively. Tests cover both
operations, both native architectures, both explicitly reviewed registry views,
same-artifact removal, display-version/OS requirements, inherited switches and
unsupported actions, identities and separators. The existing source/catalog
PostgreSQL race suite passes in 17.265 seconds after extracting shared checks;
full handler tests, focused vet and Windows compilation also pass. No Burn
installer is downloaded or executed by these tests.

The source-level contract follows the pinned
[WinGet known-switch implementation](https://github.com/microsoft/winget-cli/blob/c17eadbcacf2f5244b13de0d563d921c33ac4af6/src/AppInstallerCommonCore/Manifest/ManifestCommon.cpp),
the pinned [Burn action parser](https://github.com/wixtoolset/wix/blob/77aa9818ad37637f961afe143be88bdc38a3f350/src/burn/engine/core.cpp)
and Microsoft's [.NET installer operation documentation](https://learn.microsoft.com/en-us/dotnet/core/install/windows#command-line-options).
The latter documents same-version uninstall and success/restart-required results;
it does not make every EXE a Burn bundle or authorize removing related versions.

The implementation follows Microsoft's [manifest overview](https://learn.microsoft.com/en-us/windows/package-manager/package/manifest),
the [installer schema documentation](https://github.com/microsoft/winget-pkgs/blob/5630670fa24b40b74bc32038abd26e677ad4b71c/doc/manifest/schema/1.12.0/installer.md)
and GitHub's [exact reference API](https://docs.github.com/en/rest/git/refs#get-a-reference).
The manifest format allows root defaults and per-installer overrides; package
version and installed display version can differ. Those distinctions must be
preserved by the subsequent execution adapter.
Its inheritance checks also follow the pinned
[WinGet manifest population implementation](https://github.com/microsoft/winget-cli/blob/c17eadbcacf2f5244b13de0d563d921c33ac4af6/src/AppInstallerCommonCore/Manifest/ManifestYamlPopulator.cpp).

The shared profile contract at `1be84d1b5bc3ce65b699a5fc6f30f520859d6f62`
adds an optional `software_burn_version` hint without changing legacy JSON. The
worker advertises version 1 only for private Windows profiles with both signed
capability columns available. The agent negotiates that exact version in its
device-signed recipient registration and checks current permission before new
admission and native execution. Upgrade/downgrade, mismatched replies, withdrawal
at admission and retained result retry pass portable race tests in 8.521 seconds.
The actual Linux ARM64 worker passes profile/schema/broker checks in 1.32 seconds.
All consumers pin the published module. This profile hint alone does not approve
or dispatch a source-derived package.

The source/catalog/dispatch/migration PostgreSQL race suite passes in 39.571
seconds, including exact encrypted Burn install/remove, absent and downgraded
capabilities, replaced review IDs, withdrawn original coordinates, changed source
history and missing provenance. The source adapter and view race suites pass in
1.807/2.096 seconds. Actual route tests on Linux ARM64 also cover Burn source
review, scope/CSRF/body boundaries, exact approval retry, credential-free history,
withdrawal and rejection of direct publication. Owned Chrome checks pass four
source pages at 390, 768 and 1440 pixels without horizontal overflow, including
the Burn bundle code and same-artifact removal explanation.

Focused vet and full Linux ARM64/Windows AMD64 builds pass. Another 80,092 Burn
fuzz inputs pass in 16.496 seconds. All seven agent CI jobs pass with signed Burn
negotiation at `763c6a5`, including native AMD64 and ARM64 lifecycle fixtures
([agent run](https://github.com/the-luap/openuem-agent/actions/runs/34629673589)).

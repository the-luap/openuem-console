# WinGet source review and immutable MSI approval

Open an approved WinGet revision and select **WinGet installers**. An organization
software manager can confirm **Save installer source**, review compatible machine
MSI choices and confirm **Approve this MSI revision**. The resulting MSI revision
has its own approval, binary digest and source evidence link. Select its
**Windows device requests** to prepare and explicitly dispatch installation or
removal through the existing individual-agent protocol.

Saving a source and approving an MSI do not create device requests or installer
tasks. An unresolved WinGet coordinate remains non-executable. This integration
supports the exact machine MSI/WiX subset described below; unsupported installer
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
revalidates those fields and atomically publishes a separate MSI revision, its
source link and audit events. A final deadline check prevents a transaction
delayed during auditing from committing an expired approval. Exact approval
retries return the same revision; another request ID cannot reuse the source or
reattribute an existing ordinary catalog approval.

The original WinGet coordinate is retained. Original and derived withdrawals are
independent: withdrawal of the coordinate prevents new captures/approvals, while
withdrawal of the derived MSI prevents its future installation. Neither erases
history. Historical retries preserve withdrawal and never restore approval.
Expired, incompatible and withdrawn source reviews expose no approval forms.

Authorized organization/site readers can inspect source evidence and history,
including the originating source from an MSI detail page. History is bounded to
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

This is source metadata translation, not enabled Burn delivery. Console source
review and immutable approval currently admit only MSI/WiX. Before integrating
Burn, the native contract must verify that the binary's embedded bundle identity
matches its reviewed registration, in addition to the existing hash, Authenticode
and PE architecture checks. Those existing checks alone do not establish bundle
identity. The agent also currently rejects an emulated bootstrapper executable,
even when its payload targets the native architecture. Source-derived Burn
approval/history, capability advertisement, native execution/recovery and physical
acceptance remain open.

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
Windows process; ARM64 process and physical endpoint acceptance remain open.
The bounded preflight subprocess now requires this proof for explicit Burn plans,
comparing exact machine identity, displayed version and native 64-bit registry
view. The retained stage and its approved digest are verified before and after
inspection; parent cancellation and a child exit timer bound FDI work to ten
seconds. Generic EXE inspection cannot silently select this path. The native
helper fixture passes at `767bf1a9ec62456807bc783c2cd60db9dbc6f30e`, including machine
and user scope, foreign architecture, x86, wrong identity/version/digest and closure.
The remaining agent CI jobs are still running.

The shared protocol at `a4fe1e816a3b7feb051817728536fcd857c97aa1` requires Burn
support in the device-signed recipient registration before sealing a task. A
challenge alone grants no capability. Migration `014` preserves old recipients
at zero, and their JSON wire encoding remains unchanged. Capability changes issue
a new recipient ID, cancel pending old work and preserve delivered uncertainty;
audit failures roll back the complete transition. Full local module/registry race
tests and 814,083 wire-fuzz inputs pass. Agent admission still advertises no Burn
capability and rejects new Burn work before recording an attempt; its process
builder cannot fall through to MSI. Source approval/dispatch stays disabled while
native execution and recovery evidence are completed.

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

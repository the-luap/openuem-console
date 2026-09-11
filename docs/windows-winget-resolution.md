# Immutable WinGet source snapshots

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

Next integration must retain encrypted source evidence with an immutable approval
and expose explicit scoped installer review. The existing WinGet catalog coordinate
remains non-executable until that work is complete. Binary staging must still
enforce HTTPS, content digest and native trust checks. WIN-01 and the complete
roadmap remain in progress.

The implementation follows Microsoft's [manifest overview](https://learn.microsoft.com/en-us/windows/package-manager/package/manifest),
the [installer schema documentation](https://github.com/microsoft/winget-pkgs/blob/5630670fa24b40b74bc32038abd26e677ad4b71c/doc/manifest/schema/1.12.0/installer.md)
and GitHub's [exact reference API](https://docs.github.com/en/rest/git/refs#get-a-reference).
The manifest format allows root defaults and per-installer overrides; package
version and installed display version can differ. Those distinctions must be
preserved by the subsequent execution adapter.
Its inheritance checks also follow the pinned
[WinGet manifest population implementation](https://github.com/microsoft/winget-cli/blob/c17eadbcacf2f5244b13de0d563d921c33ac4af6/src/AppInstallerCommonCore/Manifest/ManifestYamlPopulator.cpp).

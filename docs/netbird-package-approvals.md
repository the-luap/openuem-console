# Organization NetBird package approvals

Organizations can now record exact Unix NetBird package approvals at
`/tenant/<tenant>/netbird/packages`. Links are available from NetBird settings
and the device's NetBird overview when the user can read software for the whole
organization. Windows retains the existing authenticated software catalog flow.

An organization administrator or server administrator can approve a package and
permanently revoke an approval. Organization software readers can inspect history
and details. Site-only grants do not confer organization-wide access. Routes
check the current principal and exact URL scope; each store transaction rechecks
authorization and holds the organization row until its audit commits.

## Approval and history

The form records platform, architecture, native package version, exact direct
HTTPS URL, byte length, SHA-256 and a publisher verification reference. The package
identity is fixed to `netbird` on Linux or `io.netbird.client` on macOS. A required
confirmation records the administrator's decision to approve these exact bytes.
This is the administrator's verification attestation; the console does not
independently assess a publisher signature or fetch the artifact when saving.

The strict shared descriptor supplies a canonical UUID, organization and digest.
Oversized or ambiguous forms, invalid target combinations, invalid version
syntax, unsupported URLs and invalid hashes are rejected. Source URLs must
identify direct HTTPS downloads without redirects. In particular, a redirecting
GitHub release URL must first be replaced by an approved direct distribution
source, not by relaxing the agent's download checks.

Approvals are immutable. An exact retry of the same UUID succeeds only for the
original actor, full descriptor and verification reference. Changing any of
those values conflicts; changes require a new approval. An approval replay after
revocation returns the retained revoked record and cannot reactivate it.

The source-containing descriptor is encrypted with AES-GCM under a separate
HKDF purpose. Associated data binds the approval, organization, actor, descriptor
digest and verification reference. History reads never select or decrypt that
envelope, and ordinary approval objects do not contain a source URL. Missing or
incorrect keys cannot publish or authenticate a replay. Authorized metadata reads
and revocation remain possible without decrypting an existing source.

History uses bounded pages of 50 records, with an immutable time/UUID cursor
constrained to the organization. The detail page shows the precise approved
metadata, actor, timestamp and revocation receipt. The human verification
reference is visible to organization software readers and must not contain
credentials. Source URLs and verification text are excluded from audit resources.

## Permanent revocation and audit

Revocation requires the reviewed approval digest, a fresh request UUID, current
management authority and explicit confirmation. A separate permanent record keeps
the revocation actor and timestamp. Repeating the exact revocation returns that
receipt; changing the request identity or actor conflicts. A request UUID cannot
be repurposed for another approval. Revocation concerns future admission; it is
not an uninstall command or proof that an already admitted operation stopped.

Inventory migration `023_netbird_packages.sql` adds permanent approval/revocation
tables with format/identity/bounds constraints and immutable-record triggers.
Revocations must match the retained approval digest. Records do not cascade with
device or organization deletion. Startup checks ensure the protective triggers
are enabled. The revocation path first locks the approval row, then reads a fresh
statement snapshot so concurrent identical requests observe the committed receipt.

Audit migration `036_netbird_packages.sql` admits list, read, approve and revoke
events in the existing settings audit source. Every new approval/revocation and
its audit commit together; audit failure rolls back the mutation. Failed read
audits withhold metadata. Existing audit export and retention behavior still apply.

POST routes support native forms and HTMX with CSRF protection. Both the common
token middleware and route middleware enforce the 16 KiB wire limit before form
normalization. Query/body mixing, duplicate fields and unexpected inputs are
rejected. Pages disable history caching and disable the form while a request is
pending. The interface and authored documentation use English.

## Validation and remaining installer work

Owned PostgreSQL tests cover current and revoked authority, scope isolation,
immutable records, exact replays, encryption context, concurrent approval and
revocation, cursor behavior, audit rollback and startup guards. Registered-route
tests exercise real cookie/form/header CSRF, native redirects, HTMX redirects,
strict input and privacy. Browser cases cover mobile/tablet/desktop layouts,
reader and revoked states, exact request fields, required confirmation and pending
controls. All 30 new and 2,472 total browser cases pass. The complete inventory
race suite passes in 279.359 seconds and the complete audit race suite in 9.279
seconds. Focused approval database tests pass in 4.182 seconds, middleware tests
in 1.482 seconds, and the affected administrator/desktop view suites in 1.915 and
1.932 seconds. Registered routes with PostgreSQL and the full Linux console build
also pass. No package, provider or physical-device execution is part of these checks.

This completes the approval/history workflow, not the installer lifecycle.
The [version-three command and agent journal](netbird-installation-commands.md)
now preserve exact installation intent and share the common uncertainty barrier.
Authenticated installer capability and command delivery must load and authenticate
the exact retained descriptor, recheck revocation with current target authority,
and durably admit execution under the common NetBird operation barrier. Native
install/remove, resulting-state observation and uncertainty recovery still need
implementation. Independent Linux publisher trust and real installation/provider/
physical acceptance remain separate evidence. Approval routes perform no download,
provider request, agent command or installation.

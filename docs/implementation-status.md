# Expanded roadmap implementation evidence

The authoritative scope is [the expanded roadmap](fehlende-funktionen-und-roadmap.md).
Its original reviewed code is `c19a58b`; implementation started from worktree commit
`11328cb`. Every package remains open until its full requirement and acceptance
scope is proven. A passing protocol simulator is not physical-device acceptance.

New [SCEP enrollment](apple-scep-enrollment.md) moves initial iPhone/iPad keys to
the device. [Automatic identity renewal](apple-identity-renewal.md) now schedules
replacement profiles, verifies new-key use and preserves existing device records,
including tested server-side legacy metadata recovery. Hardware acceptance,
CA/master-key rotation and the remaining ENR-01/PKI-01 requirements stay open.

[Native Mac management](native-macos-management.md) adds platform-aware enrollment,
inventory, system profiles and DDM update readiness with encrypted bootstrap-token
escrow. MAC-01/MAC-02 remain open for broader templates, security workflows
and physical-device acceptance.

[Mac channel association](macos-agent-mdm-linkage.md) now has a separate scoped
hardware RPC, bounded Mac collection, protected managed-preference proof reading,
capability negotiation and transactional hashed evidence. Native MDM challenges,
bounded cleanup, association reconciliation and canonical device navigation now
preserve channel history across re-enrollment. Multiple active claims and hardware
conflicts do not silently transfer authority. Physical acceptance, broader Mac templates
and hardware-repair/cross-site merge workflows remain open.

[Mac user channels](macos-user-channels.md) add immutable enrollment capability
tracking, separate encrypted push and profile command state, Apple-schema channel
gates, staged renewal tokens, pause/resume and scoped console actions. PostgreSQL
race tests and console route tests cover ownership, lifecycle and rollback; managed,
paused and reader views were checked at 390/768/1440 pixels. Actual user login,
fast switching, APNs delivery and profile effects still need Mac hardware acceptance.

## Package ledger

| Package | Current evidence | Remaining work |
| --- | --- | --- |
| NET-01 | Native HTTPS gateway; exact public Apple route allowlist; source-network admin restriction; pinned mutual TLS on all backends; canonical login origin; optional exact agent WSS, upgrade limits and stream shutdown tested against real NATS; optional desktop metadata/configuration/key/claim/download routes with pinned private TLS and bounded streaming; synthetic TLS/PostgreSQL tests | Released-agent authorization/enrollment integration; Windows protocol routing; full reference installation/firewall proof; TLS automation, proxy/browser/timeouts/load acceptance |
| SEC-01 | Header-only certificate login removed; trusted gateway boundary; OCSP certificate/freshness binding; canonical redirects; global request-token/Origin CSRF; persisted server/organization/site grants, native Apple and individual desktop enrollment capabilities, permission administration/history; existing sessions rechecked | Legacy desktop route scope/action permissions beyond current global-admin boundary; audit all existing mutation paths; complete authorization and direct-access regression matrix |
| ENR-01 | Device-generated Apple SCEP enrollment with one-time challenge, exact request retries, separate encrypted RA, scoped certificate pinning and TLS/gateway/PostgreSQL tests; shared desktop CSR/broker-key proof, limited PostgreSQL invitations and CA issuance, scoped subjects, bounded broker authorization/session outbox, executable auth/disconnect and worker TLS/NKey services, protected broker setup, durable fixed-consumer reconciliation, worker body/profile/task checks; scoped console authority setup/import, release-bound invitation creation, metadata and revocation; approved-release-bound public HTTPS claims, scanner-safe metadata and public installation instructions; Windows DPAPI/macOS Keychain storage, durable claim recovery, native command authorization and installed-agent admission, verified scope/checkpoints, protected executable binding, explicit service arguments, Windows/macOS activation, macOS app bundle assembly and authenticated local readiness, and opt-in scoped WSS runtime; real-broker/database tests and passing related-repository CI | Reference installation wiring; macOS signed-release registration/approval acceptance, signed installer distribution, binding migration/updates, renewal and release integration |
| APP-01 | Instance-generated public CSR and encrypted per-request key; authorized request history/download/revocation; certificate-only import with offline Apple chain/production usage verification and a mandatory fresh TLS/HTTP2 APNs connection gate; atomic renewal revision/topic checks, account metadata, setup warning and persistent scoped SMTP expiry reminders/history; pinned vendor envelope verification/download, offline vendor signing utility and PostgreSQL/console route tests | Deployment vendor authority/operations and automatic service transport; independent certificate revocation checking; deployment SMTP delivery and actual Apple issuance/renewal/device continuity |
| UX-01 | Roadmap and supporting authored documentation in English; permission-aware navigation/forms; shared header wrapping and rendered access-page checks at 390/768/1440 px | Shared platform navigation/components, locale keys/preferences, pagination/filter/export/bulk consistency, dates/states, redacted errors, build summary, full accessible responsive browser acceptance |
| ENR-02 | Public Apple instructions, confirmed browser-bound claims, GET/HEAD scanner safety, local QR, bounded encrypted retries, status/expiry/revocation help; real-browser native form and download checks; scoped desktop invitation creation, public administrator-assisted installation page, metadata/claim/download protocol with exact gateway routes, file verification and safe same-key recovery | Physical iPhone/iPad and Safari acceptance; macOS signed-release activation acceptance and finished Windows/Mac installer flows |
| MAC-01 | Native manual Mac SCEP enrollment; persisted platform/version evidence; platform filters, device-channel system profiles and inventory; Mac instructions, profile lifecycle, minimal-inventory and scoped console tests; scoped agent hardware/proof RPC, protected Mac collection and transactional hashed evidence; encrypted MDM verification profiles, bounded cleanup, scoped canonical identity and history, conflict handling, re-enrollment continuity and permission-aware device grouping; per-user enrollment, separate encrypted push/command/profile state, capability-gated user profiles, renewal staging, pause/resume and scoped console controls | Mac template coverage, hardware-repair/cross-site merge workflows and real Mac acceptance |
| MAC-02 | Native Mac GDMF/DDM compatibility; conservative supervision/security/bootstrap authorization gates; encrypted device-bound token escrow, renewal access transfer and immediate policy reconciliation; staged FileVault profiles, per-device encrypted recovery escrow/history, authenticated agent validation, journaled rotation, explicit uncertainty resolution and audited retrieval; opt-in native Recovery Lock with encrypted password history and conservative result reconciliation; PostgreSQL/HTTP/browser tests | Physical FileVault rotation/recovery acceptance, escrow certificate rotation, complete Mac security workflows and hardware update/reboot acceptance |
| IOS-01 | Native iPhone/iPad protocol/profile/DDM foundation | iPad filters/templates and separate hardware evidence; full template targeting/conflicts/rollback; group/ring UX and verified results |
| WIN-01 | Upstream deployment and model tests | Simple approved standard/custom catalog, detection/reboot/retry results, actual install/remove/offline/restart tests; update rings/policies and supported-OS matrix |
| PKI-01 | Device-generated Apple SCEP enrollment and bounded CA/RA certificate lifetimes; automatic Apple identity replacement with candidate confirmation, legacy metadata recovery, scoped history and TLS/database tests; encrypted Apple secrets; documented/tested gateway leaf rotation; persistent Apple push expiry reminders with bounded SMTP, authorization rechecks and renewal supersession | Physical-device identity renewal acceptance; desktop identity renewal; CA/master-key rotation, broader expiry health, encrypted backup/restore preserving enrollments |
| OPS-01 | Console CI builds and gateway/service CLIs; signed installer manifest validation, persisted monotonic catalog, verified file descriptors, release-admission CLI and separately signed bootstrap configuration with PostgreSQL race tests | Native signing/notarization jobs, versioned agent/console distribution, secure update/rollback workflows, monitoring, fresh-install and restore runbooks |
| APP-02 | Organization-scoped ADE server certificates and encrypted verified token renewal; atomic full/delta Apple assignment synchronization, preserved history/backoff; administrative UI and PostgreSQL race CI; profile publication with durable uncertain outcomes, desired/observed assignment reconciliation, pinned-issuer signed activation, SCEP/check-in admission binding, immutable removal rights, re-arming and observed MDM setup release; managed ADE administrator provisioning, bound account inventory, protected password history, manual/scheduled rotation and pause/resume; synthetic persistence/protocol and initial CI/browser checks | Managed administrator physical acceptance; groups/rings, directory associations, provider-specific Platform SSO acceptance, certificate rotation and Apple/hardware acceptance |
| WIN-02 | Separate native discovery XML/SOAP codec and read-only TLS handler, OnPremise XCEP request decoding, scoped PostgreSQL enrollment credentials with permission revisions, revocation and atomic one-use consumption; encrypted organization CAs and authenticated XCEP policies; initial WSTEP CSR proof, scoped client certificates, encrypted provisioning/SyncML bootstrap secrets and durable exact retries; direct TLS identity, OMA DM digest/XML codecs and durable authenticated sessions with nonce transitions and a correlated read-only DevInfo probe, with protocol/TLS/PostgreSQL/race/fuzz tests; production route not registered | Credential/CA/device console and gateway integration, administrative SyncML/CSP policies/results, renewal/unenrollment and physical Windows acceptance; separate Entra/Autopilot integration evidence |
| SEC-02 | Existing security inventory; Apple inventory-read/download audit events; permission-change history with before/after grants; scoped multi-source audit viewer, bounded CSV/JSON exports and explicit preview/confirmation retention with permanent deletion receipts, transaction authorization and PostgreSQL/browser checks | BitLocker/FileVault recovery lifecycle, lock/wipe, further policies, compliance/conditional access, vulnerability/KEV prioritization; comprehensive legacy mutation audit coverage and production-scale operational acceptance |
| API-01 | Internal console handlers only | Versioned management API, scoped authentication, desired-state validation/reconciliation, CLI/GitOps, webhooks/retries and equivalent UI outcomes |
| SW-01 | Upstream Windows/Homebrew foundation; immutable approved macOS PKG catalog, native install/remove with exact managed-version observations, scoped console assignment/search/history and PostgreSQL/race/browser validation | Common platform adapters, DDM applications, Apps & Books/license lifecycle, updates/self-service and physical package acceptance; later BYOD/Shared iPad acceptance as specified |

Cross-cutting scope includes native User Enrollment/privacy limits, SCIM and IdP
associations, macOS recovery/local-admin/Platform SSO extensions, certificate
lifecycle and later desktop security analysis listed in roadmap sections 3–4.
These must receive their own implementation and evidence before full completion;
the table's package summaries do not remove any detail from the roadmap.

## Current change evidence

- [Native Windows discovery](native-windows-mdm.md) adds a bounded UTF-8 SOAP 1.2
  decoder and fixed-configuration HTTPS handler with read-only GET/HEAD probes,
  request/response correlation, fixed-length responses, endpoint binding and
  non-reflecting faults. Synthetic parser, TLS, HTTP and concurrent correlation
  race tests pass locally; both complete workflows for `79eeac3` and `2dd103a`
  pass Linux/native Windows protocol and fuzz checks, database/browser regression
  and both builds. Discovery is not registered publicly and does not authenticate
  or enroll a device. WIN-02 and its remaining protocol/hardware gates stay open.
  The subsequent OnPremise XCEP request decoder checks nil policy fields and
  unique bounded `UsernameToken` credentials, preserves exact password text and
  redacts default credential serialization. The subsequent PostgreSQL credential
  store adds exact tenant/site and creator-permission-revision binding, random
  enrollment secrets with stored verifiers, scoped audit/revocation and atomic
  one-use consumption. Local race tests cover restart, 12 concurrent claims,
  observed lock waits, expiry, permission/site changes and complete issuer/audit/
  cancellation rollback. Both complete workflows also pass for credential commit `72f2535`.
  Protected organization CA initialization now adds authenticated private-key
  encryption, immutable issuer configuration, whole-organization certificate
  permissions and scoped audits. The XCEP response/HTTPS service authenticates
  credentials and CA readiness together, returns schema-ordered RSA/SHA-256
  policy and preserves invitations. Local synthetic CA/PostgreSQL/TLS tests
  cover tampering, concurrent initialization, restart, schema upgrade, audit
  rollback and late expiry; final evidence is recorded in the linked document.
  Both full workflows also pass for CA/policy commit `a1f6353`.
- [Native Windows certificate enrollment](native-windows-enrollment.md) adds
  bounded initial WSTEP requests, RSA/SHA-256 CSR proof, server-assigned scoped
  client certificates and encrypted device provisioning. Ten concurrent identical
  requests issue once and retrieve the same persisted result, with fresh response
  correlation and no second certificate. Local PostgreSQL/race/TLS tests cover
  restart, schema upgrade, request/config binding, revoked access/devices/certificates,
  ciphertext tampering and full rollback after audit, cancellation or expiry errors.
  Separate 30-second WSTEP and CSR fuzz runs pass; both complete workflows pass
  for WSTEP commit `be418e8`.
  The subsequent session implementation is recorded below. Administrative
  commands/results, gateway/console workflows, renewal/unenrollment and physical
  Windows acceptance remain open.
- [Native Windows management authentication](native-windows-management.md) verifies
  the exact enrolled TLS leaf against stored certificate/device scope and a
  private organization root pool. Current revocation, site ownership and database
  time are checked under transaction locks, including resumed TLS connections.
  Invitation expiry and later creator permission changes do not revoke an issued
  device identity. Bounded OMA DM digest primitives use independent test vectors
  and constant-time comparison. The full local PostgreSQL/race suite passes in
  27.625 seconds at 90.9% package coverage; vet and 824,941 digest fuzz executions
  also pass. Session and nonce processing is recorded separately below; this
  identity primitive does not report a successful management session. Administrative
  command results, production wiring and physical acceptance remain open.
  Both complete workflows pass for management-authentication commit `3fa2827`.
- [Native Windows SyncML XML](native-windows-syncml.md) adds typed headers,
  commands, status/results, digest challenges, metadata and incomplete-object
  markers. It preserves text/CDATA and self-contained XML data, rejects ambiguous
  namespaces and IDs, emits protocol field order and enforces input/output limits.
  Independent XML decoding and payload-preservation fuzz targets verify the codec.
  The full local PostgreSQL/race suite passes in 28.448 seconds at 91.3% coverage,
  with 499,328 message and 202,307 constructed-data fuzz executions passing.
  Both complete workflows pass for codec commit `a3f5487`. No production
  management route is registered.
- [Native Windows SyncML sessions](native-windows-sessions.md) persist separate
  client/server nonce transitions, ordered exchanges, exact encrypted responses
  and scoped audit. A read-only DevId probe verifies command/result correlation;
  session UUIDs in command IDs prevent stale results after wire-session-ID reuse.
  PostgreSQL tests cover concurrency, restart, challenged authentication, upgrade,
  scope/revocation, ciphertext corruption and atomic rollback. Real loopback TLS
  tests verify response framing and revocation on resumed connections. Bounded
  text chunks validate their declared size before completion. The final local
  PostgreSQL/race suite passes in 33.144 seconds at 89.4% coverage; vet and 325,599
  transition fuzz executions pass. Both complete workflows pass for session
  commit `2c3c2ad`
  ([push](https://github.com/the-luap/openuem-console/actions/runs/34407599355),
  [pull request](https://github.com/the-luap/openuem-console/actions/runs/34407601208)).
  Broader typed policies, console/gateway wiring, lifecycle and physical Windows
  acceptance remain open; exchange completion does not prove policy compliance.
- [Native Windows CSP commands](native-windows-csp.md) add an administrator-only
  compiler and scoped encrypted queue for Get/Add/Replace/Delete/Exec and bounded
  Atomic/Sequence trees. Authenticated sessions deliver eligible intent and persist
  correlated statuses, chunked Get results and immutable packet-bound evidence.
  Creator permission revisions, deadlines, user context and negotiated sizes guard
  delivery and replay. Unknown outcomes stop the queue until an audited resolution;
  acknowledgment is separate from verified policy compliance. PostgreSQL, restart,
  real TLS, rollback, integrity and lifecycle tests pass. The final PostgreSQL/race
  suite passes in 49.024 seconds at 86.4% package coverage; compiler and structured
  result-transition fuzzing pass after 622,469 and 21,261 executions. Both complete
  workflows pass for CSP commit `a03800e`
  ([push](https://github.com/the-luap/openuem-console/actions/runs/34412236916),
  [pull request](https://github.com/the-luap/openuem-console/actions/runs/34412241887)).
  Broader typed policies, command/result views, outgoing chunking, production wiring,
  renewal/unenrollment and physical Windows acceptance remain open.
- [Native Windows update policy runs](native-windows-updates.md) add explicit
  deadlines, deferrals, grace periods, active hours, notifications and driver
  policy. A scoped operator can create immutable apply/removal runs whose
  generated CSP steps are bound to the saved typed intent. Authenticated current
  platform/SKU evidence gates configuration; separate Config/Result reads detect
  effective-value drift and source-specific removal. A dated release catalog
  separates applicability, servicing support, LTSC dates and unknown ESU status.
  PostgreSQL/race tests pass in 51.294 seconds at 85.4% package coverage, including
  restart, cancellation/audit rollback, permission changes, substituted payloads,
  migration and real TLS delivery of all three stages. The policy fuzz target
  passes 502,874 executions; full CI for this extension is pending. Versioned
  rings, scheduled group rollout, console/production wiring, continuous and
  asynchronous reconciliation, actual update/restart results and hardware
  acceptance remain open; verified policy values do not prove patch installation.
- [VPN target and DNS validation](apple-vpn-profiles.md) checks outer protocol
  configuration, DNS types and property versions, App-Layer connection UUIDs,
  transparent proxy Mac versions and fresh mobile supervision for Always On.
  IKEv2 adds authentication, TLS/integer types, property versions, security
  association parameters, post-quantum settings and removed-algorithm checks.
  Always On applies these checks and local certificate bindings to every flat
  tunnel, including the iOS 14.2 minimum Diffie-Hellman group.
  The subsequent exception validator checks service actions, app/captive bundle
  identifiers, UDP limits, duplicate/unknown fields and property versions;
  isolated tests and both full workflows at `c9e0c93` pass, including PostgreSQL
  cases with mixed iPhone/iPad targets, revision/restoration rollback and removal.
  IKEv2 on-demand rules add ordered action/evaluation structure, field placement,
  bounded match lists, SSID byte limits and DNS/probe validation. Isolated tests
  and both full workflows at `abc5ecd` pass, including five persistence/assignment
  paths and all 81 browser cases. Broader provider rules and an on-demand editor
  remain open.
  A typed IKEv2 generator copies certificate configurations into System/User
  profiles with local bindings and machine/EAP-TLS authentication. Protected
  composition uses exact encrypted certificate revisions and atomic audit
  provenance; its console editor enforces scope/algorithm choices and review.
  Isolated production tests and both full workflows for target/DNS, IKEv2,
  Always On, generator, composition and form changes pass. At `e20074e`, 27 IKEv2,
  39 Wi-Fi and 15 AD certificate cases pass against the same rendered CI artifact
  in Chrome, including scope changes, exact form values, keyboard review,
  reset, reader restrictions and three window widths.
  The [portable browser suites](../tests/browser/README.md) reproduce all 81
  cases locally and detect an intentionally broken fixture. Both complete
  workflows at `b41e647` pass, including the new automatic browser steps.
  The [network acceptance procedure](apple-network-acceptance.md) records the
  still outstanding physical-device and provider tests separately.
  Further protocol schemas, complete editors and physical acceptance remain open.

- [VPN certificate references](apple-profile-certificate-references.md) extend
  local identity binding checks to regular/App-Layer VPN, IPsec, IKEv2 and
  transparent proxy configurations. Isolated tests and both full workflows pass,
  including 14 System/User PostgreSQL variants. The subsequent DNS reference
  extension also passes both complete workflows. Always On references pass
  isolated tests and both complete workflows. Complete VPN templates and physical tunnel
  acceptance remain open.

- [Active Directory certificate validation](apple-ad-certificates.md) checks
  uploaded and composed AD identities, typed values, Mac property versions and
  manual-prompt/automatic-renewal restrictions. The dedicated creation form
  preserves omitted options and restricts enabled renewal to computer identities.
  Isolated payload tests, scoped form tests and 15 browser cases pass, as do both
  complete workflows for the backend validation and the form.
  Physical AD/CA acceptance remains open.

- [Enterprise Wi-Fi with EAP-TLS](apple-enterprise-wifi.md) composes exact encrypted
  identity/trust certificate revisions with new local payload bindings, explicit
  TLS and trust settings, and System/User target checks. Isolated payload tests
  and 306 production SQL preparations against 35 migrations pass. All 39 actual
  browser cases and both complete CI workflows pass after a fixture correction.
  Physical RADIUS authentication remains open.

- [Certificate references in Apple profiles](apple-profile-certificate-references.md)
  check that Wi-Fi identities and EAP anchors resolve to unique, correctly typed
  certificate payloads in the same profile. Isolated parsing/reference tests and
  both full CI workflows pass, including System/User persistence and removal.
  Composition is tracked above; broader network templates and physical
  authentication acceptance remain open.

- [ACME certificate profiles](apple-acme-profiles.md) add typed issuer, identity,
  hardware and key settings, durable encrypted client ownership across profile
  removal/deletion, and protected review of historical archive gaps. Parser and
  schema checks, both full CI workflows and 36 actual browser cases pass.
  Issuance, renewal and attestation still require
  the intended issuer and physical-device acceptance.

- [PKCS12 identity profiles](apple-pkcs12-profiles.md) add bounded archive uploads,
  protected passwords, System/User scope and Mac-only key options with revision
  checks. The server validates the outer envelope without executing archive KDFs
  or claiming password/identity verification. Core/fuzz tests, builds, scoped
  console checks and 12 actual browser cases pass. Both full workflows pass,
  including protocol/regression CI. Physical certificate acceptance remains.

- [SCEP certificate profiles](apple-scep-profiles.md) add typed external-CA settings,
  subject/alternative names, key controls and pinned HTTP or HTTPS configuration.
  System/User revision updates check Mac option versions. Parser, wire-format and
  shared public-certificate checks, both full workflows and 18 actual browser
  cases pass. Issuance and renewal against the intended CA remain device acceptance.

- [Public certificate profiles](apple-public-certificates.md) add bounded PEM/DER
  import, separate certificate payloads, System/User scope and assignment-time
  validity checks with revision rollback. Core checks and template generation
  pass. Builds, scoped multipart console checks and six actual browser cases pass;
  both complete workflows pass. PKCS12 and ACME templates are tracked separately;
  physical trust/renewal acceptance remains open.

- [Mac privacy profiles (PPPC/TCC)](macos-privacy.md) add typed application identities,
  all 24 privacy services, Apple Events receivers, grant/deny/user-choice policies
  and their version boundaries. Device/channel/approval checks also guard revision
  changes. Both complete workflows and 21 cases using actual CI-rendered pages pass. Application signature matching and privacy behavior remain
  physical acceptance requirements.

- [Mac System Extensions profiles](macos-system-extensions.md) add typed team/bundle
  approvals, extension types and removal rules with platform, channel, OS and fresh
  management approval checks. Potentially installed revisions retain conflict
  reservations until fresh replacement/removal evidence. Parser checks, all 34
  migrations and 291 prepared production statements pass locally. Builds and scoped
  console checks pass, as do 12 cases on the actual CI-rendered page across three
  widths. Both complete workflows pass for the original implementation and the
  strict-builder follow-up.

- [Mac Gatekeeper profiles](macos-gatekeeper.md) now provide typed application
  assessment, Finder exception and malware-submission prompt settings. The editor
  separates Apple's payloads, omits unchanged defaults and checks macOS versions
  for direct assignment and revision updates. Local core and console checks pass.
  The corrected push workflow passes all jobs, including the older-Mac revision
  rollback case; the matching PR workflow also passes every job. Nine cases using the actual CI-rendered
  page pass at 390/768/1440 pixels, including policy values, confirmation and
  keyboard submission without overflow. ACME templates and broader certificate lifecycle/composition remain separate work.

- [Retained Apple profile revisions](apple-profile-revisions.md) now preserve
  encrypted immutable System/User snapshots, protected history/downloads and
  confirmed restoration with stale-write protection and fresh UUID deployment.
  All 29 migrations, 190 prepared production statements, actual migration and
  immutability checks, and 21 responsive browser scenarios pass. Complete push
  and PR CI pass at `bee0145`. Assigned historical snapshot verification and Mac
  responses without `IsManaged` also pass complete push/PR CI at `9d17f4b`.
  Nine further browser scenarios cover the corrected Mac user pages at `913fbaa`,
  whose complete push workflow passes. Inventory ordering at `08029fd` additionally
  protects newer device/user snapshots from late queries; all 30 migrations, 250
  prepared SQL statements and actual query execution pass, as do all four jobs in
  both complete CI workflows.
  ADE pin ownership and profile prerequisites now have the implemented Platform
  SSO workflow below. Physical acceptance remains open.

- [Mac application reenrollment recovery](apple-application-reenrollment.md) now
  guards creation and delivery across earlier enrollment identities, retains
  immutable per-attempt stopping evidence, exposes scoped/organization review
  views and resumes ADE prerequisites without treating the receipt as installation
  success. All 28 migrations, 164 prepared production SQL statements, actual
  recovery-trigger execution and 12 responsive browser scenarios pass. Complete
  push and PR CI pass at `9e898d6`; physical stopping/reenrollment acceptance remains
  open.

- [Platform SSO profiles](apple-platform-sso.md) now have a typed Mac editor,
  encrypted registration-token storage, bounded provider data, shared editor and
  upload validation, and platform/MDM approval checks for assignment. Console and
  native protocol tests, three responsive browser scenarios and 28,837 isolated
  parser fuzz inputs pass. Immutable ADE profile/app pairs, setup ownership,
  reviewed corrections, retained history and repair receipts pass both complete
  workflows at `67b968c`, together with 36 further browser scenarios. The binding
  and every correction have separate revision identifiers, so stale forms cannot
  become valid after returning to an earlier pair. Historical release dispatches
  keep prerequisite changes closed even after an explicit release retry.
  Cross-profile routing reservations are implemented in `96b8d0c`; all 33 migrations
  and 287 prepared SQL statements pass locally, including historical System/User
  reservation backfill and verification-dependent release. Both complete CI
  workflows pass at `ccbde13`, including the corrected historical migration test.
  Provider-specific registration, token provisioning and hardware
  acceptance remain open.

- [ADE required applications](apple-ade-required-applications.md) now include
  immutable approved revisions inherited at admission, native app observations
  that gate setup release, a bounded searchable console picker, and explicit
  per-device revision correction retaining original intent and change history.
  Migration/preparation, console, native protocol and 18 browser scenarios pass.
  Cross-enrollment installer recovery is covered by the separate milestone above.
  The Platform SSO workflow above binds and corrects provider app/profile
  revisions together. Physical installation and provider acceptance remain open.

- [Managed Mac applications](apple-managed-applications.md) now have an approved
  immutable artifact catalog, native installation/removal and scoped console
  approval, device search, actions and paginated history. Command acceptance is
  distinct from observed managed state and exact app version. Unknown outcomes
  block further mutations; source credentials remain encrypted and absent from
  read pages. Both complete CI runs at `3bfc0c9` passed, as did 39 browser checks,
  URL fuzzing and actual-schema SQL checks. ADE application prerequisites have
  their own subsequent milestone above. Physical acceptance, unified platform
  adapters, Apps & Books and DDM applications remain open. Platform SSO provider
  prerequisites are implemented above; provider registration remains separate.

- [ADE enrollment protocol primitives](apple-automated-enrollment.md#enrollment-protocol-primitives)
  add bounded profile definition/retrieval, per-device assignment/removal outcomes
  and current ownership lookups. Uncertain creation is not automatically replayed;
  missing or non-successful device details cannot prove ownership. CMS MachineInfo
  verification pins Apple's published device issuer, validates the signer and
  signed attributes, and bounds both XML and binary device dictionaries. Synthetic
  protocol/race tests and vet pass. Parser fuzzing completed 869,945 and 302,482
  inputs; an optional public Apple CMS capture also verified locally. Native
  Windows CI includes the ADE protocol suite. The subsequent durable integration
  exposes profile/assignment actions and signed admission, binds SCEP/check-in to
  one activation generation, preserves removal rights on renewal and reconciles
  Setup Assistant from reported state. New focused PostgreSQL tests passed locally;
  the broad local regression run exhausted disk space, so complete regression
  evidence must come from the corresponding branch CI. Physical acceptance remains
  required.

- [Automated Device Enrollment connections](apple-automated-enrollment.md) add
  organization-scoped server certificate creation, verified encrypted token import
  and renewal, immutable Apple account binding, full/delta assignment sync and
  retained history. Page and cursor publication share a transaction with audit;
  failed or partial full fetches cannot remove published assignments. Apple retry
  deadlines apply to scheduled/manual sync and token verification. Five browser
  states passed at 390/768/1440 px with keyboard submission and confirmation
  checks. Local protocol/race and console rendering tests pass, as does the full
  [PostgreSQL/console/build CI](https://github.com/the-luap/openuem-console/actions/runs/34299243491).
  Parser regression tests also reject Unicode case-folded duplicate field names
  and restart unchanged continuation cursors; additional fuzzing passed 380,344
  inputs. Subsequent profile assignment and authenticated setup/re-enrollment
  are described above; physical Apple acceptance remains open.

- [FileVault rotation recovery](macos-filevault.md) now requires a signed process
  stopping claim before an uncertain attempt can admit an old-key resolution check.
  A synthetic parent/child regression confirms that a child can outlive the agent
  while its parent lease becomes free. The protected journal records the kernel
  boot-session UUID; same-boot intent recovery waits without repeating a mutation,
  and a subsequent boot can establish termination. Legacy receipts and intents
  cannot acquire invented stopping evidence. Already queued legacy resolution
  checks finish as rejected without advancing key validation or blocking later
  reconciliation. Agent, worker and console use the
  same protocol v2 dependency. Local native process/journal/runtime race tests,
  console tests and vet pass; the shared registry's
  [PostgreSQL race CI](https://github.com/the-luap/openuem-nats/actions/runs/34294862275)
  also passes. Six browser cases cover waiting and stopped uncertainty at
  390/768/1440 px, blocked actions, retained history and keyboard POST submission,
  without horizontal overflow. These tests perform no real FileVault operation;
  physical rotation/recovery acceptance and broader MAC-02 work remain open.

- [Recovery Lock](macos-recovery-lock.md) adds explicit enrollment rights and
  owner confirmation, encrypted password history, native creation/import/checks,
  rotation/removal, and separately authorized, audited password retrieval.
  Delivery consumes each mutation once; distinct candidate verification and
  explicit stopping evidence govern uncertain results. Superseded or expired
  preflight responses cannot authorize another change. Local protocol, handler,
  rendered-view checks and vet pass. Thirty browser cases cover ten states at
  390/768/1440 px, keyboard confirmation and protected POST forms, with no
  horizontal overflow. PostgreSQL-backed native protocol, console routes and
  rendering pass with the race detector in
  [CI](https://github.com/the-luap/openuem-console/actions/runs/34292333350),
  alongside Linux/Windows builds and native Windows cryptographic checks.
  Physical recoveryOS/password acceptance and the broader MAC-02 package remain open.

- [Mac firewall profiles](macos-firewall.md) add a System-scope editor with
  explicit firewall settings and bounded app rules. The editor and uploaded
  profiles enforce field types, device platform and version-specific settings.
  PostgreSQL tests cover atomic mixed-target rejection, incompatible revision
  rollback and verified installation/removal; real-router tests cover roles,
  CSRF and form ambiguity. Browser checks cover three roles at 390/768/1440 px,
  keyboard operation and repaired profile-page overflow. Effective firewall
  behavior on a Mac and broader template/conflict coverage remain open.

- [Scoped audit logging](audit-log.md) queries available original Apple, agent,
  access, release, audit access and retention sources with exact scope/filter
  enforcement and stable pagination. CSV/JSON exports exclude secret payloads
  and are bounded by rows, bytes, concurrency and request lifetime. Explicit
  one-use retention previews default to indefinite storage; transactional batch
  deletion preserves permanent policy/deletion evidence. PostgreSQL and console
  tests cover scope, revocation, CSRF/MFA, pagination, preview replay, concurrent
  cleanup, rollback and joined cancellation. Responsive browser checks cover
  390/768/1440 px and keyboard confirmation. Historical unknown outcomes/sites
  remain explicit; comprehensive legacy action coverage is still open.

- [Apple device identity renewal](apple-identity-renewal.md) schedules replacement
  enrollment profiles without changing immutable MDM fields. One-use SCEP
  authorization, staged encrypted push data and a new-key command request gate
  activation; retired keys can acknowledge only the exact replacement command
  during a bounded grace. PostgreSQL tests cover retries, rollback, restart,
  offline confirmation, late failure, revocation, scope, stale credentials and
  known legacy PKCS#12 metadata recovery. Real TLS tests exercise direct and
  gateway routes. Rendered English device views were checked at 390/768/1440 px
  with expanded fingerprints and keyboard disclosure. Hardware continuity and
  other certificate lifecycle work remain open.

- [Apple push requests](apple-push-requests.md) add a local external-vendor CSR
  workflow with encrypted request keys, bounded history, administrative account
  metadata and atomic certificate-only import. Tests use synthetic issuers and
  exercise actual PostgreSQL transactions and console permissions. This is not
  a verified APNs setup wizard; APP-01 remains open.
- [Vendor signing](apple-vendor-signing.md) now provides an offline vendor utility,
  explicit operator certificate pins, exact-CSR signature/chain validation and
  transactional portal-request upload/download. Synthetic issuers exercise the
  cryptography and persistence; real Apple permission, issuer acceptance and
  real push issuance and deployment APNs connectivity remain unproven.

- [Push certificate validation](apple-push-certificate-validation.md) now rejects
  untrusted issuer chains through both import paths, requires production push
  and client authentication usage, and preserves active credentials and pending
  requests on rejection. Fixed public Apple roots and intermediates are embedded;
  no upload-controlled AIA URLs or OS roots are used. Synthetic chain/database
  tests and real-router rejection tests cover the change. Independent revocation
  and actual issuance/renewal acceptance remain open.
- [APNs connection checks](apple-apns-connection-check.md) now gate both import
  paths on a fresh certificate-authenticated TLS/HTTP2 connection and PING ACK.
  Loopback TLS 1.2/1.3 tests cover failure and cancellation; PostgreSQL tests
  exercise rejection, corrected retry and rollback through both import paths.
  Successful imports atomically record the leaf fingerprint/check time and audit.
  This sends no device command and does not establish real Apple or device
  continuity acceptance.

- [Push expiry reminders](apple-push-expiry-reminders.md) persist staged warnings
  and individual delivery attempts, recheck current organization authority and
  certificate identity immediately before sending, and survive console restarts.
  PostgreSQL/race and actual loopback SMTP tests cover retries, replica races,
  renewal, permission changes, TLS/authentication and joined shutdown. The setup
  page exposes scoped aggregate history; SMTP acceptance is explicitly separate
  from inbox delivery and ambiguous crash retries retain their Message-ID.

- Shared library client `d6129ce9fe9b` verifies HTTPS, bounds requests/responses,
  rejects redirects and binds issued certificate purpose, key, device and WSS
  origin. [Linux/native Windows CI passed](https://github.com/the-luap/openuem-nats/actions/runs/34182431163).
  The console exercises that client implementation with reconstruction,
  same-key recovery and withdrawal through its real TLS gateway/handler/registry.
  That console integration retains test keys in memory; the native persistence
  evidence below separately covers DPAPI and Keychain recovery.

- Agent `f5a3731` durably stores pending keys before the first HTTPS claim, binds
  retries to the original bootstrap and only returns a validated committed
  identity. Windows DPAPI protects System/Administrators records; macOS uses an
  explicit noninteractive file keychain. Tests cover a lost issuance response with
  both native backends, corrupt state, concurrent publication and shutdown.
  [Windows, macOS and Linux CI passed](https://github.com/the-luap/openuem-agent/actions/runs/34185479070),
  including full agent builds. Agent `1345f54` adds opt-in runtime selection,
  protected scope, scoped WSS reports/profile requests, read-only prepared-consumer
  access and joined transport shutdown. Its [three-platform CI passed](https://github.com/the-luap/openuem-agent/actions/runs/34186649018).
  Native bootstrap authorization, signing, renewal, complete command execution
  bounds and installed-device acceptance remain open.

- Shared library `d21252be66de` separately authenticates configuration and release
  signatures, origin/target, expiry and release checkpoints. [Linux/Windows CI passed](https://github.com/the-luap/openuem-nats/actions/runs/34187288931).
  Agent `e65091e` durably binds verified scope and release sequence before claims,
  rejects rollback and checks configuration expiry before identity publication.
  [Windows/macOS/Linux CI passed](https://github.com/the-luap/openuem-agent/actions/runs/34187759140).
  Console `b8a810f` adds a protected dedicated configuration signer and read-only
  public key/configuration routes; [CI passed](https://github.com/the-luap/openuem-console/actions/runs/34188910114).
  Library `c3688fa59622` adds bounded native HTTPS GET methods and strict origin-key
  parsing, with [passing Linux/Windows CI](https://github.com/the-luap/openuem-nats/actions/runs/34189077681).
  Library `126bca15f12f` also streams verified installer bytes with a
  separate 15-minute bound and expiry checks before/after transfer;
  [Linux/Windows CI passed](https://github.com/the-luap/openuem-nats/actions/runs/34190387673).
  The console exercises all these methods through its live TLS gateway/registry
  fixture. Console `3593d4b` adds the bootstrap-key CLI, which provisions or
  validates a private signer without overwriting existing state;
  [Linux/native Windows CI passed](https://github.com/the-luap/openuem-console/actions/runs/34189388894).
  The later native command below adds explicit administrator authorization;
  finished end-user installation remains open.

- Agent `0a1b28d` adds bounded native signature verification: Windows Authenticode
  with revocation checks and macOS's explicit notarized Developer ID assessment.
  Its [Windows/macOS/Linux CI passed](https://github.com/the-luap/openuem-agent/actions/runs/34190740402).
  Agent `5076ec5` connects exact-origin package downloads to private staging,
  descriptor-bound hashing before/after native verification, checkpoint checks,
  cancellation and conservative cleanup; [all three CI platforms passed](https://github.com/the-luap/openuem-agent/actions/runs/34191314823).
  Windows exercises the complete staging path with the Go project's licensed
  embedded-signature fixture, without running it. Shared-library `92c941119613`
  adds separate installed-agent bindings, and agent `6c4bf3c` verifies the running
  executable's bytes, identity and permissions; [native CI passed](https://github.com/the-luap/openuem-agent/actions/runs/34192280621).
  Console `bc76544` tests that binding through its actual TLS configuration route;
  [CI passed](https://github.com/the-luap/openuem-console/actions/runs/34192284726).
  Agent `8bc63f8` joins those checks with explicit native-command management/scope
  authorization, protected input, independent release trust and durable store
  admission before claims and identity publication. [All three CI platforms passed](https://github.com/the-luap/openuem-agent/actions/runs/34193859066),
  including real Windows WinTrust/HTTPS/DPAPI enrollment and idempotent retry.
  Real release signing, finished installers/consent UI, macOS activation and
  device acceptance remain open. See [native command implementation](https://github.com/the-luap/openuem-agent/blob/8bc63f8ed7272eef1f0414d31449531e637245dc/docs/native-enrollment-command.md).

- `internal/desktop/public_http.go`, `internal/desktop/protocol` and the optional console
  TLS listener expose read-only metadata/configuration/key documents, strict endpoint-key claims and approved
  package downloads through the exact gateway allowlist. Real PostgreSQL/TLS race
  tests cover one-identity recovery, ambiguous JSON, origin/source spoofing, direct
  backend denial, release withdrawal, file mutation, ranged downloads, database
  contention and shutdown. [Protocol operations](desktop-public-protocol.md) records
  bounds and remaining native bootstrap/installer work.

- The [desktop console invitation form](desktop-console-invitations.md) now creates
  scoped release-bound invitations after explicit confirmation. It offers only
  installed-agent-compatible targets, handles single-site navigation and rejects
  stale releases, duplicated fields, foreign scope/origin input, invalid limits,
  missing signers and changed packages. Real PostgreSQL/router tests verify atomic
  audit and one-time token exposure. A disposable browser session exercised native
  form submission and token-free list navigation at mobile/tablet/desktop widths;
  light/dark rendering was inspected. [CI passed for `e75f777`](https://github.com/the-luap/openuem-console/actions/runs/34195300064).
  The subsequent [public installation page](desktop-public-protocol.md) adds bounded,
  script-free English instructions and read-only invitation-file downloads. Actual
  TLS/gateway/PostgreSQL tests prove scanner safety, unchanged capacity, restrictive
  browser headers, escaped labels and same-key recovery without revealing device
  identities. Its saved HTML fits mobile/tablet/desktop widths in light/dark
  rendering. Finished native installers and their automatic activation flow remain outstanding.

  Console `90d811e` passed both [protocol/console CI](https://github.com/the-luap/openuem-console/actions/runs/34196986096)
  and [build CI](https://github.com/the-luap/openuem-console/actions/runs/34196982995)
  with the public installation page and invitation-file routes.

- Agent `6d66ea5` now reports service readiness after local identity/configuration
  validation and job registration, schedules initial inventory asynchronously,
  returns startup errors, handles Unix signals during initialization and joins
  admitted work before releasing credentials or closing the logger. Windows keeps
  its control loop available during startup/cleanup and reports actual pending
  states. [Linux, macOS and Windows CI passed](https://github.com/the-luap/openuem-agent/actions/runs/34198267075),
  including actual temporary Local System SCM services, isolated SIGTERM
  subprocesses, scheduler timeout/ownership tests and the existing native identity
  checks. macOS service registration/activation and complete OS execution
  bounds remain open. See [service lifecycle details](https://github.com/the-luap/openuem-agent/blob/6d66ea5988aacd8190efe4479db8312eb21fb0ef/docs/service-lifecycle.md).

- Agent `046f858` selects the individual identity through explicit canonical
  `serve -identity-directory` arguments before logging or service startup,
  independently of enrollment environment variables. Duplicate/unknown arguments
  fail with redacted diagnostics. [All three native CI platforms passed](https://github.com/the-luap/openuem-agent/actions/runs/34198749706).
  Agent `0649326` adds [Windows activation](https://github.com/the-luap/openuem-agent/blob/0649326763aa426a8f7cc4505d6a27b7e4b30f19/docs/native-windows-activation.md):
  private marked configuration, exact automatic Local System service registration,
  local readiness and retained-state startup recovery. Native admission persists
  the executable size/hash; activation and runtime both verify it. Old unbound
  records remain readable but are refused by activation; migration, authorized
  executable updates, macOS registration, end-user installers and physical device
  acceptance remain open. [Windows, macOS and Linux CI passed](https://github.com/the-luap/openuem-agent/actions/runs/34201701916),
  including actual DPAPI/SCM activation and startup recovery in uniquely named
  Local System fixtures, runtime rejection of a wrong executable binding, foreign
  installation/ACL rejection, preserved identity/configuration on retry and full
  native builds. Fixture services construct the actual individual agent but do
  not start inventory or host management. Local Windows ARM64 cross-build also
  passed; physical ARM64 acceptance remains outstanding.

- Agent `5327ffd` adds [macOS app bundle assembly](https://github.com/the-luap/openuem-agent/blob/5327ffdbd2dfc04487aa724c5c9127302b6430de/docs/macos-app-bundle.md)
  with sealed app/daemon metadata, a fixed external identity location, exclusive
  publication and an explicit macOS 13.0 deployment baseline. The builder rejects
  incompatible Mach-O targets and newer binary minimum versions. Native tests
  verify an ad-hoc resource seal, including rejection after daemon plist changes;
  the build-only check packages the actual CGo agent without running or installing
  it. [All three CI platforms passed](https://github.com/the-luap/openuem-agent/actions/runs/34204893519).
  Assembly does not provide Developer ID signing, notarization or distribution.

- Agent `d9f6f40` adds [authenticated local macOS readiness](https://github.com/the-luap/openuem-agent/blob/d9f6f40966ae3b5518013f3a8958ff9b1833d423/docs/macos-local-readiness.md)
  for individually enrolled agents bound to their executable. A private root-only
  Unix endpoint signs a fresh challenge tied to the native peer PID, device/scope,
  admitted image and certificate expiry. Readiness follows scheduler startup;
  shutdown joins admitted requests before releasing identity keys. Native tests
  cover peer credentials, actual crash/restart recovery, foreign file/socket
  preservation, slow clients, cancellation and held signing work. Local native
  race tests and the full production build pass. [Windows, macOS and Linux CI passed](https://github.com/the-luap/openuem-agent/actions/runs/34207785970),
  including the isolated socket fixtures under root, native production builds and
  actual-agent bundle assembly. This proof describes local
  initialization, including an offline reconnect schedule, not inventory delivery.
  `SMAppService` registration/approval integration, signed end-user installers,
  binding migration/updates and physical Mac acceptance remain open.

- Agent `82080f0` implements [native macOS activation](https://github.com/the-luap/openuem-agent/blob/82080f0e34bd93f4d584ff89798ceb88a5be09f1/docs/native-macos-activation.md):
  root-owned installed app admission, exact sealed metadata, explicit Developer ID
  Application/notarization checks, a native Foundation/ServiceManagement bridge,
  private operational configuration and authenticated readiness after approval.
  Pending approval returns a distinct public state and exit code; cancellation
  retains observed registration, and retry preserves operational settings. Actual
  interrupt/termination subprocess tests verify cooperative CLI cancellation.
  Local native race tests and the production build pass. [Windows, macOS and Linux CI passed](https://github.com/the-luap/openuem-agent/actions/runs/34211147047),
  including root filesystem/read-only framework checks and actual Unix signal
  subprocesses. The public installation page now explains the activation command
  and Mac background-service approval; existing PostgreSQL/portal race tests pass.
  CI fixtures perform native read-only bundle/status and code-signature checks,
  plus root filesystem tests and injected registration-state transitions. They do
  not register a native daemon or start inventory. Positive registration, approval,
  reboot and device connectivity with the final Developer ID signed/notarized
  release remain unproven; installer distribution, guided consent, migration and
  updates remain open.

- `internal/security/clientidentity`: explicit gateway leaf pins, direct TLS mode,
  strict RFC 9440 decoding, backend enforcement and header replacement.
- `internal/gateway` and `cmd/openuem-gateway`: HTTPS reverse proxy, public route
  allowlist, administrator source-network policy and protected backend transport.
- `internal/mdm/apple/http_test.go`: real TLS enrollment/check-in directly and
  through the gateway, backed by isolated PostgreSQL schemas.
- `internal/controllers/authserver/handlers`: certificate login uses the trust
  policy; OCSP responses must match the certificate and freshness requirements.
- `internal/controllers/router`: common request-token/Origin CSRF for native forms
  and HTMX, host-bound cookie, no URL-token fallback, correct HTTP error statuses.
- `internal/common/db.go` and login handlers: configured `OPENUEM_PUBLIC_ORIGIN`
  drives login redirects; gateway trust is loaded before listeners accept traffic.
- [Gateway operations](gateway-operations.md): implemented configuration, rotation
  and explicit boundaries; not a claim of complete NET-01 acceptance.
- `internal/security/access`: persisted additive grants, revision conflicts,
  one-time bootstrap, transaction-level actor checks and last-administrator guard.
- Console authorization: explicit native Apple capabilities, organization/site
  selector filtering, object/body scope enforcement, default denial of legacy
  administration to scoped roles and immediate effect on existing sessions.
- [Access operations](access-control.md): migration, role matrix, permission UI,
  history, credential reset behavior and remaining desktop scope work.
- Shared header wrapping and rebuilt pinned Tailwind assets; permission-page
  overflow checks at 390/768/1440 CSS pixels using actual handler-rendered HTML.
- [Public enrollment](enrollment-portal.md): explicit claims, one identity per
  invitation, three encrypted browser-bound retries, lifecycle cleanup, rate
  limits, token-free errors/audit and scanner-safe instruction/status reads.
- A live TLS/PostgreSQL browser fixture verified native forms and three identical
  downloads, denial to another browser, CSP and responsive instruction rendering.
  It exposed and fixed null Origin caused by `no-referrer`; `strict-origin`
  preserves form Origin while excluding tokens from Referrer headers.
- [Desktop enrollment administration](desktop-console.md): additive registry
  startup, scoped public metadata with keyset pagination and read audit, encrypted
  authority setup/import, and confirmed invitation/identity revocation. Real-router
  PostgreSQL tests cover roles, foreign scopes, CSRF and command cleanup. A live
  TLS browser fixture covers native setup, keyboard confirmation and responsive
  tables; signed installation artifacts and new invitation creation remain open.
- [Installer release admission](agent-release-operations.md): explicit public-key
  trust, signed immutable metadata, all-target file verification, transactional
  sequence/digest checkpoint, concurrent approval protection, withdrawal and
  database-independent candidate inspection. Public downloads now use this catalog;
  native signing and installer execution remain unfinished.
- Installer invitation/claim store methods now bind the exact approved release,
  target, origin and expiry in transactions. PostgreSQL lock-observation tests
  verify issuance/withdrawal ordering and rollback of related state. The public
  handler now uses those methods. The invitation UI and native bootstrap activation
  remain open.

## Verification record

Local verification on 7–8 September 2026 uses Go 1.26.8 and the existing isolated
PostgreSQL container `openuem-ios-test-pg` on loopback port 55439. Tests create and
drop their own unique schemas; the normal application database is not used.

Recorded passing commands for this change set:

```sh
go test -race -count=1 ./internal/security/clientidentity ./internal/gateway ./internal/controllers/authserver/handlers ./internal/controllers/router/...
APPLE_MDM_TEST_DATABASE_URL='<isolated PostgreSQL test DSN>' go test -race -count=1 ./internal/security/access ./internal/controllers/webserver/handlers ./internal/mdm/apple ./internal/views/mdm_views ./internal/views/access_views
go test -count=1 -run TestDeploymentTestSuite ./internal/models
APPLE_MDM_TEST_DATABASE_URL='<isolated PostgreSQL test DSN>' go test -race -count=1 ./internal/mdm/apple ./internal/controllers/webserver/handlers ./internal/views/mdm_views
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./...
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./...
```

All listed commands passed, with a final router race run after adding the native
form size limit. The GitHub workflow definition now includes gateway, certificate-login and router security tests; a changed YAML
file is not evidence that a remote CI run has executed.

The current access-control changes also pass the combined security, gateway,
router, Apple, console and view race checks, deployment-model regression and both
cross-builds. Tests cover concurrent grants/demotions, stale revisions, foreign
tenant/site IDs, all registered administrator routes, reader mutation denial,
operator escalation denial, grant/revoke effects on existing sessions, read audit
events and preserving grants during built-in account credential reset.

The subsequent enrollment portal also passes combined security/Apple/gateway/
console/view/router race checks and Linux/Windows cross-builds. Its PostgreSQL suite includes concurrent
claims/downloads, encrypted restart recovery, expiry/revocation, HTTP form
boundaries and completed device status. The opt-in live browser fixture runs
against a separate schema and is never enabled by the normal CI test command.

The optional native-agent WSS gateway and NATS dependency update (server 2.14.6,
client 1.53.1) pass the combined race suite above and Linux/Windows cross-builds.
The real-broker gateway test covers individual key proof through both TLS legs,
direct-backend rejection, public route limits, concurrent stream capacity,
continued traffic beyond HTTP deadlines and explicit stream closure at shutdown.
The related NATS library has separate passing real-broker auth callout tests;
the two components are not yet wired into the production console and agent release.

The shared desktop registry now passes PostgreSQL and real-broker race tests for
concurrent claims, invitation capacity, public certificate/key binding, encrypted
CA storage, restart recovery and concurrent authorization/revocation. Published
library commit `2af211c88d57` also passed
[GitHub CI](https://github.com/the-luap/openuem-nats/actions/runs/34170105505).
Worker commit `6c7cc1f` pins this published dependency and passes standalone
Linux/Windows builds, model race tests, and Linux execution of real-broker/body
boundary tests. Its
[GitHub CI passed](https://github.com/the-luap/openuem-worker/actions/runs/34170316983),
including Linux race tests and both platform builds.
[Console CI also passed](https://github.com/the-luap/openuem-console/actions/runs/34170372575)
for commit `ffac98f`, covering the gateway, access controls, Apple protocol/portal,
Windows deployment models and both platform builds. See [desktop integration evidence](desktop-enrollment-plan.md).

## Outstanding external acceptance inputs

Physical iPhone, iPad, Mac and Windows endpoints, a usable Apple MDM push
certificate/vendor-signing path, Apple Business/ADE and Apps & Books access,
Windows signing and Apple Developer ID/notarization access are not established
by the current worktree. Their availability was requested from the user while
independent implementation continues. Missing hardware does not block remaining
code work, and synthetic tests do not satisfy hardware gates.

## Next implementation sequence

1. Complete desktop bootstrap (ENR-01/ENR-02) across the agent and PKI components,
   and extend scoped action enforcement to audited desktop routes (SEC-01).
2. Integrate authenticated agent WSS and individual issuance in versioned related
   repositories; complete the actual one-port reference deployment (NET-01).
3. Implement CSR/push renewal, native Mac management/linkage, platform profiles,
   update/security/token workflows, PKI recovery and unified UX.
4. Complete Windows deployment/release evidence and every P2 package, including
   ADE, Windows native MDM, security, public API and application self-service.
5. Audit every requirement and final acceptance checkbox against current source,
   automated checks, rendered UI and physical devices before claiming completion.

- [FileVault](macos-filevault.md) now stages and confirms escrow before deferred
  activation, preserves encrypted recovery history across profile removal and
  revocation, and exposes separately authorized, audited POST retrieval. The
  bounded CMS decoder supports Apple BER/DER and legacy decryption without
  changing SCEP. The shared library, worker and agent now implement encrypted
  validation delivery, a protected X25519 recipient, bounded read-only local
  validation and signed, idempotent receipts. The console creates independently
  bound, permission-checked validation tasks, reconciles signed outcomes against
  current keys and channel identities, and displays verification state and
  historical success. The agent now has an immutable protected rotation journal,
  OS lease and bounded driver; the worker holds inventory scope through delivery
  and receipt commit. The console adds separately encrypted return keys, scoped
  rotation requests, candidate retention/deduplication, native authority invalidation
  and explicit resolution through a subsequent current-key validation. Physical
  rotation/recovery acceptance, escrow certificate rotation, MAC-02 and the full
  roadmap remain incomplete.

Managed administrator implementation and acceptance boundaries are tracked in
[apple-managed-administrator.md](apple-managed-administrator.md).

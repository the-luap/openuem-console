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
| NET-01 | Reviewed resumable installation with supplied TLS or automatic DNS-01 and retained renewal service; provider-neutral DNS-01 issuer with pinned lego, protected account identity and atomic publication; native HTTPS gateway with atomic public TLS file renewal, retained live streams and per-handshake lifetime checks; exact public Apple route allowlist; source-network admin restriction; pinned mutual TLS on all backends; canonical login origin; optional exact agent WSS, upgrade limits and stream shutdown tested against real NATS; optional desktop metadata/configuration/key/claim/download routes with pinned private TLS and bounded streaming; optional exact Windows discovery/XCEP/WSTEP/SyncML routes with pinned gateway identity; synthetic TLS/PostgreSQL tests | Released-agent authorization/enrollment integration; deployment firewall proof; live DNS/ACME provider operations, proxy/browser/timeouts/load acceptance |
| SEC-01 | Header-only certificate login removed; trusted gateway boundary; OCSP certificate/freshness binding; canonical redirects; global request-token/Origin CSRF; persisted server/organization/site grants, native Apple and individual desktop enrollment capabilities, permission administration/history; existing sessions rechecked; scoped desktop overview with explicit inventory projection, transaction-bound authorization and audit, incomplete-report handling and linked Mac navigation; durable scoped inventory refresh with current-authority dispatch checks, independent attempt evidence, bounded retries and truthful delivery states; scoped software report search and 25-entry pagination with transaction-bound read audit | Remaining legacy desktop detail/action permissions beyond scoped inventory reads and refresh; audit all existing mutation paths; complete authorization and direct-access regression matrix |
| ENR-01 | Device-generated Apple SCEP enrollment with one-time challenge, exact request retries, separate encrypted RA, scoped certificate pinning and TLS/gateway/PostgreSQL tests; shared desktop CSR/broker-key proof, limited PostgreSQL invitations and CA issuance, scoped subjects, bounded broker authorization/session outbox, executable auth/disconnect and worker TLS/NKey services, protected broker setup, durable fixed-consumer reconciliation, worker body/profile/task checks; scoped console authority setup/import, release-bound invitation creation, metadata and revocation; approved-release-bound public HTTPS claims, scanner-safe metadata and public installation instructions; Windows DPAPI/macOS Keychain storage, durable claim recovery, native command authorization and installed-agent admission, verified scope/checkpoints, protected executable binding, explicit service arguments, Windows/macOS activation, macOS app bundle assembly and authenticated local readiness, and opt-in scoped WSS runtime; real-broker/database tests and passing related-repository CI | Reference installation wiring; macOS signed-release registration/approval acceptance, signed installer distribution, binding migration/updates, renewal and release integration |
| APP-01 | Instance-generated public CSR and encrypted per-request key; authorized request history/download/revocation; certificate-only import with offline Apple chain/production usage verification and a mandatory fresh TLS/HTTP2 APNs connection gate; atomic renewal revision/topic checks, account metadata, setup warning and persistent scoped SMTP expiry reminders/history; pinned vendor envelope verification/download, offline vendor signing utility and PostgreSQL/console route tests | Deployment vendor authority/operations and automatic service transport; independent certificate revocation checking; deployment SMTP delivery and actual Apple issuance/renewal/device continuity |
| UX-01 | Roadmap and supporting authored documentation in English; permission-aware navigation/forms; shared header wrapping and rendered access-page checks at 390/768/1440 px | Shared platform navigation/components, locale keys/preferences, pagination/filter/export/bulk consistency, dates/states, redacted errors, build summary, full accessible responsive browser acceptance |
| ENR-02 | Public Apple instructions, confirmed browser-bound claims, GET/HEAD scanner safety, local QR, bounded encrypted retries, status/expiry/revocation help; real-browser native form and download checks; scoped desktop invitation creation, public administrator-assisted installation page, metadata/claim/download protocol with exact gateway routes, file verification and safe same-key recovery | Physical iPhone/iPad and Safari acceptance; macOS signed-release activation acceptance and finished Windows/Mac installer flows |
| MAC-01 | Native manual Mac SCEP enrollment; persisted platform/version evidence; platform filters, device-channel system profiles and inventory; Mac instructions, profile lifecycle, minimal-inventory and scoped console tests; scoped agent hardware/proof RPC, protected Mac collection and transactional hashed evidence; encrypted MDM verification profiles, bounded cleanup, scoped canonical identity and history, conflict handling, re-enrollment continuity and permission-aware device grouping; per-user enrollment, separate encrypted push/command/profile state, capability-gated user profiles, renewal staging, pause/resume and scoped console controls | Mac template coverage, hardware-repair/cross-site merge workflows and real Mac acceptance |
| MAC-02 | Native Mac GDMF/DDM compatibility; conservative supervision/security/bootstrap authorization gates; encrypted device-bound token escrow, renewal access transfer and immediate policy reconciliation; staged FileVault profiles, per-device encrypted recovery escrow/history, authenticated agent validation, journaled rotation, explicit uncertainty resolution and audited retrieval; opt-in native Recovery Lock with encrypted password history and conservative result reconciliation; PostgreSQL/HTTP/browser tests | Physical FileVault rotation/recovery acceptance, escrow certificate rotation, complete Mac security workflows and hardware update/reboot acceptance |
| IOS-01 | Native iPhone/iPad protocol/profile/DDM foundation | iPad filters/templates and separate hardware evidence; full template targeting/conflicts/rollback; group/ring UX and verified results |
| WIN-01 | Upstream deployment/model tests; exact WinGet arguments and owned native processes; immutable encrypted WinGet/MSI/EXE approvals and scoped device preparation; authenticated generation-bound MSI/EXE task delivery, current-certificate receipt proofs, immutable DPAPI admission/results and joined Windows service; private HTTPS/hash/Authenticode staging, native host/package preflight, exact state observations and conservative restart/interruption outcomes; native synthetic MSI install/property/removal and combined executor fixtures, service activation/recovery and cross-platform CI; fresh explicit console dispatch, atomic signed task linkage, verified scoped outcome history and pre-delivery cancellation; separate confirmed read-only reconciliation with protected later-boot evidence, signed durable observations and verified reservation release, retaining original execution outcomes; PostgreSQL/router/browser tests | Immutable WinGet source resolution; physical install/remove/offline/restart/hibernate acceptance; update rings/policies and supported-OS matrix |
| PKI-01 | Device-generated Apple SCEP enrollment and bounded CA/RA certificate lifetimes; automatic Apple identity replacement with candidate confirmation, legacy metadata recovery, scoped history and TLS/database tests; encrypted Apple secrets; documented/tested gateway leaf rotation; persistent Apple push expiry reminders with bounded SMTP, authorization rechecks and renewal supersession; audited native Windows certificate health with current/pending identity separation and CA issuance warnings; persistent Windows certificate/CA reminders with live recipient checks, protected outboxes and scoped delivery history; encrypted database backups with separately encrypted recovery keys/configuration, confirmed isolated restore and synthetic Apple/Windows/desktop identity continuity; shared desktop renewal preparation/confirmation with permanent key ownership, immutable generations and atomic FileVault key-processing acknowledgements; bound HTTPS renewal client and exact gateway/console routes with proof, retry, concurrency, audit rollback and recovery-coordination tests; native protected candidate/decision/activation journals, automatic installed-service scheduling, joined handoff/reconnect, stoppable startup recovery, authoritative cancellation and historical FileVault reconciliation with immutable receipt continuity | Physical-device renewal/disaster-recovery acceptance; production desktop release integration; CA/master-key rotation and cross-platform expiry health |
| OPS-01 | Console CI builds and gateway/service CLIs; minimal unprivileged gateway image with pinned build inputs and isolated native process checks; signed installer manifest validation, persisted monotonic catalog, verified file descriptors, release-admission CLI and separately signed bootstrap configuration with PostgreSQL race tests | Native signing/notarization jobs, versioned agent/console distribution, secure update/rollback workflows, monitoring, released-distribution and restore runbooks |
| APP-02 | Organization-scoped ADE server certificates and encrypted verified token renewal; atomic full/delta Apple assignment synchronization, preserved history/backoff; administrative UI and PostgreSQL race CI; profile publication with durable uncertain outcomes, desired/observed assignment reconciliation, pinned-issuer signed activation, SCEP/check-in admission binding, immutable removal rights, re-arming and observed MDM setup release; managed ADE administrator provisioning, bound account inventory, protected password history, manual/scheduled rotation and pause/resume; synthetic persistence/protocol and initial CI/browser checks | Managed administrator physical acceptance; groups/rings, directory associations, provider-specific Platform SSO acceptance, certificate rotation and Apple/hardware acceptance |
| WIN-02 | Separate native discovery XML/SOAP codec and read-only TLS handler, OnPremise XCEP request decoding, scoped PostgreSQL enrollment credentials with permission revisions, revocation and atomic one-use consumption; encrypted organization CAs and authenticated XCEP policies; initial WSTEP CSR proof, scoped client certificates, encrypted provisioning/SyncML bootstrap secrets and durable exact retries; direct TLS identity, OMA DM digest/XML codecs and durable authenticated sessions with nonce transitions and a correlated read-only DevInfo probe, with protocol/TLS/PostgreSQL/race/fuzz tests; scoped CSP queues/results, typed update verification, versioned rings and scheduled cohorts; optional listener/gateway registration and bounded schedule worker lifecycle; CA/invitation/device console with scoped inventory, one-time credentials, audit and access revocation; protected update run history and cancellation; typed policy apply/removal forms with validated preview and idempotent confirmed admission; scoped ring lists/history and confirmed create/edit revisions; reviewed explicit cohort apply/removal and protected assignment history; UTC schedule preview/confirmation, protected plan history and revision-checked pending cancellation; administrator-only CSP request/result history, undelivered custom-command cancellation and explicit uncertain-queue resolution; bounded custom JSON command editor with shared-compiler preview and confirmed idempotent admission; protected cumulative observation history with authenticated pagination and single-message detail; bounded CMS/PKCS#10 old/new-key renewal proof verification; persistent scoped renewal issuance/retries, encrypted lifecycle history/cancellation, atomic SyncML replacement confirmation and immutable session anchor with TLS/database tests; registered certificate-authenticated Renew SOAP with direct/gateway TLS, disjoint request grammars, timestamp freshness and restart/fuzz tests; scoped certificate replacement history, protected source/replacement details, confirmation evidence and revision/CSRF-checked pending cancellation with database/router/browser tests; authenticated first-packet disconnection reports, atomic access retirement and interrupted-command uncertainty with protected history and console status; typed fixed-provider disconnection requests, protected lifecycle history, priority delivery, revision-checked cancellation and explicit review of missing notifications; scoped disconnection preview/confirmed creation, ten-row history, independent report/outcome/review details and CSRF/revision-checked cancellation/release with router/browser tests; audited organization/site certificate health, bounded expiry filters, authenticated current/pending generations and CA issuance warnings; staged device/CA expiry reminders with protected retry state, live source/recipient checks, runtime shutdown and scoped SMTP history; revision-bound audited JSON command/observation downloads with bounded preparation and integrity checks; twelve native audit sources in the shared viewer/export with explicitly confirmed organization retention and immutable deletion receipts | CSP command/packet/observation retention, broader typed policies, automatic ring promotion, account-authenticated renewal, renewal scheduling, production SMTP/inbox acceptance, end-to-end missing-notification recovery and physical Windows cleanup acceptance; separate Entra/Autopilot integration evidence |
| SEC-02 | Existing security inventory; Apple inventory-read/download audit events; permission-change history with before/after grants; scoped multi-source audit viewer, bounded CSV/JSON exports and explicit preview/confirmation retention with permanent deletion receipts, transaction authorization and PostgreSQL/browser checks; all twelve native Windows audit sources with original scope and opt-in guarded retention | BitLocker/FileVault recovery lifecycle, lock/wipe, further policies, compliance/conditional access, vulnerability/KEV prioritization; comprehensive legacy mutation audit coverage and production-scale operational acceptance |
| API-01 | Internal console handlers only | Versioned management API, scoped authentication, desired-state validation/reconciliation, CLI/GitOps, webhooks/retries and equivalent UI outcomes |
| SW-01 | Upstream Windows/Homebrew foundation; common approved macOS PKG and Windows WinGet/MSI/EXE catalog; native Mac install/remove with exact managed-version observations, scoped console assignment/search/history and PostgreSQL/race/browser validation; authenticated, journaled Windows MSI/EXE service execution with native compatibility, trust and observation checks; explicit console review/dispatch, verified results and queued cancellation; read-only Windows reconciliation with later-boot evidence and separate immutable release history | WinGet resolution; Homebrew delivery, DDM applications, Apps & Books/license lifecycle, updates/self-service and physical package acceptance; later BYOD/Shared iPad acceptance as specified |

Cross-cutting scope includes native User Enrollment/privacy limits, SCIM and IdP
associations, macOS recovery/local-admin/Platform SSO extensions, certificate
lifecycle and later desktop security analysis listed in roadmap sections 3–4.
These must receive their own implementation and evidence before full completion;
the table's package summaries do not remove any detail from the roadmap.

## Current change evidence

- [WinGet source snapshots](windows-winget-resolution.md) now bind the exact
  identifier/version, Microsoft community commit, canonical repository path and
  original YAML digest. The bounded HTTPS client rejects redirects and mutable
  fallback; parsing retains all behavior while rejecting ambiguous or excessive
  input. Combined source/translation HTTPS/race checks pass in 1.742 seconds and parser fuzzing passes
  530,700 inputs. A separate public-source read verifies the fixed Go manifest and
  independently resolved source head without downloading an installer. A separate
  machine MSI/WiX adapter now binds exact architecture, product/display version,
  minimum OS and artifact hash to the existing install/remove plan. Inherited
  switches and dependencies cannot disappear through partial or empty overrides;
  unsupported behavior is rejected. Translation fuzzing passes 569,203 inputs;
  focused vet and Windows compilation also pass. Other installer kinds, encrypted immutable
  approval linkage and scoped console review remain open; these components alone
  do not enable WinGet execution.

- [Windows software reconciliation](windows-software-requests.md#read-only-reconciliation-after-uncertainty-or-a-required-restart)
  now joins the console, signed registry protocol, private worker RPC and protected
  Windows service. Independent capability negotiation enables only the read-only
  protocol. A fresh console review binds current authority, original task and
  certificate, exact expectation and deadline; confirmation atomically records
  its signed task, immutable review link and audits. The native consumer retains
  original admission evidence, requires a later kernel boot before querying exact
  state, and persists signed results and acknowledgements across restarts and
  certificate renewal. Only verified `observed` or `drifted` evidence releases a
  reservation. Other outcomes retain it; original installer outcomes and receipts
  remain unchanged. History, pagination and queued cancellation retain original
  scope and current permissions. The [registry/configuration CI](https://github.com/the-luap/openuem-nats/actions/runs/34595324940),
  [worker CI](https://github.com/the-luap/openuem-worker/actions/runs/34596892195),
  [protected journal CI](https://github.com/the-luap/openuem-agent/actions/runs/34596998567)
  and [native consumer CI](https://github.com/the-luap/openuem-agent/actions/runs/34598058930)
  pass, including mandatory Windows DPAPI and actual read-only MSI helper checks.
  Console targeted PostgreSQL/race checks pass in 46.349 seconds and the complete
  Apple model PostgreSQL/race suite passes in 447.710 seconds. Full scoped
  handler, rendered-view, Linux/Windows build and focused vet checks pass. All 270 browser
  cases pass, including 42 new reconciliation cases at 390/768/1440 pixels.
  The [complete console CI](https://github.com/the-luap/openuem-console/actions/runs/34600864430)
  and [reference installation CI](https://github.com/the-luap/openuem-console/actions/runs/34600864384)
  pass for console commit `3834fa9`, including the coordinated registry/worker
  migrations and actual resumable installation/maintenance on Linux amd64/arm64.
  These fixtures use synthetic boot evidence and do not reboot an endpoint.
  Immutable WinGet resolution and physical package, offline, restart and hibernate
  acceptance remain required; WIN-01/SW-01 and the full roadmap remain open.

- Windows software delivery now has matching reference PKI and worker pins.
  The [broker migration](https://github.com/the-luap/openuem-cert-manager/blob/466c4b3170ef10bae3350ebff971d4e276b93fdf/docs/broker-upgrade.md)
  adds the exact `software` grant from either supported preceding renderer,
  preserves completed v1 journals and uses separate v2 records. Its
  [native CI](https://github.com/the-luap/openuem-cert-manager/actions/runs/34591466304)
  passes on Linux amd64/arm64 and Windows. Local broker/CLI/private-PKI race
  tests and all three actual offline distribution scenarios also pass, retaining
  service identities, JetStream messages and a durable consumer. The reference
  maintenance controller accepts only the reviewed v2 deltas, retains completed
  v1 maintenance history and rejects incomplete or altered prior operations.
  Twelve maintenance and eighteen installation unit checks pass. The fresh
  seven-service reference installer reaches authenticated readiness; its
  interrupted bootstrap also recovers the retained database and console. Full
  reference maintenance with the actual original initializer passes interrupted
  upgrade recovery, broker recreation, retained queued commands, atomic public
  TLS renewal, release admission and an authenticated device WSS worker request.
  These are owned synthetic containers, not a deployment or endpoint acceptance.

- [Native Windows boot evidence](https://github.com/the-luap/openuem-agent/blob/15044d8c1e0d2d17452d0b6321d9a1ae62953021/docs/windows-software-boot-evidence.md)
  is retained in the protected software intent before admission. New work rejects
  missing or changing evidence. Legacy intents remain readable with no invented
  boot proof. The bounded reader combines the native loader boot sequence with
  the System process creation value; a service restart or resumed kernel session
  cannot establish a later boot merely by changing one component. Journal
  reopen/retry preserves the original evidence, and parser fuzzing passes 764,547
  local inputs. The full local agent/store/executor race suites, Windows
  amd64/arm64 builds and focused vet pass. [Agent CI](https://github.com/the-luap/openuem-agent/actions/runs/34590356368)
  passes on Linux, macOS and Windows, including the native Windows reader,
  separate-process comparison and DPAPI journal tests without skips. No test
  rebooted a physical endpoint. Signed post-boot reconciliation and reservation
  release are integrated in the milestone above; physical restart/hibernate
  acceptance remains open.

- [Explicit Windows software dispatch](windows-software-requests.md) joins the
  approved MSI/EXE catalog to the authenticated individual-agent channel. A fresh
  review binds exact device/scope, operation/revision, actor, certificate/recipient
  generation, private plan and original deadline. Confirmation repeats live
  permission, inventory, approval and reservation checks, then commits the signed
  encrypted task, immutable dispatch link, preparation transition and audit
  together. Existing preparations remain inert across migration. Exact retries
  return historical status without re-admission. Original-scope history verifies
  retained envelope/receipt signatures and displays safe observations and exit
  codes; queued cancellation serializes with delivery and cannot stop delivered
  work. The shared registry's [administrative API CI](https://github.com/the-luap/openuem-nats/actions/runs/34587114278)
  passes, as does its full local PostgreSQL/race suite. Console dispatch tests
  cover MSI/EXE install/remove plans, six concurrent exact retries, stale
  authorization/identity/recipient/approval, audit/expiry rollback and immutable
  history. The complete Apple PostgreSQL/race suite passes in 401.150 seconds,
  including legacy preparation migration and competing dispatches. The full Linux
  arm64 handler suite passes against owned PostgreSQL; rendered-view race tests,
  all 228 browser cases (36 new dispatch cases), full
  Linux/Windows builds and focused vet pass. Console tests execute no installer.
  Subsequent read-only reconciliation is recorded above. Immutable WinGet
  resolution and physical endpoint acceptance remain open. WIN-01/SW-01 and the
  complete roadmap remain in progress.

- [Native Windows installer execution](https://github.com/the-luap/openuem-agent/blob/b6a5a1fb8b3592054b343ae0a4a3cccc00f6ef57/docs/windows-installer-processes.md)
  now connects the authenticated software client to the individual Windows
  service, a protected recipient for each certificate generation, immutable
  attempt/result records and the held installation service lease. The joined
  consumer persists signed results before releasing identity/store state, including
  shutdown. It combines private HTTPS/hash/Authenticode staging, read-only native
  architecture/OS and MSI product/version/template or EXE PE checks, retained file
  protection, owned suspended process jobs and exact before/after observations.
  Already observed targets do not execute again; different installed versions
  cannot become implicit upgrades or removals. Success requires both an approved
  exit and the exact observed target. Restart and uncertainty retain their separate
  outcomes; there is no automatic installer retry or claimed rollback.
  The [process/preflight CI](https://github.com/the-luap/openuem-agent/actions/runs/34584903213)
  passed on Linux, macOS and Windows, including an opted-in, generated registry-only
  MSI with unique product/component identities. It was installed, its exact native
  properties (including Unicode, whitespace and trailing backslashes) were read,
  and its removal/absence were verified. No existing product or enrolled device
  was targeted. Local service/executor race tests and complete agent/Store race
  suites passed (12.912/50.963 seconds for the latter); Windows builds pass.
  The [combined executor/service CI](https://github.com/the-luap/openuem-agent/actions/runs/34585800282)
  passed on Linux, macOS and Windows, including native service activation with
  immutable recipient recovery and the combined protected-stage MSI executor,
  exact observation, refusal to remove a different version and observed removal.
  The complete Windows arm64 cross-build also passes. Console MSI approval now
  rejects embedded property quotes to match
  the native wire contract; focused real PostgreSQL/race regressions pass in
  39.474 seconds. Console dispatch and cancellation/history are implemented in
  the subsequent milestones above, alongside signed read-only reconciliation.
  Immutable WinGet resolution and
  physical package acceptance remain open. WIN-01/SW-01 and the full roadmap
  remain in progress.

- The [authenticated Windows software protocol](https://github.com/the-luap/openuem-nats/blob/b932b7b4316170dea4c7c5c74327ac0371494aa6/enrollment/windows-software.md)
  now signs encrypted MSI/EXE task envelopes with a task-bound command certificate
  under the independently pinned enrollment CA. Private plans bind exact scope,
  certificate generation, approval/preparation, recipient, deadline and detection
  expectations. The [agent journal/client](https://github.com/the-luap/openuem-agent/blob/da964472c33eddb31194010ec029a797c25ef1e8/docs/windows-software-delivery.md)
  has exclusive immutable execution admission, generation-specific recipient keys,
  durable signed outcomes and current-certificate submission proofs for historical
  receipts. The [worker RPC](https://github.com/the-luap/openuem-worker/blob/a9886d2135f6b00c294fc8014650fcfb596463d2/docs/windows-software-delivery.md)
  holds current identity, inventory status/site and result/audit in one transaction.
  An agent awaiting admission or disabled agent cannot receive new work; a disabled
  agent can report previously delivered work in its unchanged authorized scope.
  Delivered expiry and interrupted execution remain reserved as uncertain.
  Local verification passes: the full shared protocol/race suite, the complete
  PostgreSQL registry/race suite (69.905 seconds), 567,381 software-wire fuzz inputs,
  complete agent Store/runtime race suites (52.416/11.959 seconds), isolated native
  Keychain inventory/lock tests, Windows cross-compilation and real worker
  PostgreSQL/WSS tests, including result-audit rollback and scope/status lock waits.
  [Shared protocol CI](https://github.com/the-luap/openuem-nats/actions/runs/34580958733),
  [agent journal CI](https://github.com/the-luap/openuem-agent/actions/runs/34581145025)
  and [worker CI](https://github.com/the-luap/openuem-worker/actions/runs/34581149919)
  all passed. Subsequent service/native adapter and explicit console dispatch work
  are recorded above. Preparations remain non-executable without a fresh confirmed
  dispatch. Signed reconciliation is recorded above; WinGet artifact resolution and
  physical endpoint acceptance remain open. WIN-01/SW-01 and the full roadmap
  scope remain in progress.

- [Windows device request preparation](windows-software-requests.md) connects an
  immutable catalog revision to a current individual Windows identity and its
  sole inventory site. Transactional rights, identity/approval locks, generation
  binding, a one-hour/certificate-capped deadline, exact retry handling and one
  reservation per device protect the recorded install/remove intent. Cancellation
  and expiry preserve immutable, scoped history; target and history pages require
  committed read audits. The confirmed 8 KiB forms and six browser states expose
  the preparation boundary explicitly: no agent or worker consumes these
  preparations, and they expire without automatic execution. The subsequent
  dispatch milestone above adds a separate confirmed executable task.
  The full Apple PostgreSQL/race suite passes in 409.591 seconds. After the final
  disabled-endpoint admission restriction, the focused selection passes in 45.850
  seconds, including catalog, Mac application, ADE/Platform SSO and migration
  regressions.
  The complete handler suite, rendered-view race checks and all 192 browser
  cases pass; 18 new cases cover preparation/history states. Linux/Windows
  builds and focused vet pass. No package was downloaded or executed.
  All six CI runs for preparation commit `811776e` passed, including the Native
  Apple management [pull-request run](https://github.com/the-luap/openuem-console/actions/runs/34575448340)
  and [push run](https://github.com/the-luap/openuem-console/actions/runs/34575445134).
  WIN-01 and SW-01 remain in progress; every broader roadmap requirement remains
  unchanged.

- Agent commits `800f72d` and `7a27844` add a
  [bounded exact Windows software observation helper](https://github.com/the-luap/openuem-agent/blob/7a27844821659ebb44955a366df45bd010d788f3/docs/windows-software-observation.md).
  It reads one approved machine MSI product or the exact HKLM uninstall key/view,
  preserves a different installed version as present, and treats inaccessible,
  advertised, malformed or disappearing records as unknown. The same executable
  dispatches the helper before service/identity initialization. Canonical bounded
  pipe messages, redacted failures, joined cancellation and an independent helper
  deadline preserve its process boundary. Portable race tests pass in 18.689
  seconds; macOS/Linux/Windows builds and Windows vet pass. The final code passed
  [all three native CI jobs](https://github.com/the-luap/openuem-agent/actions/runs/34571170520),
  including ten mandatory Windows package/process checks, three of them new
  observation fixtures using only owned machine registrations and an absent MSI
  product. No package was installed or removed. The first native run identified
  Windows normalization of a test's missing string terminator; the corrected
  fixture retains embedded-terminator and malformed-surrogate rejection. The
  helper is a local observation foundation; authenticated operation/result
  binding, durable recovery and physical acceptance remain required.

- The [shared Windows software catalog](windows-approved-software.md) adds immutable
  WinGet/MSI/EXE approvals alongside Mac PKG revisions. Source URLs and executable
  parameters are encrypted with organization/revision binding; readers see only
  safe requirements. Current publication/read authority and audit commit together.
  Concurrent exact retries retain one revision and audit; withdrawal is permanent
  and retries do not restore approval. Filtered pagination over 103 Windows
  revisions interleaved with Mac revisions, foreign cursors, revoked readers and
  publishers, audit failure rollback, Mac application delivery and ADE/Platform
  SSO prerequisites have PostgreSQL/race coverage. The complete handler suite
  passes, including all three approval types and scoped negative cases. Rendered
  view/race checks and all 174 browser cases pass; 27 new cases exercise Windows
  approval/detail/reader/withdrawn/search states at 390/768/1440 pixels. Linux and
  Windows builds and focused vet pass. The first full CI run also exposed two
  historical profile-migration fixtures calling current catalog queries before
  their schema upgrade. They now seed historical inventory directly, retaining
  the original migration/history assertions and real post-upgrade Connect checks.
  The expanded catalog/Mac/ADE/all-migration race selection passes in 38.605 seconds.
  All six console workflows for `a596d27` passed, including both complete Native
  Apple runs ([PR evidence](https://github.com/the-luap/openuem-console/actions/runs/34572509965),
  [push evidence](https://github.com/the-luap/openuem-console/actions/runs/34572503726)).
  These are synthetic approvals, with no
  package downloads or endpoint changes. WIN-01 and SW-01 remain in progress:
  individual-agent delivery, immutable WinGet manifest resolution, operation-bound
  detection, restart/offline recovery and physical acceptance are still required.

- Agent commits `81ed1be`, `62561fb` and `b87cbce` harden the existing Windows package execution path with
  direct arguments, exact fixed-source selection, cancellable job ownership,
  bounded output and original nonzero exit codes. Common legacy callbacks reject
  foreign/ambiguous requests, produce result metadata locally, and report removal
  failures correctly. Windows shutdown joins command/result handling, and an
  owned crash fixture verifies OS cleanup when the runner owner exits. Profile
  fields reject invalid types, conflicting pinned/latest versions and a foreign
  source before execution instead of panicking or changing intent. Local
  agent/deployment race tests, macOS/Linux/Windows builds and native/cross-platform
  vet pass. Required Windows CI tests use only owned executable fixtures.
  Final code commit `b87cbce` passed [all three native CI jobs](https://github.com/the-luap/openuem-agent/actions/runs/34567053317),
  including seven mandatory Windows execution, shutdown, crash and profile-input
  rejection tests. See the agent's
  [execution boundary and remaining acceptance](https://github.com/the-luap/openuem-agent/blob/b87cbce5c5ff6990f9db98ad808b5a8fcc122eae/docs/windows-package-execution.md).
  This is WIN-01 implementation progress, not completion: delivery from the
  approved catalog, detection, reboots, transactional recovery and physical package
  acceptance remain required. Individually enrolled agents do not gain legacy package
  subjects through this change.

- The issuer now exposes [local renewal readiness](gateway-acme.md#local-renewal-readiness)
  through a private Unix socket. It checks the live service's original directory
  leases, retained installation UUID, paired bindings, original account key,
  accessible inputs and valid published TLS without issuance or state changes.
  Bounded connections/checks and joined shutdown preserve unexpected socket entries
  and recover only a protected stale socket under the service leases. A valid
  publication remains ready during an active or transiently failed network attempt;
  missing keys, substituted bindings, changed leases and expired material fail.
  Both Compose definitions configure the exact local probe as a Docker health
  check, and the installer requires a positive result before completion. Native
  race tests and six Linux socket/state tests pass; the real issuer/lego fixture
  passes readiness, DNS-01, ARI renewal, gateway reload and joined shutdown.
  Full fresh and interrupted installation acceptance also passes with the retained
  issuer reporting healthy and the actual local probe returning readiness.
- The [12cb474 native workflow](https://github.com/the-luap/openuem-console/actions/runs/34557618416)
  passes all four supplied/automatic TLS installation scenarios on Linux amd64 and
  arm64, plus its Windows checks. Its [ACME workflow](https://github.com/the-luap/openuem-console/actions/runs/34557618441)
  and [gateway workflow](https://github.com/the-luap/openuem-console/actions/runs/34557621103)
  also pass.
- Configuration version 2 of the [reference installer](reference-installation.md)
  now performs automatic DNS-01 setup with a reviewed local issuer image and
  protected provider inputs. Its offline input check has no writable mounts or
  network. Initial issuance precedes private provisioning; the separate retained
  renewal service shares only the public publication with the gateway. Original
  ACME account keys and paired installation bindings enter the provisioning
  snapshot, while renewable generations remain dynamic. Supplied-TLS version-1
  profiles and journals remain compatible. Local Linux arm64 acceptance passes
  fresh installation and interrupted recovery in both modes, real first login and
  password replacement, bootstrap retirement and completed retries without
  recreating the seven services or issuer. DNS-01 recovery additionally covers
  provider failure, missing original-key rejection and controller termination
  during a held DNS request followed by joining the same live issuer process.
  The issued gateway chain verifies against the local fixture CA; actual TXT
  validation and cleanup are observed. The 28 installer/maintenance Python tests,
  native issuer race tests, Linux issuer vet and workflow syntax checks pass.
  The native console workflow includes all four installer scenarios on both Linux
  architectures. Signed distribution, graphical setup, general upgrade/restore,
  real provider operations and physical-device acceptance remain open.
- The [f29aebb native workflow](https://github.com/the-luap/openuem-console/actions/runs/34554965508)
  passes Linux amd64, Linux arm64 and Windows. Its [ACME workflow](https://github.com/the-luap/openuem-console/actions/runs/34554965621)
  and [Native Apple workflow](https://github.com/the-luap/openuem-console/actions/runs/34554965543)
  also pass.
- The reference ACME fixture now runs the actual issuer/lego command separately
  from its Pebble and DNS provider processes on an owned internal Docker network.
  The Linux arm64 acceptance passes real DNS-01 and TXT cleanup, provider-failure
  recovery without changing the account key, issued-chain verification against
  pinned fixture roots, and joined server shutdown. Both test roles require an
  explicit isolated-fixture opt-in and use non-root containers without host ports.
  The existing single-container DNS-01/ARI/reload fixture also passes after the
  shared DNS helper change. The automatic installation tests use this provider
  boundary for fresh setup and actual retained-process recovery.
- The [2bb1a82 Native Apple workflow](https://github.com/the-luap/openuem-console/actions/runs/34551946533)
  passes its test, Linux/Windows builds and Windows bootstrap-key jobs.
- The [ab1ccb4 native workflow](https://github.com/the-luap/openuem-console/actions/runs/34553841835)
  passes Linux amd64, Linux arm64 and Windows, including atomic public TLS reload,
  separate issuer composition, fresh installation and interrupted broker maintenance.
- The [reference public TLS composition](reference-public-tls.md) adds a separate
  issuer project with the explicit runtime account, isolated account/configuration
  mounts and its own outbound network. Its actual input preflight passes with
  empty account/publication volumes and unchanged protected inputs on an isolated
  test network. The gateway overlay selects the atomic `current` publication
  through its existing read-only directory mount; maintenance readiness selects
  only the public chain and rejects escaping or aliased selections. Full Linux arm64
  reference acceptance passes fresh and old-grant maintenance with synthetic TLS
  renewal published from Linux, matching the actual issuer environment. It retains
  container identities across reload, then passes restart and live WSS revocation.
  The protected Python checks, syntax checks and Linux reference vet pass. These fixtures
  complement the independent real DNS-01 issuer test and automatic installation
  acceptance; real-provider and hardware acceptance remain open.
- The [2bb1a82 native workflow](https://github.com/the-luap/openuem-console/actions/runs/34551946528)
  passes on Linux amd64, Linux arm64 and Windows with the resumable installer and
  administrator completion checks. Its [ACME workflow](https://github.com/the-luap/openuem-console/actions/runs/34551946548)
  passes on both native Linux architectures with the read-only issuer preflight.
- The public DNS-01 issuer now provides `--check` for protected local input
  validation before creating state, acquiring leases, executing lego or contacting
  a provider. It returns a fixed public result and rejects conflicting issuance
  flags; the normal issuer path shares this input validation. Explicit ACME trust
  accepts complete certificate PEM blocks only, rejecting private keys, skipped
  malformed blocks, extra data and excessive certificate counts. Native race tests
  cover missing inputs, absent fresh state and unchanged state while an issuer owns
  both leases. The actual-command fixture checks preflight before exercising DNS-01,
  retained-account retry, ARI renewal, gateway reload and clean shutdown; the Linux
  arm64 run passes in 18.53 seconds. The actual scratch runtime also passes offline
  preflight with only its read-only configuration mount, plus the image boundary
  audit. Native race tests and vet pass. The version-2 installer uses this preflight;
  real provider acceptance remains open.
- The [reference installation controller](reference-installation.md) reviews exact
  local image IDs, protected public TLS/release inputs, account/directory identity
  and the seven-service definition before provisioning. Its private journal and
  lease preserve setup jobs across controller interruption; retained keys and
  completed artifacts are verified before resuming. It validates existing runtime
  boundaries before starting services, waits for database/broker/service readiness,
  and uses the read-only administrator gate to retire the initial-password mount
  after the real password workflow. Controlled acceptance covers fresh CLI setup,
  wrong-review rejection without writes, live controller termination after PKI,
  stopped-database recovery, interrupted console replacement including an absent
  replacement, literal-dollar preservation through Compose rendering and runtime
  arguments, and completed retries without service recreation. These are owned
  isolated containers with synthetic inputs; graphical setup,
  signed release distribution, general upgrade/restore and external/device
  acceptance remain open.
- The [876d877 native workflow](https://github.com/the-luap/openuem-console/actions/runs/34547939271)
  passes on Linux amd64, Linux arm64 and Windows with the administrator completion
  gate. Its [Native Apple workflow](https://github.com/the-luap/openuem-console/actions/runs/34547939306)
  also passes.
- The production reference probe now provides a read-only first-administrator
  completion gate for the guided installer. It verifies the retained installation
  ID and JWT/master proofs, original bootstrap account and markers, current global
  administrator grant, completed password registration and replacement of the
  initial password. It uses a repeatable-read, read-only transaction and never
  creates missing schema or repairs state. Protected, unambiguous verify-full
  database inputs exclude inherited search paths, fallback hosts and client keys.
  Actual PostgreSQL tests cover status-only bypass, missing markers/account/grants,
  changed credentials, cancellation, write rejection and missing-schema retention;
  stored Argon2 parameters are bounded before comparison. Fresh and interrupted
  broker-maintenance reference fixtures run the actual image before and after
  the real administrator password workflow, then retire the password mount and
  pass the remaining complete lifecycle. Local Linux arm64 integration, native
  readiness/CLI race tests, Windows build/vet, five-command image smoke and the
  strict probe image audit pass. The reference installation controller now wires
  this gate into fresh-install completion; broader setup/restore work remains open.
- The [76bd587 native workflow](https://github.com/the-luap/openuem-console/actions/runs/34546675423)
  passes on Linux amd64, Linux arm64 and Windows, including complete public claim
  and signed-bootstrap delivery. The broader
  [db236a4 Native Apple workflow](https://github.com/the-luap/openuem-console/actions/runs/34544456740)
  also passes, including the release-command protected database input tests.
- Public reference enrollment now also verifies the production bootstrap key
  document, signed configuration and portal invitation download over the gateway.
  Bootstrap trust comes from the authorized HTTPS origin; release keys remain
  independently provisioned. The verified configuration binds scope, invitation,
  target and synthetic package/agent bytes, rejecting swapped key roles and a
  different architecture. Repeated file GET/HEAD requests preserve the single
  invitation use. The same bootstrap public identity survives complete restart
  and interrupted broker maintenance; release withdrawal denies the portal's
  enrollment files and configuration while public key discovery remains usable.
  Both complete fixture modes pass locally on Linux arm64, along with Linux amd64
  cross-compilation, affected vet and runner syntax checks. These files are tested
  with explicitly non-executable payloads; native signing, installation and
  activation remain separate acceptance requirements. Setup documentation now
  also accurately describes the first-password mount's temporary bootstrap use.
- The reference release mode now claims its synthetic device through the actual
  public HTTPS gateway using the shared endpoint client. A trusted setup probe
  creates the release-bound invitation; the edge client receives only public trust
  and its own protected files, generates and persists both endpoint keys, and
  validates the returned certificate against its CSR and authorized WSS origin.
  Repeated metadata GET/HEAD and an invalid proof do not consume the invitation;
  identical proofs recover the same identity, while different keys cannot reuse
  its single use. Full restart preserves claim recovery. Exact release withdrawal
  denies downloads, metadata and claims before the independent WSS device
  revocation test. Fresh and interrupted historical-grant maintenance fixtures
  pass locally on Linux arm64; Linux amd64 cross-compilation, affected vet and
  runner syntax checks also pass. Existing Linux amd64/arm64 CI invokes both
  modes. Inventory remains explicit scoped fixture preparation; this is public
  protocol integration, not native installer execution or hardware acceptance.
- The [002424f native workflow](https://github.com/the-luap/openuem-console/actions/runs/34545260455)
  and its [pull-request run](https://github.com/the-luap/openuem-console/actions/runs/34545261089)
  pass on Linux amd64, Linux arm64 and Windows, including the separate release
  image, gateway downloads, retained approval and exact withdrawal.
- The separate [release admission image](agent-release-operations.md#separate-release-job-image)
  now runs the actual protected-file CLI as an unprivileged scratch job. The
  reference fixture stages a synthetic signed manifest and non-executable payload,
  admits it through the provisioned PostgreSQL TLS connection, and verifies gateway
  HEAD, full and ranged downloads against the signed size/hash. Approval survives
  the complete service restart and historical-grant maintenance with interrupted
  resume. A final exact-digest withdrawal, using only database URL/public CA mounts,
  makes subsequent public downloads return 404. Both complete fixture modes pass
  locally on Linux arm64, as do the strict image filesystem/startup audit, affected
  vet and workflow checks. Linux amd64/arm64 CI builds and exercises this image.
  The fixture does not produce or execute a natively signed installer; release
  signing/notarization and endpoint activation remain distinct acceptance
  requirements. Public protocol claim composition is covered by the extension
  described below.
- The [73d5e57 native workflow](https://github.com/the-luap/openuem-console/actions/runs/34543954735)
  passes on Linux amd64, Linux arm64 and Windows, including generated independent
  administrator trust, bootstrap mount retirement and retained broker maintenance.
- The [release admission command](agent-release-operations.md) now accepts
  `--dburl-file` and `OPENUEM_AGENT_DATABASE_URL_FILE` through the shared protected
  credential reader. Raw/file conflicts, missing or damaged files and argument
  errors fail without revealing input values; offline signed-manifest inspection
  does not load database credentials. Actual isolated PostgreSQL admission, show
  and withdrawal pass using only the protected connection file, preserving the
  approved catalog checkpoint and audit path. CLI/offline/privacy race tests,
  native and Windows vet, and Windows cross-build pass. Native Windows command
  checks and the PostgreSQL race workflow include these paths. Signed package
  distribution and complete release-pipeline integration remain open.
- The [2d89af1 native workflow](https://github.com/the-luap/openuem-console/actions/runs/34543092044)
  passes Linux amd64, Linux arm64 and Windows, including actual first-password
  mount retirement before the fresh and retained-maintenance reference sequences.
- The reference setup now obtains independent administrator trust from the actual
  retained PKI initializer at
  [`633bc7b`](https://github.com/the-luap/openuem-cert-manager/commit/633bc7bb0dc34c1240a72a9df25c74ad19451885).
  Its opt-in administrator root is self-signed with a distinct key, and exports
  only public trust to the console. Both CA keys and provisioning journals stay
  outside runtime mounts. Exact retries, interrupted export, committed loss,
  incompatible mode changes and backend cross-signing rejection pass, including
  actual TLS administrator admission/backend-identity denial and the distribution
  smoke. The [native PKI workflow](https://github.com/the-luap/openuem-cert-manager/actions/runs/34543538601)
  and [broker compatibility workflow](https://github.com/the-luap/openuem-cert-manager/actions/runs/34543538465)
  pass. The console pins this revision and removes synthetic administrator-CA
  generation from its reference probe. Fresh and retained broker-maintenance
  acceptance pass locally on Linux arm64 with the generated trust, bootstrap mount
  retirement, preserved login/device/command state and live WSS revocation.
  Administrator client issuance, account binding, deployed certificate status,
  enterprise CA import and rotation remain open; password login remains the
  implemented first-account path. Current console integration CI remains required.
- The [f8339b5 native workflow](https://github.com/the-luap/openuem-console/actions/runs/34542668163)
  passes Linux amd64, Linux arm64 and Windows, including both fresh and historical
  broker-grant maintenance fixtures, interrupted CLI resume and retained commands.
- The reference runtime now omits the initial administrator password. A separate
  [`compose.bootstrap.yaml`](../deploy/reference/compose.bootstrap.yaml) mounts it
  only for first-account creation. The actual container fixture completes the
  required password replacement, joins gateway/console shutdown, recreates the
  console without the bootstrap mount or setting, and proves retained login while
  preserving the original protected recovery file. Both fresh and historical-grant
  maintenance sequences pass locally on Linux arm64, including subsequent restart,
  pending-command retention and WSS revocation. The maintenance validator accepts
  the initialized layout and the previous exact bootstrap mount layout. Full
  guided installation and current-commit native CI remain required.
- The [reference maintenance controller](reference-maintenance.md) now reviews
  and resumes the known retained broker worker-grant migration across the actual
  seven-service project. It binds the rendered Compose model, exact local images,
  protected mount recipients and container identities to an explicit review;
  private leased journals record joined shutdown, configuration publication,
  broker recreation, bounded readiness and completion. PostgreSQL remains running.
  Actual Linux arm64 distribution acceptance passes with the historical initializer:
  the current worker rejects its old grant, then maintenance preserves a synthetic
  device identity, administrator access, one pending message and its consumer
  across interruption immediately after publication and CLI resume. Stale reviews
  and competing leases are rejected; completed retry preserves container IDs and
  start times. Fresh current configuration returns unchanged without operation
  state, followed by the complete retained restart and live WSS revocation checks.
  The separate minimal readiness image checks actual worker subscription boundaries,
  private health and pinned gateway discovery. Go race/TLS/broker/cancellation,
  Python protected metadata and failed-shutdown recovery, native Linux probe,
  setup smoke, image audit, affected vet and Windows cross-build checks pass locally.
  CI now covers fresh and retained-maintenance fixtures on Linux amd64/arm64 and
  portable readiness tests on Windows. Current-commit CI remains required.
  General image upgrade/rollback, full installation/restore orchestration,
  external ingress and physical endpoint acceptance remain open.
- The preceding [d4c7a87 console workflow](https://github.com/the-luap/openuem-console/actions/runs/34538874140)
  passes Linux amd64, Linux arm64 and Windows. The pinned PKI revision `b06bac1`
  passes both its [broker upgrade workflow](https://github.com/the-luap/openuem-cert-manager/actions/runs/34538787901)
  and [private PKI workflow](https://github.com/the-luap/openuem-cert-manager/actions/runs/34538787915).
- The PKI component's [broker upgrade c3a5943](https://github.com/the-luap/openuem-cert-manager/commit/c3a5943431c4c6542cdfc38e9eb94405ff7cab49)
  adds a read-only review plan and a hash-bound, resumable migration of the known
  preceding worker grant. It retains all six service seeds, TLS/listener settings,
  storage path and original configuration; private journal/staging files and an
  OS directory lease protect publication. Tests cover completed-write interruption,
  rollback/damage rejection, concurrency, cancellation and pre-publication changes.
  The actual historical initializer, upgrade command and stock NATS process pass
  isolated Linux arm64 acceptance: the old grant rejects hardware subscriptions,
  the new grant accepts all three added subjects while rejecting a broader wildcard,
  and the same persisted message and durable consumer survive a clean restart.
  Further commands enter the retained consumer. Unit/CLI/race, private PKI, native
  process, vet and Windows cross-build checks pass locally. The [c3a5943 broker workflow](https://github.com/the-luap/openuem-cert-manager/actions/runs/34538538635)
  also passes Linux amd64/arm64 process upgrades and Linux/Windows setup checks.
  Console CI pins the `b06bac1` documentation follow-up and the full reference
  lifecycle passes with the new initializer and an unchanged preview of fresh state.
  General image maintenance, complete restore and physical device
  acceptance remain open.
- The [aadf9c3 native workflow](https://github.com/the-luap/openuem-console/actions/runs/34537016525)
  passes on Linux amd64, Linux arm64 and Windows, including generated retained
  protocol keys, input bind-alias rejection and the full separate reference
  composition on both Linux runners.
- The [protocol key provisioner](protocol-keys.md) now supplies retained,
  independent Windows authority encryption and desktop bootstrap signing keys.
  It verifies an existing complete installation without writing to that input,
  binds output to its exact credential manifest, preserves completed writes on
  retry and rejects damaged state or replacement foundation credentials.
  Its separate scratch distribution command is integrated into the seven-service
  reference setup with only the two exported files mounted into the console.
  Lifecycle/crypto, concurrency, cancellation, CLI privacy and read-only-source
  tests pass, including race checks; the actual container smoke and reference
  lifecycle pass locally on Linux arm64. A reproduced bind-alias input mutation
  is prevented by directory identity checks and covered by the container fixture.
  This removes synthetic Windows/bootstrap key generation from the reference
  probe. Public TLS, administrator authority, release trust and full guided
  installation/restore acceptance remain separate work.
- The preceding [0b716ae native workflow](https://github.com/the-luap/openuem-console/actions/runs/34535362093)
  passes on Linux amd64, Linux arm64 and Windows, including the full separate
  reference composition on both Linux runners.
- The [reference composition](reference-composition.md) now runs seven separate
  distribution containers with explicit private networks and credential mounts.
  Its isolated Linux arm64 acceptance passes generated setup/database bootstrap,
  gateway administrator source admission and forwarding-header rejection,
  distinct Apple/desktop/Windows public listeners, real WSS broker authorization,
  scoped worker mutation and durable command-consumer reconciliation. Actual
  runtime inspection verifies exact mount recipients, privileges, network
  membership, no published ports and no raw encryption/database environment
  values; public clients cannot connect directly to private backend sockets.
  All seven services stop successfully and restart with retained administrator,
  device and JetStream state. Revocation disconnects a live WSS session and
  subsequent connection receives an explicit broker authorization denial.
  The publication overlay is validated as TCP 443 to gateway 8443 but is not
  started by the fixture. Guided installer/provider/administrator-authority
  setup, host firewall/IPv6 acceptance, restore and physical devices remain open.
- Composition exposed a stale shared-library pin in the broker initializer:
  its worker grant omitted `hardware`, `recovery` and `rotation`. The initializer
  [update e7525ad](https://github.com/the-luap/openuem-cert-manager/commit/e7525ad161cc06323e8cc7573f1d6525379d88a7)
  uses the current protocol and adds an exact worker-subscription regression
  that fails with the old pin and passes with the update. Broker/race, private
  PKI/CLI, vet and Windows cross-build checks pass locally. Console CI pins this
  revision for all private setup tests. Installed broker files remain immutable
  on ordinary retry; existing-configuration upgrade/reload is still separate work.
- Native Windows management now accepts a protected
  `WINDOWS_MDM_MASTER_KEY_FILE`, preserving the canonical Base64 key format and
  rejecting conflicting sources, missing/unprotected files and malformed input.
  File-input, existing configuration/lifecycle tests, the full reference listener
  startup, Linux/Windows vet and Windows cross-build pass. The native console
  workflow includes the new protected-file tests. The preceding
  [81ddd66 native workflow](https://github.com/the-luap/openuem-console/actions/runs/34531904715)
  passes on Linux amd64, Linux arm64 and Windows.
- The [private broker reference image](broker-container.md) builds the stock
  NATS 2.14.6 command from this repository's pinned module graph into a non-root
  scratch runtime. The exact executable/license audit and offline version/help
  checks pass. The console PostgreSQL fixture now uses this separate distribution
  process, authenticates a provisioner through TLS/NKey, creates a command stream,
  and proves retained JetStream configuration and administrator state across
  clean broker/console SIGTERM restarts. The complete Linux arm64 PostgreSQL
  suite and affected vet checks pass locally. Native amd64/arm64 CI now requires this distribution and process
  boundary; complete multi-container installation and restore acceptance remain
  open.
- The [console reference image](console-container.md) now retains CGO/SQLite
  support with pinned Go and Distroless runtime inputs, a non-root account,
  versioned static assets, public trust and explicit writable cache/auth-log
  mounts. Its audit proves unchanged base files and exact application assets;
  the offline runtime/SQLite smoke passes. The image-extracted
  console process passes isolated PostgreSQL startup using generated installation
  secrets, actual private PKI and broker initialization, pinned gateway TLS,
  direct-backend rejection, first-password replacement and retained state across
  SIGTERM restart. The fixture deliberately blocks the initial catalog connection
  at an offline proxy on each start. Foreground startup now registers signals
  before starting listeners and cancels release requests through its shutdown
  context; the preceding version fails this process regression and the new
  version passes. Request cancellation, the complete PostgreSQL suite (including
  all three private services), Windows cross-build and Linux/Windows vet pass
  locally. The fixture keeps a separate synthetic
  administrator CA and does not claim certificate login/OCSP or physical-device
  acceptance. Native CI now requires these image and process checks. Complete
  installer orchestration, persistent log operations and administrator authority integration
  remain open.
- The preceding private service distribution pipeline
  [passes](https://github.com/the-luap/openuem-console/actions/runs/34526398961),
  as does the worker's [image/process pipeline](https://github.com/the-luap/openuem-worker/actions/runs/34526227432).
  [Native console CI for revision 7862a7e](https://github.com/the-luap/openuem-console/actions/runs/34527193093)
  passes on Linux amd64, Linux arm64 and Windows, including the complete Linux
  foreign-UID bind-mount denial, private database bootstrap and restart gates.
- [Reference database ownership](reference-database-ownership.md) now has a
  container acceptance fixture using the host's non-root UID/GID for the actual
  installation, database credential, private PKI and bootstrap distribution
  images plus the official pinned PostgreSQL entrypoint. Local macOS/Docker
  arm64 checks pass for protected creation/exact retries, unchanged ownership
  and source contents, verified TLS bootstrap, cleartext denial, private Unix
  socket access, clean stop/restart and retained journal verification. Native
  Linux CI additionally requires denied access to a bound password by another
  runtime UID; Docker Desktop bind semantics cannot establish that negative
  Linux gate. No runtime receives the offline private CA or installation source.
  This is synthetic installation groundwork; dedicated account creation,
  persistent ownership preparation and full reference/restore acceptance remain open.
- [Private service images](private-service-containers.md) now provide separate
  unprivileged scratch runtimes for authorization, command provisioning and the
  individual worker, with pinned builders and restricted build contexts. The
  image boundary checks pass for the actual default UID, read-only root, offline
  help/rejected startup, fixed entrypoint, no exposed ports and exact permitted
  filesystem. The three image-extracted executables pass the isolated native
  Linux arm64 PostgreSQL/private TLS process fixture (6.69 seconds), including
  authorization/revocation, command reconciliation, authenticated Windows/Mac
  worker requests and SIGTERM shutdown. Console CI pins
  [worker revision 4a5462e](https://github.com/the-luap/openuem-worker/commit/4a5462e832d9896816a7759af9a9a9453fc302c9)
  and now extracts the actual service image binaries. Worker CI likewise tests
  its distribution executable and audits native amd64/arm64 images. These checks
  do not yet prove full multi-container composition, automatic mount ownership,
  console/admin authority integration or complete installation/restore acceptance.
- Protected service credential files now cover the authorization service, command
  provisioner and individual agent worker, using the shared reader at
  [revision 87aa1bd](https://github.com/the-luap/openuem-nats/commit/87aa1bdf56ea7776f170c9d09de870b30be7d263).
  Selected files have bounded contents, private Unix permissions or Windows ACLs,
  read-only access and fixed redacted errors; competing raw/file sources are
  rejected. The worker accepts the actual 32-byte task-field key and validates
  all input before replacing configuration. The shared library's
  [CI passes](https://github.com/the-luap/openuem-nats/actions/runs/34523652815).
  [Worker revision 4f66293](https://github.com/the-luap/openuem-worker/commit/4f6629381090c91884bec08f90c77ea1288cf9d1)
  passes Linux configuration tests, a full Windows build and affected Linux Vet
  checks. Local console secret/authorization/command race tests pass
  (2.947/3.674/3.817 seconds). An isolated native Linux arm64 PostgreSQL fixture
  runs all three actual service executables using protected file inputs against
  generated private TLS and the provisioned database (6.07 seconds). Existing
  real-broker assertions cover authorization, revocation, command queues and
  authenticated Windows/Mac worker requests, with successful SIGTERM shutdown.
  Native console CI pins that worker and requires the combined process fixture;
  worker CI also requires its executable fixture and native Windows input checks.
  The worker's [complete CI run](https://github.com/the-luap/openuem-worker/actions/runs/34525215784)
  passes. Full console Linux/Windows builds and affected Vet checks pass. The
  rebuilt bootstrap distribution binary and all private services pass the full
  isolated PostgreSQL interruption, drift, concurrency and recovery suite;
  service processes take 6.05 seconds. The existing broker restart fixture now
  observes disconnection and reconnection separately and requires a flush before
  publishing, avoiding an old transport's stale connected status after shutdown.
  The updated fixture passes ten native Linux arm64 repetitions and three race
  repetitions on macOS, and compiles for Windows.
  See the [authorization](agent-authorization-operations.md),
  [command](agent-command-operations.md), and [setup container](setup-containers.md)
  operations guides. Reference service images, mount ownership, complete topology
  and administrator authority integration remain open.
- [Separate setup container images](setup-containers.md) now distribute one
  command per unprivileged scratch image for installation secrets, database
  credentials and online database bootstrap. All three image filesystem,
  entrypoint, runtime UID and no-listener checks pass. The offline process
  fixture passes (0.03 seconds), as does initial creation/retry on a private
  Docker volume mounted below a read-only runtime root. The actual bootstrap
  distribution binary passes PostgreSQL startup/retry/SIGTERM with read-only
  credential permissions and generated private TLS (0.87 seconds); the full
  isolated PostgreSQL interruption/drift/recovery suite passes, including actual
  console schema initialization (0.40 seconds). Existing credential input
  inspection is now strictly read-only. Secret/command race tests pass
  (3.941/1.335/1.330 seconds), as does the installation CLI suite (1.453 seconds).
  Full Linux/Windows builds and affected Vet checks pass. Native CI now extracts
  the distribution binary for its PostgreSQL fixture and audits all three images.
  Automatic service ownership, full reference composition and signed release
  publication remain open.
- Private database TLS is now supplied by the certificate manager's optional,
  immutable `--database-dns` configuration at
  [revision 938ea1a](https://github.com/the-luap/openuem-cert-manager/commit/938ea1a77eba4c9eb4517db629fc42ef2f8b96ad).
  The generated PostgreSQL server leaf has distinct DNS names, a separate P-256
  key and server-only usage. Existing backend-only state keeps its exact encoding
  and cannot silently acquire database identities. PKI/command race tests pass
  (12.590/2.153 seconds), including all fourteen export interruptions, committed
  database material loss, hostname verification and rejected configuration changes.
  The actual private PKI/gateway smoke container still passes (0.30 seconds).
  Native Linux arm64 PostgreSQL uses the actual PKI executable with the actual
  database bootstrap command (0.49 seconds) and normal console schema migration
  (0.56 seconds). Both validate TLS, password separation and process/restart
  behavior. Console CI pins that certificate-manager revision for native
  amd64/arm64 acceptance. The certificate manager's
  [native PKI CI](https://github.com/the-luap/openuem-cert-manager/actions/runs/34521690446)
  passes on amd64/arm64, as does its existing broker setup workflow.
  The console's [combined PKI/database pipeline](https://github.com/the-luap/openuem-console/actions/runs/34521873749)
  also passes on native Linux amd64/arm64 and Windows.
  Full reference wiring, service mount ownership,
  administrator/device authorities and restore/migration acceptance remain open.
- [Resumable database bootstrap](database-bootstrap.md) now creates the production
  application role and database from completed protected credentials. A private
  journal and PostgreSQL control table bind the cluster and original object OIDs;
  the pending role cannot log in and the staged database cannot accept connections.
  Final name, private database grants, login, connections and SQL readiness commit
  together. Isolated native Linux arm64 PostgreSQL tests pass for nine durable
  interruption points, finalization rollback, suppressed binding writes, concurrency,
  cancellation, missing/corrupt inputs, changed roles/databases/catalogs, cluster
  binding and phase reconstruction. The compiled command passes actual startup,
  restart, output privacy and blocked-query SIGTERM checks (0.38 seconds), and the
  real console model migrates/initializes the resulting database over verified TLS
  (0.32 seconds). Affected secret and command race suites pass (3.232, 1.363 and
  1.327 seconds); full Linux/Windows builds and affected Vet checks pass.
  The [native bootstrap CI](https://github.com/the-luap/openuem-console/actions/runs/34520905792)
  passes on Linux amd64/arm64 and Windows, including the full isolated PostgreSQL
  suite on Linux. Service mounts, full reference installation and
  restore/migration acceptance remain open.
- [Persistent database credentials](database-credentials.md) generates independent
  bootstrap/application passwords and a verify-full URL with explicit CA trust,
  bound to the installation and immutable deployment metadata. The offline command
  never emits credentials or changes database roles. Recovery, concurrency,
  corruption and the shared installation source tests pass under the race detector
  (26.089 seconds); command privacy/restart tests pass (1.374 seconds). An isolated
  native Linux arm64 PostgreSQL 17 process authenticates both generated roles,
  runs actual console schema migrations as the application owner and proves TLS,
  rejected role creation, password separation and hostname validation (0.90 seconds).
  The existing generated-secret administrator/router lifecycle also passes
  (11.847 seconds), as do full Linux/Windows builds and affected Vet checks.
  The original fixture's manual role/database setup is now replaced by the
  production bootstrap above. Service mounts and full
  reference installation/restore acceptance remain open. The
  [credential configuration pipeline](https://github.com/the-luap/openuem-console/actions/runs/34517852043)
  passes on native Linux amd64/arm64 and Windows.
- [Persistent installation secrets](installation-secrets.md) adds an offline
  private provisioner with a durable source and completion manifest, independent
  JWT/master/start-password values, exact resumable completed writes and no
  credential output. The console CLI and installed services accept protected
  JWT/encryption files, reject competing sources and require both keys in
  individual mode. Race tests cover corruption, concurrency, interrupted writes,
  privacy and the existing AES API (2.594 seconds); command tests pass in 1.323
  seconds. The actual PostgreSQL/router administrator lifecycle now uses generated
  credentials and passes in 4.793 seconds. Full Linux/Windows builds and affected
  Vet checks pass. An isolated unprivileged Linux arm64 process verifies the
  actual console flags, file environment inputs, installed credential selection
  and rejected legacy fallback. Native Linux amd64/arm64 and Windows
  [secret provisioning/loading CI passes](https://github.com/the-luap/openuem-console/actions/runs/34513814100).
  Explicit installation identifiers now bind independent HMAC proofs to a fresh
  database before account creation. Existing bindings cannot be bypassed by
  clearing configuration or selecting legacy mode. Exact restarts, conflicting
  initializers, marker rollback/loss and occupied registries pass PostgreSQL/race
  tests with the full administrator lifecycle (32.530 seconds). An actual Linux
  arm64 worker against disposable PostgreSQL also rejects a mode/reset downgrade
  (2.59 seconds). Console
  database URLs now also support protected file inputs with parser-error privacy,
  bounded content and no competing sources or legacy fallback. The native
  [binding configuration pipeline](https://github.com/the-luap/openuem-console/actions/runs/34514993895)
  passes on Linux amd64/arm64 and Windows. Database URL/file race tests pass
  in 28.800 seconds. Legacy binding migration, database credential provisioning,
  distribution, rotation and full reference composition remain open. The protected
  database URL [native configuration workflow](https://github.com/the-luap/openuem-console/actions/runs/34515734079)
  passes on Linux amd64/arm64 and Windows.
- [Protected first-administrator bootstrap](first-administrator-bootstrap.md)
  creates the initial account, grant, audit and retained completion binding in
  one transaction, from a bounded private file without password logging. CLI
  and installed individual service startup use it before listeners, reject
  implicit resets and preserve existing accounts, MFA and revoked privileges.
  PostgreSQL/race initializer and actual console password-route tests pass in
  4.555 seconds; shared access tests pass in 1.402 seconds. Affected PostgreSQL
  handler and webserver race suites pass in 13.430 and 1.955 seconds. Password replacement
  now requires a bounded verified session proof tied to the current credentials;
  unverified or superseded recovery codes, stale sessions and competing requests
  cannot replace a new password. The same transaction consumes recovery and
  invitation records and retires session rows; reusing the current password is
  rejected. The local email fixture sends no mail. An isolated Linux arm64 process
  checks actual startup configuration and reset rejection. Full Linux/Windows
  builds and affected Vet checks pass. Native Linux amd64/arm64 and Windows
  [configuration and protected-file CI passes](https://github.com/the-luap/openuem-console/actions/runs/34512524550).
  Secret distribution, administrator PKI, the full setup wizard
  and reference composition remain open.
  The initial protected administrator/password proof commit also passes the full
  [PostgreSQL, protocol, browser and native build workflow](https://github.com/the-luap/openuem-console/actions/runs/34512524496).
- [Individual console broker startup](individual-console-broker.md) connects the
  CLI and installed Linux/Windows service through a separate console NKey before
  listener startup, with explicit private TLS origins, no legacy fallback and no
  stream/consumer/election management. Broker command retention, restart and
  permission rejection pass the stock generated-config race fixture in 6.956
  seconds. Native handler and joined HTTP lifecycle checks pass; an isolated
  Linux arm64 process verifies the actual CLI flags without legacy broker/SFTP
  inputs, and full Linux/Windows builds pass. Complete affected PostgreSQL/race
  suites pass (handlers 13.324 seconds, webserver 1.895 seconds), as does Vet.
  The native [Linux amd64/arm64 and Windows pipeline](https://github.com/the-luap/openuem-console/actions/runs/34508769503)
  and matching [pull-request pipeline](https://github.com/the-luap/openuem-console/actions/runs/34508777009)
  also pass on all three platforms.
  Direct file/log/remote operations
  are denied and their UI actions hidden; unsupported legacy service subjects
  return synchronous errors. Separate internal notification/certificate/catalog
  integration, complete reference composition and physical acceptance remain.
- [Private backend PKI initialization](https://github.com/the-luap/openuem-cert-manager/blob/272d58538f2854efd65cbba81c3bbf469ee3e595/docs/private-pki.md)
  adds a protected CA and distinct console, broker and gateway identities, retained
  original key/certificate records, configuration binding, exclusive initialization,
  immutable exports and a final readiness manifest. Interrupted exports preserve
  exact identities; missing committed keys, foreign data, corruption, expiry and
  changed configuration stop initialization. Native macOS race/Vet and complete
  Linux/Windows builds pass. The actual initializer and actual console gateway
  pass a network-isolated Linux arm64 process fixture in 0.17 seconds, covering
  generated private TLS, exact gateway pins, public admin denial and shutdown.
  Its separate scratch runtime has no exposed port, shell or credential material.
  Gateway `1f7a657` fixes explicit CA-issued client selection under exact-leaf
  issuer hints; the real NATS/race suite passes in 5.524 seconds. Both native
  [gateway image jobs](https://github.com/the-luap/openuem-console/actions/runs/34505625003)
  and [ACME issuer jobs](https://github.com/the-luap/openuem-console/actions/runs/34505625021)
  pass. The certificate-manager's new native
  [amd64/arm64 PKI pipeline](https://github.com/the-luap/openuem-cert-manager/actions/runs/34506116559)
  and existing [Linux/Windows broker pipeline](https://github.com/the-luap/openuem-cert-manager/actions/runs/34506116623)
  also pass;
  full reference composition, first-administrator setup, other authority roles
  and coordinated private certificate renewal remain open.
- ACME renewal diagnostic follow-up: the earlier arm64
  [fixture run](https://github.com/the-luap/openuem-console/actions/runs/34512528587)
  timed out waiting for daemon renewal. The subsequent unchanged ACME code passes
  [both native jobs](https://github.com/the-luap/openuem-console/actions/runs/34513812819).
  Three isolated Linux arm64 repetitions also pass (8.84, 11.30 and 9.93 seconds).
  The fixture now preserves sanitized daemon output after process/output joining
  on failure. The intermittent timeout's cause remains unconfirmed; this is
  improved evidence collection, not a claimed renewal fix.
- [Automatic gateway DNS-01](gateway-acme.md) adds a separate pinned lego v5.4.1
  runtime and issuer executable with explicit protected provider configuration,
  bounded attempts, ARI-aware periodic renewal and atomic validated publication.
  Paired installation bindings and a durable original account-key fingerprint
  prevent silent replacement after partial restore; permanent leases exclude
  competing writers. Private provider/account data stays outside the gateway
  mount. Native macOS race tests and Vet pass, as do complete Linux/Windows
  builds. The actual issuer/lego/Pebble Linux arm64 container fixture passes
  provider failure, real DNS validation/cleanup, retained account, ARI renewal,
  gateway handoff and SIGTERM/restart in 9.75 seconds, without external networking.
  The Compose component validates and publishes no ports. Both native amd64/arm64
  [issuer CI jobs pass](https://github.com/the-luap/openuem-console/actions/runs/34503036882)
  for `735c310`, including race/Vet, the actual DNS-01 fixture and the runtime
  filesystem/entrypoint checks. The same head also passes both native
  [gateway container jobs](https://github.com/the-luap/openuem-console/actions/runs/34503041557).
  The prior console head `dbdf906` also passes the complete
  [Native Apple workflow](https://github.com/the-luap/openuem-console/actions/runs/34497358714).
- [Public gateway TLS renewal](gateway-operations.md#public-tls-renewal) loads complete certificate/key generations without restarting HTTP/2 or authenticated NATS streams. Invalid, partial, mismatched or expired material cannot replace the active pair; new handshakes, including session resumption, recheck its lifetime. Tests cover issuer constraints, optional client certificates, concurrent handshakes, native archive switches, bounded files and joined watcher recovery. The [separate minimal container](gateway-container.md) adds a pinned builder, source-only build context and unprivileged runtime; an isolated Linux arm64 process fixture passes actual-command TLS renewal, source-network denial and SIGTERM shutdown. Both native amd64/arm64 [image CI jobs pass](https://github.com/the-luap/openuem-console/actions/runs/34497033584). Live DNS/ACME provider operations and a complete one-port reference installation remain open.
- [Desktop identity renewal](desktop-identity-renewal.md) pins shared registry
  `06ec5c5` with persistent preparation, candidate-key confirmation, permanent key
  ownership, exact generation retries and bounded broker-session handoff. Its
  [CI](https://github.com/the-luap/openuem-nats/actions/runs/34471335722) passes native
  Windows and Linux/PostgreSQL/race/fuzz checks. The console acknowledges exact
  FileVault receipts only after returned-key retention or verified uncertainty
  resolution, final state and audit in the same transaction. A synthetic Mac
  integration preserves its recovery key and original receipt across certificate
  activation and registers a fresh recipient epoch. Registry-audit failure rolls
  back the complete key-processing transaction; partial upgrades retain pending
  material. Shared-library full race, Vet and Linux/Windows builds pass, with
  449,004 confirmation wire fuzz executions. Final focused console integration
  passes in 5.008 seconds; complete Apple/desktop race suites pass in
  262.823/19.407 seconds, with authorization/command/protocol subpackages also
  passing. Affected handlers pass in 1.981 seconds. Vet, module consistency and
  complete Linux/Windows builds pass. The subsequent HTTPS client/gateway/console
  integration recovers a lost activation response after client reconstruction,
  enforces all current/candidate proofs and typed conflicts, and preserves delivered
  recovery work until signed completion. Four-request capacity and shutdown tests
  leave no partial issuance, activation, reservation or audit. Full transport race
  tests pass (desktop 28.950 seconds; authorization 7.027; command 3.589; protocol
  1.176; gateway 3.154), as do Vet, module consistency and Linux/Windows builds.
  Response fuzzing passes 459,737 executions. Both console CI runs for `3a49b79`
  pass. Agent `4b782a1` adds immutable native candidate/issuance/decision/activation
  records, prevents old-key fallback during confirmation uncertainty, retains
  original installation anchors and verifies historical FileVault receipts after
  source expiry. Local full native macOS protected-store/runtime/command/service
  race checks, Vet, module consistency and Linux/Windows/macOS builds pass; its
  [journal CI](https://github.com/the-luap/openuem-agent/actions/runs/34476393712) passes.
  Subsequent work adds authoritative cancellation, automatic installed-service
  scheduling, joined handoff/reconnect, native process ownership and stoppable
  startup recovery; agent `cdffd2c` passes
  [all-platform CI](https://github.com/the-luap/openuem-agent/actions/runs/34486258522).
  Agent `f5fc83a` additionally requires signed Windows readiness from the exact
  live Local System SCM process before activation reports initialization. The
  private named-pipe proof survives restart and joins before key release;
  [all-platform CI passes](https://github.com/the-luap/openuem-agent/actions/runs/34493137911).
  Follow-up `12fac05` passes [all three platform jobs](https://github.com/the-luap/openuem-agent/actions/runs/34493655438),
  including explicit assertions that the required Windows readiness and recovering
  SCM fixtures execute successfully rather than skip.
  Historical server reconciliation now admits fresh signed current-key checks
  bound to exact old rotation receipts, including erased return keys. The console
  preserves pending validations, retries with bounded backoff and commits key
  verification, acknowledgement and audit together. Missing/changed proof, key,
  authority or restore evidence cannot release renewal. Production release
  integration, CA/master-key rotation and physical acceptance remain open.
- [Encrypted database backup and recovery](encrypted-backup-restore.md) adds a
  standalone CLI with separate age recipients for database and recovery keys,
  protected streaming/staging, authenticated pair binding and confirmed empty
  destinations. Real PostgreSQL restores retain all schemas, large objects,
  sequences and immutable guards. Existing synthetic Apple, Windows and desktop
  identities remain usable, including pending profile/CSP work and exact retries.
  CLI, malformed/canceled input, child privacy, destination guards and failed
  transaction rollback are covered; uncertain restore outcomes preserve prepared
  keys without claiming completion. CI includes Linux database/platform drills
  and native Windows private-file/CLI boundaries. Final local recovery/CLI race
  suites pass in 6.049/1.748 seconds; platform drills pass in 2.854/2.318/2.098
  seconds. Complete Apple/Windows/desktop regression passes in
  247.525/162.006/19.527 seconds. Fuzzing passes 861,386 executions; Vet, module
  consistency and complete Linux/Windows builds pass. Native Windows recovery
  checks also pass in CI. The initial Linux run lacked the PostgreSQL 17 client
  repository; the workflow now configures official signed PGDG explicitly.
  Both corrected workflows for `c5336c3` pass:
  [push](https://github.com/the-luap/openuem-console/actions/runs/34463014418) and
  [pull request](https://github.com/the-luap/openuem-console/actions/runs/34463018453).
  Physical recovery, deployment activation, CA/master-key rotation and the full
  PKI-01 package remain open.
- [Native Windows audit integration](native-windows-audit.md) adds twelve original
  Windows sources to scoped search and metadata-only exports. Existing retention
  policies and pending previews remain Windows-disabled on upgrade. Explicit
  organization preview/confirmation enables bounded cleanup guarded by immutable
  transaction receipts bound to event IDs; later-source failure rolls back the whole policy
  batch. Original command, packet and observation evidence remains protected.
  The shared audit PostgreSQL/race suite passes in 3.909 seconds, real console
  routes in 12.598 seconds, startup in 1.918 seconds and audit views in 2.412
  seconds. The full Windows PostgreSQL/race suite passes in 161.787 seconds.
  Vet and complete Linux/Windows builds pass.
  Browser checks cover nine responsive layouts, a 500-event native JSON download,
  keyboard opt-in confirmation and disabling cleanup. Both full workflows pass
  for `26ee438` ([push](https://github.com/the-luap/openuem-console/actions/runs/34457649525),
  [PR](https://github.com/the-luap/openuem-console/actions/runs/34457653660)).
  Payload retention, production-scale operation and full roadmap acceptance remain
  open.

- [Windows CSP evidence exports](native-windows-csp-export.md) add scoped,
  revision-bound native downloads of original intent, current results and all
  or selected historical snapshots. They preserve partial/complete distinctions,
  authenticate every included observation, bound memory and concurrent preparation,
  and release bytes only after the export audit commits. Missing lifecycle proof
  now rejects altered initial command metadata in shared result readers and before
  dispatch; repeated blocking preserves its prior authenticated revision.
  The full Windows PostgreSQL/race suite passes in 166.014 seconds; final
  console/handler tests pass in 15.303 seconds and views in 4.429 seconds.
  Nine responsive browser views and three native keyboard downloads pass.
  Vet and Linux/Windows builds pass. The full PR workflow for `d3bec86` passes;
  its push workflow exposed timestamp-dependent sizing in a test. That fixture
  now allows variable audit metadata while keeping exact buffer-boundary tests;
  twenty PostgreSQL/race repetitions pass in 12.077 seconds.
  Payload retention, physical acceptance and the full WIN-02 scope remain open.

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
  passes 502,874 executions. Both complete workflows pass for `52cc010`
  ([push](https://github.com/the-luap/openuem-console/actions/runs/34414811751),
  [pull request](https://github.com/the-luap/openuem-console/actions/runs/34414816527)).
  Scheduled group rollout, console/production wiring, continuous and
  asynchronous reconciliation, actual update/restart results and hardware
  acceptance remain open; verified policy values do not prove patch installation.
- Windows update compiler version 2 partitions verification into ordered batches
  of three Config/Result pairs. All 13 settings complete within the default
  5,000-byte response budget in synthetic apply, drift and removal exchanges;
  configuration remains a single Atomic group. Completed partial observations
  and earlier errors survive later batches, with per-batch receipt times and a
  15-minute collection window. Queue admission reserves all generated steps.
  Migration 007 preserves version-1 command trees, immutable ciphertext and
  idempotent retries. The full PostgreSQL 17/race suite passes in 69.105 seconds
  at 85.5% coverage; extended compiler fuzzing passes 23,726 executions. The real
  loopback TLS test verifies all seven steps. Vet and formatting pass; full CI
  for batching commit `293f062` passes in both workflows
  ([push](https://github.com/the-luap/openuem-console/actions/runs/34416153591),
  [pull request](https://github.com/the-luap/openuem-console/actions/runs/34416160052)).
- [Windows update ring revisions and explicit cohorts](native-windows-update-rings.md)
  add reusable scoped policies, optimistic revision checks, enabled/disabled
  revisions and immutable history. Atomic cohort assignments retain exact
  normalized targets and source revisions, with encrypted provenance checked at
  device delivery/read/replay. Historical removal remains available after ring
  changes. Concurrent retry, edit, multi-device rollback, audit/source integrity,
  migration and full ring-bound TLS exchanges are tested. Target fuzzing passes
  213,552 executions. The full PostgreSQL 17/race suite passes in 73.283 seconds
  at 84.4% package coverage; Vet and formatting pass. Full CI for ring commit
  `3c75b00` passes in both workflows
  ([push](https://github.com/the-luap/openuem-console/actions/runs/34417747091),
  [pull request](https://github.com/the-luap/openuem-console/actions/runs/34417751680)). Dynamic
  group selection, promotion gates, console wiring and actual patch/restart
  acceptance remain open.
- [Scheduled Windows ring activation](native-windows-update-schedules.md) stores
  immutable source revisions, reviewed cohorts and absolute activation windows.
  The bounded worker rechecks live creator/device/ring eligibility, activates
  each plan once, persists queue backoff and retires invalid/expired intent.
  Savepoint rollback removes all cohort work if admission or either final audit
  exceeds its window. Protected source proof connects later device results to
  the activated plan. Deadline, cancellation-lock, concurrent worker, cap,
  corruption-isolation, restart and migration tests pass; the real TLS exchange
  now uses scheduled activation. The full PostgreSQL 17/race suite passes in
  80.271 seconds at 83.6% package coverage; Vet and formatting pass. Both complete
  workflows pass for scheduling commit `8bb65fb`
  ([push](https://github.com/the-luap/openuem-console/actions/runs/34419443928),
  [pull request](https://github.com/the-luap/openuem-console/actions/runs/34419447259)).
  Console wiring, dynamic groups and patch-based promotion
  gates remain open; activation timing does not control the Windows reboot time.
- [Native Windows listener and gateway](native-windows-operations.md) register
  exact discovery/XCEP/WSTEP/SyncML endpoints, bounded request admission and
  direct or pinned gateway TLS. The server initializes the encrypted store after
  access migrations, rejects partial setup and owns schedule-worker startup,
  retry and cancellation. Real TLS/PostgreSQL tests exercise enrollment/retry,
  scheduled full-policy delivery, effective-value evidence, resumed TLS and
  revocation through both gateway legs. Routing, forwarded identity, admission,
  lifecycle, migration and persisted-credential restart tests pass. The full
  local PostgreSQL 17/race suite passes (Windows 88.587 seconds, 83.7% coverage;
  route classifier 100%; gateway 90.8%; shared identity 92.8%), including the
  existing server reminder lifecycle. Vet, formatting and Linux/Windows builds
  pass. Both complete workflows pass for listener commit `85cac95`
  ([push](https://github.com/the-luap/openuem-console/actions/runs/34421236660),
  [pull request](https://github.com/the-luap/openuem-console/actions/runs/34421239217)).
  Enrollment/device console evidence follows below; command/update console
  workflows and physical Windows acceptance remain open.
- [Native Windows enrollment/device console](native-windows-console.md) adds
  confirmed organization CA creation, one-time enrollment credentials, invitation
  revocation, paged site inventory, device details and audited access revocation.
  Shared inventory includes separate native identities with exact site links,
  enrollment-only status and no invented last contact. Live transaction scope,
  site moves, organization grants, audit rollback, concurrent revocation, replay
  denial, bounded CSRF forms, escaped output and real session routes are tested.
  Owned loopback browser flows cover CA creation, invitation creation, GET secret
  absence and revocation at 390/768/1440 pixels. The full Windows PostgreSQL/race
  suite passes in 84.932 seconds at 83.7% coverage; handler, shared view and router
  tests, Vet and Linux/Windows builds pass. The initial `f7a2d6e` workflows failed the gateway schedule fixture
  because its protected polling read could lock out the worker until the next
  15-second pass. Test correction `55ffd76` removes observer lock interference
  and verifies the protected read after activation; 20 race repetitions with
  one CPU pass. Both complete workflows pass for `55ffd76`
  ([push](https://github.com/the-luap/openuem-console/actions/runs/34424858851),
  [pull request](https://github.com/the-luap/openuem-console/actions/runs/34424861695)).
- [Windows update run console](native-windows-update-console.md) adds scoped
  history, reviewed settings, ordered delivery steps and Config/Result evidence,
  with batch receipt times and clear missing-value/source-removal semantics.
  Confirmed cancellation retires only undelivered steps; live delivery races,
  permission checks and audit rollback retain their store boundaries. Role,
  scope, bounded form/page, CSRF, XSS and cancellation integration tests pass.
  Browser form acceptance found and corrected an opaque-Origin interaction:
  form pages now retain the origin-only referrer policy required by the shared
  CSRF check. Partial drift, verified and removal views preserve historical
  meaning at 390/768/1440 pixels. Handler and view race tests, Vet and both
  builds pass. Both complete workflows pass for `9f33aae`
  ([push](https://github.com/the-luap/openuem-console/actions/runs/34425352621),
  [pull request](https://github.com/the-luap/openuem-console/actions/runs/34425355677)).
- Windows typed policy forms expose all 13 compiler-supported settings, preserving
  unset values, explicit zero and false. Validated preview/edit steps do not queue
  work; confirmed apply/removal calls retain stable request UUIDs and immutable
  run history. A fresh permission check denies lost authority after preview.
  Real console/PostgreSQL tests cover dependent settings, draft preservation,
  scope, CSRF, replay/conflict, seven-step intent and audit rollback. Browser
  acceptance verifies correction of invalid drafts, editing from preview and
  confirmed apply/removal at 390/768/1440 pixels. The full handler/race suite
  passes in 9.673 seconds; Windows/shared views pass in 1.823/1.977 seconds.
  Vet and both builds pass; the complete push workflow passes for `f10b60b`
  ([run](https://github.com/the-luap/openuem-console/actions/runs/34427128033));
  its [pull-request workflow](https://github.com/the-luap/openuem-console/actions/runs/34427131094)
  also passes. The remaining WIN-02 requirements stay open.
- [Windows ring administration](native-windows-update-console.md#versioned-update-rings)
  now provides current lists, immutable history and create/edit forms with all 13
  typed settings, enabled state and exact reviewed revisions. Preview/edit never
  writes policy work; confirmed saves preserve scoped authorization, idempotency,
  concurrent-edit conflicts and full audit rollback. Conflicts retain the draft.
  Tests cover live permission loss, sibling-site isolation, bounded history/list
  pagination, disabled revisions and no queue admission from ring edits. The full
  handler/race suite passes in 8.919 seconds; Windows/shared views pass in
  1.913/1.872 seconds. Browser creation, disabling, original-history retention and
  responsive forms pass, including long-name wrapping. Vet and Linux/Windows
  builds pass. The ring PR workflow failed during Chrome startup before the
  console tests; see the linked validation record and bounded startup/diagnostic
  correction `7d80f5f`. The ring push workflow and both later cohort workflows
  pass; the latter include the startup correction. Dynamic groups, promotion
  gates and actual patch/restart evidence remain open.
- [Windows explicit cohort assignment](native-windows-update-console.md#assign-an-exact-revision-to-devices)
  adds reviewed apply/removal for 1–100 native device UUIDs and exact ring revisions.
  Preview resolves scoped device metadata; confirmed admission uses the atomic
  existing rollout service. Protected assignment history links original runs and
  historical source revisions. Tests cover two-device admission, late-target/audit
  rollback, replay after later ring edits, changed-target conflicts, historical
  removal, scope and revoked authority. The full handler/race suite passes in
  8.503 seconds; Windows/shared views pass in 1.984/2.028 seconds. Browser tests
  confirm stale-apply rejection, multiline draft preservation, two-device source
  removal and exact history links at narrow and wide viewports. Vet and both
  builds pass. Both complete workflows pass for `d6fb091`
  ([push](https://github.com/the-luap/openuem-console/actions/runs/34429700762),
  [pull request](https://github.com/the-luap/openuem-console/actions/runs/34429703551)).
  Dynamic groups, automatic promotion and actual patch/restart evidence remain open.
- [Windows schedule console](native-windows-update-schedules.md#schedule-from-the-console)
  adds UTC timing and explicit-device preview/edit, confirmed future-plan creation,
  paginated history, original source/target detail and pending cancellation with
  the reviewed state revision. All six routes use scoped `ManageUpdates`, CSRF,
  bounded unique forms and audited store operations. Future creation queues no
  device commands; exact retries preserve the plan after source or state changes.
  Tests cover timing syntax/bounds, midnight rollover, two-device intent, worker
  activation and authority blocking, historical removal, scope/revision conflicts,
  complete audit rollback and six-state protected rendering. The full handler/race
  suite passes in 9.028 seconds; Windows/shared views pass in 2.543/1.987 seconds.
  The final browser-fixture/race run passes in 303.907 seconds including manual
  inspection, with views passing in 2.652/2.122 seconds. Real browser checks cover
  invalid draft correction, edit preservation, certificate-expiry advisories,
  confirmed creation and retained cancellation history. History is contained at
  390/768/1440 pixels, and the 768-pixel form passes visual inspection.
  Vet and Linux/Windows builds pass. Both complete workflows pass for `3a0b0fa`
  ([push](https://github.com/the-luap/openuem-console/actions/runs/34431557669),
  [pull request](https://github.com/the-luap/openuem-console/actions/runs/34431559785)).
  Dynamic groups, promotion gates, lifecycle operations and actual
  Windows patch/restart acceptance remain work; WIN-02 stays in progress.
- [Windows CSP evidence and queue controls](native-windows-csp-console.md) provide
  administrator-only command history, protected original trees and latest correlated
  outcomes, revision-checked undelivered custom-command cancellation and explicit
  uncertain-queue release with retained resolution notes. Typed steps retain their
  owning run's cancellation boundary. Public enrollment and SyncML handlers produce
  synthetic acknowledged and asynchronous outcomes for real PostgreSQL route tests.
  These cover roles, live authority loss, sibling scope, CSRF, stale revisions,
  confirmed mutations, read denial and rollback after final write-audit failure.
  Views cover all nine phases, nested intent, escaped XML/errors/notes, empty values
  and withheld partial results. Handler/race tests pass in 9.566 seconds;
  Windows/shared views pass in 3.050/2.017 seconds. Vet and both platform builds pass.
  Browser acceptance confirms uncertainty resolution and separate queued cancellation
  through real cookie/Origin CSRF, retained terminal history and contained forms at
  390/768/1440 pixels. Its complete handler/race run passes in 67.919 seconds including
  manual inspection, with view suites passing in 3.033/2.049 seconds. Both complete
  workflows pass for `999d890`
  ([push](https://github.com/the-luap/openuem-console/actions/runs/34432831838),
  [pull request](https://github.com/the-luap/openuem-console/actions/runs/34432834523)).
  Retention/export and broader WIN-02 work remain open.
- [Custom Windows CSP creation](native-windows-csp-console.md#create-and-review-a-custom-command)
  adds a bounded JSON tree editor, complete shared-compiler preview, retained draft
  editing and confirmed atomic/idempotent admission. The editor covers the existing
  operation/value/group compiler with exact lowercase unique fields, Unicode checks
  and explicit empty/omitted distinctions. Only its preview/create routes accept the
  larger percent-encoded body; all prior Windows forms retain 8 KiB. Tests cover
  nested intent, 100,000-byte values, audit rollback, actual permissions, source
  scope, Full enrollment, queue capacity and exact replay after identity revocation.
  Handler/race tests pass in 10.463 seconds; Windows/shared views in 2.903/1.980 seconds.
  The full Windows PostgreSQL/race suite passes in 86.255 seconds, with the protocol
  package passing in 1.289 seconds. JSON fuzzing passes 111,393 executions in 31.993
  seconds and now runs in CI. Browser confirmation preserves nested operations,
  zero/false, literal markup, Unicode and request identity through preview/edit;
  forms and expanded previews remain contained at 390/768/1440 pixels. Its complete
  handler/race run passes in 80.036 seconds including manual inspection, with views
  passing in 3.045/1.883 seconds. Vet and both builds pass. Both complete workflows
  pass for `4dd95d7`
  ([push](https://github.com/the-luap/openuem-console/actions/runs/34434259923),
  [pull request](https://github.com/the-luap/openuem-console/actions/runs/34434262839)).
  Retention/export, broader typed CSPs, lifecycle operations
  and the rest of WIN-02 remain open.
- [Windows CSP observation history](native-windows-csp-console.md#review-the-observation-history)
  adds ten-entry chronological pages and protected single-message snapshots under
  current scoped CSP authority. Reads authenticate existing ciphertext, packet
  digest, timestamp, original tree and dispatched operation identifiers, then commit
  audit before returning data. Older partial results stay partial after completion;
  administrative release and device revocation preserve historical evidence. Tests
  cover replay/restart, bounded pages, empty history, late outcomes, payload
  substitution, permissions, scope, audit failure and escaped values. The complete
  Windows PostgreSQL/race suite passes in 82.425 seconds, with protocol tests in
  1.412 seconds. The final handler/race suite passes in 10.156 seconds, with views
  in 2.917/2.041 seconds. Browser checks cover twelve protocol-generated synthetic
  observations, paging in
  both directions, partial-value suppression and the final literal result at
  390/768/1440 pixels. The complete browser-fixture handler/race run passes in
  127.374 seconds, including manual inspection, with views in 3.166/1.883 seconds.
  Vet and Linux/Windows builds pass. Both full workflows pass for `9e47a6b`
  ([push](https://github.com/the-luap/openuem-console/actions/runs/34435262334),
  [PR](https://github.com/the-luap/openuem-console/actions/runs/34435264197)).
  Retention/export, broader typed policies, lifecycle operations and physical
  Windows acceptance remain open; WIN-02 stays in progress.
- [Windows certificate renewal proof](native-windows-renewal.md) adds bounded
  CMS/PKCS#10 key-continuity verification against the caller's exact existing
  certificate. It verifies the old-key signature, independent new-key CSR proof,
  required renewal certificate attribute and configured key floor. Tests cover
  SHA-2 signatures, key reuse/replacement, certificate bags, malformed metadata,
  attribute ambiguity, signature substitution, redaction and ASN.1 resource bounds.
  A PostgreSQL fixture uses an issued synthetic enrollment identity without
  changing its certificate, device or encrypted bootstrap. Focused race tests pass
  in 2.715 seconds; the full Windows PostgreSQL/race suite passes in 87.008 seconds
  and protocol tests in 1.406 seconds. Fuzzing passes 118,432 executions in 31.414
  seconds; CI now includes this target. Vet and both platform builds pass. Both
  complete workflows pass for `7d4e771`
  ([push](https://github.com/the-luap/openuem-console/actions/runs/34436411706),
  [PR](https://github.com/the-luap/openuem-console/actions/runs/34436413803)).
  At that verifier-only stage, WSTEP rejected Renew. The following
  persistence extension adds issuance/handoff, SyncML continuity and lifecycle
  history; actual Windows/PKI acceptance remains open. WIN-02 stays in progress.
- [Persistent Windows certificate renewal](native-windows-renewal.md) adds scoped
  issuer-window admission, encrypted pending issuance, exact CSR retries,
  authenticated replacement membership and audited cancellation/history.
  A mutually authenticated SyncML packet using the new key commits confirmation
  and source revocation with its protocol state. The immutable initial enrollment
  remains the encryption anchor, preserving nonce/session/command history across
  multiple key generations and original-certificate expiry. Unknown CSP outcomes
  still block queued work. Device metadata switches to the confirmed certificate.
  PostgreSQL/race tests cover restart, concurrent issuance, scope and permission
  changes, audit rollback, immutable/protected history and migration preservation;
  real loopback TLS verifies new-key confirmation and resumed old-key denial.
  The complete Windows suite passes in 99.851 seconds, protocol in 1.407 seconds,
  and scoped handler/views in 2.094/2.525 seconds. Vet and Linux/Windows builds
  pass. Both complete workflows pass for persistence commit `e68fa65`
  ([push](https://github.com/the-luap/openuem-console/actions/runs/34438407740),
  [PR](https://github.com/the-luap/openuem-console/actions/runs/34438409922)).
  Subsequent extensions add certificate-authenticated Renew and console history/
  cancellation. Account/federated renewal, scheduling and real Windows/PKI
  acceptance remain open.
- [Windows renewal SOAP admission](native-windows-renewal.md) registers a separate
  certificate-authenticated Renew operation on the existing WSTEP endpoint. The
  validated RequestType selects disjoint initial/renewal grammars; CMS bounds,
  optional context/security fields, timestamp freshness and malformed/mixed
  credential rejection precede scoped store issuance. Direct TLS and pinned
  gateway identity use the enrollment endpoint while preserving the immutable
  management configuration. Tests perform initial HTTP enrollment, renewal,
  service-instance restart/retry, new-key SyncML confirmation and retired-key
  denial on resumed TLS through both direct and actual gateway listeners.
  Timestamp expiry during issuance/replay audit waits rolls back completely.
  Focused PostgreSQL/race tests pass in 9.579 seconds; the full Windows suite in
  107.712 seconds and protocol in 1.430 seconds. Client-identity/gateway regression
  passes in 1.333/3.037 seconds. Parser fuzzing passes 298,640 executions in 30.813
  seconds and now runs in CI. Vet and both platform builds pass. Both complete
  workflows pass for SOAP commit `2a5b139`
  ([push](https://github.com/the-luap/openuem-console/actions/runs/34439425052),
  [PR](https://github.com/the-luap/openuem-console/actions/runs/34439427708)).
  Account/federated renewal, complete lifecycle controls,
  scheduling and real Windows/PKI acceptance remain open; ROBO stays disabled.
- [Windows certificate replacement console](native-windows-renewal.md#review-and-cancel-a-replacement-in-the-console)
  adds ten-row renewal history, source/replacement fingerprints and lifecycle
  metadata, confirmed SyncML evidence and escaped cancellation reasons. The
  audited detail read verifies sealed evidence and terminal revocation timestamps.
  Only a scoped certificate administrator can view history or cancel a pending
  replacement; reviewed revisions and body CSRF protect cancellation. The prior
  certificate retains its existing access and the canceled candidate is denied.
  Database/router tests cover actual issuance, roles, sibling/foreign scopes,
  paging, malformed forms, stale revisions, audit rollback and protected history.
  Windows PostgreSQL/race tests pass in 114.820 seconds, protocol in 1.427 seconds,
  console integration/route checks in 10.772 seconds and views in 3.523 seconds.
  Vet and Linux/Windows builds pass. Owned loopback browser checks cover paging,
  required confirmation, the real cancellation redirect, escaped long reasons and
  contained 390/768/1440-pixel layouts. Both complete workflows pass for `04f2b34`
  ([push](https://github.com/the-luap/openuem-console/actions/runs/34441003508),
  [PR](https://github.com/the-luap/openuem-console/actions/runs/34441007033)).
  Account/federated renewal, renewal scheduling, production SMTP/inbox acceptance, unenrollment and real
  Windows acceptance remain open; WIN-02 stays in progress.
- [Windows disconnection notifications](native-windows-unenrollment.md) accept
  one complete first-package alert authenticated by the actual enrollment TLS
  certificate and current next-session digest. A live session can be interrupted
  without inventing a packet; unresolved command effects remain unknown. The
  transaction stores sealed request/response evidence, records the audit and
  revokes native access, including pending certificate candidates. Retired peers
  receive no replay exception, even on resumed TLS. Scoped protected report reads
  and device/inventory status preserve history while leaving local cleanup
  explicitly unverified. Tests cover stale proof, concurrency, restart, scope,
  audit/expiry rollback, tampering and migration preservation. Focused tests pass
  in 11.542 seconds; full Windows PostgreSQL/race in 123.217 seconds, protocol in
  1.384 seconds, console integration in 11.085 seconds and views in 2.904 seconds.
  Fuzzing passes 468,312 executions in 30.457 seconds and now runs in CI. Vet and
  Linux/Windows builds pass. Browser checks at 390/768/1440 pixels verify contained
  report views and retained uncertain-command navigation. Both complete workflows
  pass for `102e542`
  ([push](https://github.com/the-luap/openuem-console/actions/runs/34442544141),
  [PR](https://github.com/the-luap/openuem-console/actions/runs/34442546245)).
  Server-requested work is described below; physical Windows cleanup acceptance
  remains open and WIN-02 stays in progress.
- [Windows server-requested disconnection](native-windows-unenrollment.md#server-requested-disconnection-and-explicit-review)
  adds a fixed provider-bound Exec owned by an immutable lifecycle request,
  independently authorized through `devices.revoke`. It reuses durable command
  delivery while preserving the custom CSP enrollment-root prohibition. A
  delivered request holds later commands even after acknowledgment; explicit
  revision-checked review preserves uncertainty and permits subsequent management
  without replaying the Exec. A late authenticated disconnection report still
  retires access. Protected history, cancellation, audit rollback, creator revision
  changes, corrupted storage, final deadlines and migration of existing custom and
  update-owned deliveries have synthetic PostgreSQL coverage. Full Windows race
  tests pass in 130.999 seconds, protocol in 1.426 seconds, console integration in
  12.629 seconds and views in 2.994 seconds. Final lifecycle/update-queue regression
  tests pass in 17.055 seconds; reviewed history does not consume normal queue
  capacity. Vet and Linux/Windows builds pass. Both workflows pass for `45d5823`
  ([push](https://github.com/the-luap/openuem-console/actions/runs/34444483789),
  [pull request](https://github.com/the-luap/openuem-console/actions/runs/34444486383)). The console
  workflow follows; physical Windows recovery/cleanup acceptance remains open.
- [Windows disconnection console](native-windows-unenrollment.md#request-and-review-in-the-console)
  adds fixed-intent preview/confirmed admission, ten-row history, separate current
  access/report/command/review evidence, and revision-checked cancellation or
  investigation/release. All routes require current scoped `devices.revoke`;
  body CSRF, exact bounded fields and immutable request keys protect mutations.
  Command-owner links retain protected evidence while hiding raw lifecycle
  mutations. Router/database tests include grant loss after preview, foreign scope,
  malformed forms, retries, audit rollback and actual synthetic absent/200/202/500
  SyncML responses with late reports. Console/handler race tests pass in 13.174
  seconds, views in 3.395 seconds; final focused views pass in 2.022 seconds and
  public/private gateway route checks in 1.785 seconds. Vet and Linux/Windows
  builds pass. Twenty-seven
  browser page checks at 390/768/1440 pixels cover actual keyboard submissions,
  required confirmation, editing, paging, escaped long values and contained
  layouts. Both workflows pass for `cc40089`
  ([push](https://github.com/the-luap/openuem-console/actions/runs/34446401405),
  [pull request](https://github.com/the-luap/openuem-console/actions/runs/34446404608));
  physical Windows acceptance remains open.
- [Windows certificate health](native-windows-certificate-health.md) adds audited
  organization/site expiry warnings, current confirmed and pending replacement
  separation, bounded filters and CA full-lifetime issuance limits. Authenticated
  history, lock-wait confirmation, expiry, scope, migration and audit-rollback
  tests pass. The complete Windows PostgreSQL/race suite passes in 141.818
  seconds. Console route and responsive/keyboard browser tests also pass.
  Both workflows pass for `615f465`
  ([push](https://github.com/the-luap/openuem-console/actions/runs/34449014616),
  [pull request](https://github.com/the-luap/openuem-console/actions/runs/34449018594)).
  Automatic renewal and physical acceptance remain open. Persistent notification
  delivery is implemented below.
- [Windows certificate reminders](native-windows-certificate-reminders.md) add
  separate device-expiry, CA-expiry and full-lifetime issuance stages, authenticated
  outboxes, live account/permission/source checks and bounded SMTP retry. Runtime
  shutdown joins both Windows workers. Scoped history shows accepted, pending,
  retrying, canceled and missing-configuration states without recipient addresses.
  Database lock, corruption/fairness, migration, replica, audit and local SMTP
  tests pass; the full Windows PostgreSQL/race suite passes in 161.199 seconds,
  console/handler tests in 16.646 seconds, views in 4.434 seconds and runtime/SMTP
  integration in 1.962 seconds. All nine responsive history views pass browser
  checks. Vet and Linux/Windows builds pass. Both workflows pass for `98c9f9b`
  ([push](https://github.com/the-luap/openuem-console/actions/runs/34452316965),
  [pull request](https://github.com/the-luap/openuem-console/actions/runs/34452320064)).
  Production SMTP/inbox acceptance and physical Windows renewal continuity remain open.
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

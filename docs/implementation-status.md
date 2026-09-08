# Expanded roadmap implementation evidence

The authoritative scope is [the expanded roadmap](fehlende-funktionen-und-roadmap.md).
Its original reviewed code is `c19a58b`; implementation started from worktree commit
`11328cb`. Every package remains open until its full requirement and acceptance
scope is proven. A passing protocol simulator is not physical-device acceptance.

## Package ledger

| Package | Current evidence | Remaining work |
| --- | --- | --- |
| NET-01 | Native HTTPS gateway; exact public Apple route allowlist; source-network admin restriction; pinned mutual TLS on all backends; canonical login origin; optional exact agent WSS, upgrade limits and stream shutdown tested against real NATS; synthetic TLS/PostgreSQL tests | Production agent authorization/enrollment integration and downloads on 443; Windows protocol routing; full reference installation/firewall proof; TLS automation, proxy/browser/timeouts/load acceptance |
| SEC-01 | Header-only certificate login removed; trusted gateway boundary; OCSP certificate/freshness binding; canonical redirects; global request-token/Origin CSRF; persisted server/organization/site grants, native Apple action capabilities and permission administration/history; existing sessions rechecked | Individual desktop route scope/action permissions beyond current global-admin boundary; audit all existing mutation paths; complete authorization and direct-access regression matrix |
| ENR-01 | Baseline individual Apple identity; shared desktop CSR/broker-key proof, limited PostgreSQL invitations and CA issuance, scoped subjects, bounded broker authorization/session outbox, executable auth/disconnect and worker TLS/NKey services, protected broker setup, durable fixed-consumer reconciliation, worker body/profile/task checks; real-broker/database tests and passing related-repository CI | Console issuance and reference installation wiring; bootstrap manifests, protected agent storage, renewal and release integration |
| APP-01 | Baseline APNs certificate/key import | CSR/key storage; vendor signing integration; certificate-only import; renewal concurrency, account metadata, alerts and actual Apple issuance |
| UX-01 | Roadmap and supporting authored documentation in English; permission-aware navigation/forms; shared header wrapping and rendered access-page checks at 390/768/1440 px | Shared platform navigation/components, locale keys/preferences, pagination/filter/export/bulk consistency, dates/states, redacted errors, build summary, full accessible responsive browser acceptance |
| ENR-02 | Public Apple instructions, confirmed browser-bound claims, GET/HEAD scanner safety, local QR, bounded encrypted retries, status/expiry/revocation help; real-browser native form and download checks | Physical iPhone/iPad and Safari acceptance; Windows/Mac download/installer flows |
| MAC-01 | Upstream desktop agent only | Native Mac model/capabilities/channels, shared agent/MDM identity, profiles, inventory and real Mac acceptance |
| MAC-02 | No native Mac update/security workflow | Catalog/DDM compatibility and authorization, bootstrap tokens, FileVault escrow/verification and hardware update acceptance |
| IOS-01 | Native iPhone/iPad protocol/profile/DDM foundation | iPad filters/templates and separate hardware evidence; full template targeting/conflicts/rollback; group/ring UX and verified results |
| WIN-01 | Upstream deployment and model tests | Simple approved standard/custom catalog, detection/reboot/retry results, actual install/remove/offline/restart tests; update rings/policies and supported-OS matrix |
| PKI-01 | Baseline encrypted Apple secrets; documented/tested gateway leaf rotation | Automatic device renewal, CA/master-key rotation, expiry health, encrypted backup/restore preserving enrollments |
| OPS-01 | Console CI builds and new gateway CLI; security tests added to CI definition | Versioned agent/console distribution across repositories, signed/notarized installers, secure release/update/rollback manifests, monitoring, fresh-install and restore runbooks |
| APP-02 | No ADE integration | Apple Business/ADE tokens, device assignments, setup/re-enrollment, groups/rings and directory associations |
| WIN-02 | Agent transport only | Native discovery/WSTEP/enrollment, SyncML/CSP policies/results, renewal/unenrollment; separate Entra/Autopilot integration evidence |
| SEC-02 | Existing security inventory; Apple inventory-read/download audit events; permission-change history with before/after grants | BitLocker/FileVault recovery lifecycle, lock/wipe, further policies, compliance/conditional access, vulnerability/KEV prioritization, scoped general audit viewer/export/retention |
| API-01 | Internal console handlers only | Versioned management API, scoped authentication, desired-state validation/reconciliation, CLI/GitOps, webhooks/retries and equivalent UI outcomes |
| SW-01 | Upstream Windows/Homebrew foundation | Apps & Books/license lifecycle, own packages, unified execution verification, updates and self-service; later BYOD/Shared iPad acceptance as specified |

Cross-cutting scope includes native User Enrollment/privacy limits, SCIM and IdP
associations, macOS recovery/local-admin/Platform SSO extensions, certificate
lifecycle and later desktop security analysis listed in roadmap sections 3–4.
These must receive their own implementation and evidence before full completion;
the table's package summaries do not remove any detail from the roadmap.

## Current change evidence

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

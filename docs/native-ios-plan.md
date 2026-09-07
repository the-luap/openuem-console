# Native Apple management in the OpenUEM fork

## Requested outcome

One OpenUEM console for Windows software deployment and native iOS/iPadOS
management: enrollment, inventory (including OS/build and installed apps),
configuration profile lifecycle, and enforceable OS update policies. iOS app
deployment is optional. The Apple implementation belongs to this repository;
it must not depend on NanoMDM or operate as a separate management product.

Fork: https://github.com/the-luap/openuem-console
Branch: `feature/native-ios-management`

## Implementation decisions

- Preserve the upstream Windows agent, deployment workflows and database tables.
- Add an `internal/mdm/apple` domain and protocol implementation inside the console.
- Store Apple inventory, configuration, assignments and durable commands in the
  same PostgreSQL database, using versioned additive migrations. Do not add mobile
  devices to desktop agent tables with fictitious agent capabilities.
- Reuse console authentication, organization/site navigation and UI components.
  Add a unified devices view and platform-appropriate actions.
- Authenticate device traffic with individually issued certificates. Enrollment
  invitations expire and cannot be reused across devices. Public protocol routes
  are separate from session-protected administrative routes.
- Keep requested, delivered, acknowledged, verified, failed and stale states
  distinct. Reconcile actual device responses instead of treating APNs as delivery.
- Implement DDM tokens, declaration listing/retrieval and status reporting natively.
  Use software-update enforcement declarations for eligible device enrollments.
- Use Fleet Community for architectural inspiration only. Do not copy enterprise
  code or import a Fleet server. Apple schemas are the protocol authority.

## Completion checklist (evidence required)

- [x] Create GitHub fork and isolated working branch.
- [x] Native schema, persistence, tenant scoping and migrations.
- [x] Enrollment, identity validation, APNs and durable command processing.
- [x] Device, app and profile inventory with timestamps and refresh actions.
- [x] Profile upload/editor, validation, assignment, removal and device status.
- [x] Native DDM OS update enforcement and truthful progress/compliance reporting.
- [x] Unified UI, mobile device details, onboarding and Windows deployment access.
- [x] Startup/configuration integration and operator documentation.
- [x] Protocol, security, PostgreSQL and UI tests; upstream build/regression checks.
- [x] Protocol simulation against PostgreSQL, TLS client identity test and rendered
      browser fixtures (synthetic data).
- [x] Full console process with PostgreSQL/NATS, authenticated browser workflows,
      native HTTPS protocol simulation, restart recovery and live Apple catalog.
- [ ] Real-device acceptance with APNs certificates, reachable HTTPS and managed
      iOS/iPadOS and Windows hardware.
- [x] Commit and push the implementation to the user's fork.

## External acceptance requirements

Real-device acceptance requires a reachable HTTPS MDM URL, an Apple MDM push
certificate/private key and managed test iOS/iPadOS hardware. Automated protocol
tests do not establish real-device acceptance. Do not mark the overall goal
complete while requirements remain unverified.

## Research references

- https://github.com/apple/device-management
- https://github.com/fleetdm/fleet/tree/main/server/mdm/apple
- https://developer.apple.com/documentation/devicemanagement
- https://developer.apple.com/documentation/devicemanagement/deploying-software-updates-using-declarative-management

## Work log

- 2026-09-07: Created the GitHub fork; cloned upstream; inspected console routing,
  database initialization, Windows deployment and UI integration points. Downloaded
  official Go 1.26.8, verified its SHA-256, and started dependency setup. No device
  acceptance has been performed yet.
- 2026-09-07: Implemented the native Apple domain, durable queue, encrypted
  credentials/profiles, enrollment and revocation, inventory, profile revisions,
  DDM update policies and Apple catalog reconciliation. Integrated shared console
  routes, views and organization/site protections. Added an operator guide and CI.
- Verification: 14 native Apple tests; console PostgreSQL route/CSRF tests; four
  rendered UI fixtures; Go race detector passed. Linux and Windows cross-builds
  passed. Docker image built and CLI smoke test passed. Existing Windows deployment
  model tests passed. Full upstream model-suite SMTP/user failures were reproduced
  on an unchanged upstream checkout and are documented in the operator guide.
- Implementation pushed as `c0a710e` to `feature/native-ios-management` in the
  user's fork. GitHub CI run: https://github.com/the-luap/openuem-console/actions/runs/34157924980
- Initial GitHub CI passed, including PostgreSQL/race tests, Windows deployment
  model regression tests and Linux/Windows builds.
- Full runtime verification: started the actual Docker console with isolated
  PostgreSQL and NATS, logged in through the browser, configured test enrollment,
  enrolled a protocol simulator through mutual TLS, and observed OS/build and app
  inventory. Created and assigned a profile in the UI, revised it, restarted the
  console with work queued, and verified revision delivery and subsequent removal
  against reported profile inventory. An update declaration became active while
  compliance remained Update required; fresh simulated target OS/build inventory
  then changed compliance to Up to date. The existing Windows deployment page
  remained reachable through the same authenticated console. These results do
  not establish physical-device acceptance; APNs was intentionally blocked for
  the fixture certificate and token.
- Runtime fixes: trusted Apple's official public root specifically for catalog
  HTTPS after reproducing a Linux certificate-chain failure; confirmed a live
  catalog fetch. Made the selected release/build pair unambiguous when multiple
  builds share a version. Avoided duplicate inventory immediately after enrollment.
- Remaining release gate: the real-hardware acceptance
  checklist in `native-ios-operations.md`. Manual enrollment is implemented;
  ADE/ABM, SCEP, identity renewal, iOS app deployment and granular RBAC are not.

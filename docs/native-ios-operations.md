# Native iOS/iPadOS management

This fork keeps OpenUEM's Windows agent, workers, NATS integration and software
deployment workflows, and adds an Apple management implementation inside the
console binary. The `/devices` page combines computer and mobile inventory and
links to the relevant actions. No NanoMDM service or library is required.

The implementation has automated protocol, PostgreSQL, TLS and console tests.
Physical iPhone/iPad acceptance and a Windows endpoint deployment with this
fork are still outstanding. Treat this branch as a pilot until those checks pass.

## Included workflows

| Area | Implemented behavior |
| --- | --- |
| Enrollment | Per-organization APNs settings, one-hour single-use invitations, individual device certificate, checkout and server-access revocation |
| Inventory | OS version/build, model, serial, supervision, last contact, installed apps and configuration profiles |
| Refresh | On enrollment, manually, and every six hours; separate observation timestamps |
| Profiles | Unsigned XML/binary `.mobileconfig` upload; passcode, personal Wi-Fi and restriction builders; revisions; bulk assignment/removal; result verification |
| OS updates | Native DDM declarations, Apple release catalog validation, target version/build, device-local deadline, device-reported status and fresh-inventory compliance |
| Reliability | Durable PostgreSQL command queue, device deferrals, expiry, retry, encrypted command/profile data, transactional state changes |
| Console | Existing login/2FA, organization/site selection, shared navigation, device details, setup, profile management and Windows deployment access |

Login and permissions are separate. Persisted roles restrict native Apple actions
to an organization or site; viewer accounts cannot mutate profiles, certificates,
enrollment or updates. Desktop management routes currently require a global server
administrator. Read [access control](access-control.md) before upgrading: existing
accounts need explicit assignments and only the selected bootstrap account receives
initial server administration rights.

The [Apple push request workflow](apple-push-requests.md) generates a public CSR
with an encrypted instance-held key and supports certificate-only import after
external vendor signing. The [vendor signing guide](apple-vendor-signing.md) covers
operator-approved certificate pins, offline vendor tooling and verified portal
request downloads. Both credential import paths require a
[fresh APNs connection check before activation](apple-apns-connection-check.md).
Deployment vendor authority and actual Apple issuance/renewal acceptance remain
open; see these guides for checks and renewal behavior.

## Deployment prerequisites

Start from a working OpenUEM installation. Existing PostgreSQL, NATS, workers,
Windows agents, console certificates and upstream configuration remain required.
The native Apple tables are added to the same database using versioned migrations.
The database role needs permission to create these tables and foreign keys during
the first start and upgrades. Back up the database before upgrading.

Provide a dedicated public HTTPS origin such as `https://mdm.example.com` with a
certificate trusted by the devices. Route that origin to the Apple listener.
The console's public website can continue using its existing listener and proxy.

| Setting | Purpose |
| --- | --- |
| `ENCRYPTION_MASTER_KEY` | Existing OpenUEM secret. Use exactly 32 bytes for compatibility with upstream AES-256 encryption, and preserve it across restarts. |
| `APPLE_MDM_LISTEN_ADDR` | Enable the public device listener and background worker, for example `:1325`. Unset leaves the listener/worker disabled. |
| `APPLE_MDM_TLS_CERT` | Path to the public MDM server certificate/full chain in PEM format. Falls back to the console certificate. |
| `APPLE_MDM_TLS_KEY` | Path to its matching PEM private key. Falls back to the console key. |

These variables belong to the console process. With a container, mount the TLS
files read-only and publish the Apple listener port. The supplied Dockerfile
exposes 1325 but does not publish it or set the variables automatically. Start the
image with the existing OpenUEM environment and `start` command.

In direct mode, **TLS terminates in OpenUEM's Apple listener**, including through
a TCP/TLS pass-through load balancer. Arbitrary certificate headers are ignored.
The native HTTPS gateway additionally supports authenticated certificate forwarding
with explicitly pinned gateway client certificates. In gateway mode, every backend
requires that gateway identity and rejects direct connections. Follow the
[gateway operations guide](gateway-operations.md); ordinary header forwarding
without that trust configuration is not supported. The configured public URL is
the external origin, without a path, query or user information.

Allow outbound HTTPS to `api.push.apple.com` for APNs and
`gdmf.apple.com/v2/pmv` for the release catalog. Devices must also be able to reach
Apple services and the public MDM origin. Replicas must share the database,
encryption master key and public TLS configuration. Queue claims and catalog
refreshes are coordinated in PostgreSQL; this is not yet a scale benchmark.

## Build

Use Go 1.26.8 for the tested build. The templ generator is pinned in `go.mod`.

```sh
go mod download
go tool templ generate
go build -trimpath -o openuem-console .
```

Run the resulting console using the installation's existing `start` arguments,
working directory and assets. Alternatively:

```sh
docker build -t openuem-console:native-ios .
```

Upstream production binaries target Linux and Windows. A native macOS build of
the entire upstream console currently lacks `utils.NewAuthLogger`; use Linux or
Windows for deployment. Protocol and console handler tests can run on macOS.

## Apple push credentials and enrollment

1. Obtain an **MDM push certificate** and matching private key. An ordinary app
   push certificate is insufficient. Apple's issuance flow requires a CSR signed
   by an authorized MDM vendor; access to a vendor CSR signing certificate is a
   separate Apple process. This fork imports the resulting certificate/key and
   does not yet implement a CSR signing service. See
   [Apple's vendor certificate instructions](https://developer.apple.com/help/account/certificates/mdm-vendor-csr-signing-certificate).
2. Open **Apple setup & enrollment** in the intended organization. Enter the
   organization name and public HTTPS origin, then upload the certificate and
   key as PEM files, or use the certificate-only request workflow above. Both
   paths verify the Apple issuer chain, production/client usage, matching key,
   validity period and MDM topic, followed by a fresh APNs connection using the
   candidate credential. Outbound TCP 443 must reach `api.push.apple.com` directly.
   See [validation limits and trust maintenance](apple-push-certificate-validation.md).
3. Select a site and create an invitation for one device. Open its URL or scan its
   QR code on that iPhone/iPad. The public page explains the organization and
   installation steps before the owner confirms enrollment.
4. The invitation expires after one hour. GET/HEAD previews do not consume it.
   A confirmed browser claims it and has three attempts within ten minutes to
   download the same profile. Install in Settings and return to check status.
   If setup cannot finish, revoke that enrollment and create another invitation.
5. Open the device from **All devices**. Successful token registration changes its
   status to Managed and queues device, app, profile and available-update queries.

The invitation returns an individual PKCS#12 identity inside the enrollment
profile over HTTPS. A temporary retry copy is encrypted with both the browser
secret and server master key, then cleared on first device contact, exhaustion,
revocation or expiry cleanup. The issued certificate is bound to the first
enrolled device identity. Protect
the link and downloaded profile like credentials; the profile is not a reusable
installation package for multiple devices.

See [public enrollment operations](enrollment-portal.md) for cookie/claim lifetime,
browser recovery, rate limits, encryption and current verification boundaries.

Manual enrollment does not enable supervision. Prepare company-owned devices
with Apple Configurator when the required restrictions need supervision. Apple
Business Manager/Automated Device Enrollment and account-based User Enrollment
are not implemented. Do not use this enrollment mode for a BYOD privacy model.

## Profiles and inventory

Create a profile in **iOS profiles**, or upload an unsigned XML/binary
`.mobileconfig` up to 2 MiB. Upload permits additional Apple payload types; the
server checks document structure, not every platform/version-specific payload
rule. Device errors remain visible. Nested enrollment payloads are rejected.

Assign a profile to one or more enrolled devices in the selected scope. Updating
an existing profile requires its stable identifier and expected revision. A new
revision replaces existing installed assignments and cancels obsolete commands.
The root payload UUID changes per revision so inventory distinguishes revisions.

The lifecycle is Pending → Sent → Acknowledged → Verifying → Verified. APNs
acceptance only means the push was accepted. An acknowledgement alone does not
prove the expected profile revision is present. A subsequent `ProfileList`
response supplies that evidence. Removal is similarly verified by absence.
Delete a profile only after its removal has been verified on all managed devices.

Use **Refresh device, apps & profiles** for a new inventory request. Offline
devices retain their last observation with its timestamp. Installed apps are the
apps iOS reports for this enrollment; this is not unrestricted filesystem access.

## OS update policies

The update form offers Apple releases for the device's reported hardware model.
Select the exact version/build pair and a deadline in the **device's local
time**, with no UTC offset. The server rejects downgrades and unavailable releases.
The catalog client includes Apple's official Root CA because some Linux system
trust stores do not contain the root used by GDMF. Normal TLS chain, hostname and
validity checks remain enabled; this trust addition is scoped to the catalog.
The release catalog is requested at most daily; a snapshot older than 48 hours
cannot authorize a new policy. If Apple withdraws a target, the declaration is
withdrawn and the console marks the policy unavailable for administrator review.

Update enforcement uses `com.apple.configuration.softwareupdate.enforcement.specific`
on iOS/iPadOS 17 or later enrolled through Device Enrollment. It requests Apple's
deadline behavior; connectivity, power, storage and authorization conditions still
apply. See [Apple's DDM update protocol](https://developer.apple.com/documentation/devicemanagement/deploying-software-updates-using-declarative-management)
and [installation behavior](https://support.apple.com/guide/deployment/depd30715cbb/web).

The UI separates declaration activity/device update status from compliance.
Compliance requires OS inventory no older than 24 hours showing the target or a
newer version, and the requested build when the version matches. An offline
device with stale inventory is Unknown, not successfully updated. Removing a
policy withdraws its declaration; it does not downgrade an already updated OS or
guarantee cancellation of an installation already in progress.

## Certificates, recovery and offboarding

Renew the **existing** Apple push certificate with the same Apple account and
topic, then upload the renewed pair through Setup. A different topic is rejected
to avoid stranding devices. The enrollment CA remains unchanged. Changing the
public origin is also rejected while active enrollments use it.

Device identities currently last one year. Their expiry appears in device
details. Automatic identity renewal and SCEP are not implemented; plan removal
and fresh enrollment before expiry. Export/restore the whole database and retain
the original encryption master key in a separate secure backup. Changing that key
without re-encryption makes stored Apple keys and commands unreadable; there is
no key-rotation workflow yet.

Removing the MDM profile on a device sends checkout when the device can contact
the server. Checkout stops management and cancels pending work. **Revoke enrollment
access** immediately rejects the server identity and invitation and cancels work,
but does not remotely remove the MDM profile or erase device data. A replacement
enrollment receives a new identity and keeps the earlier history. Organizations
and sites containing Apple records cannot currently be deleted through the UI.

Audit events are retained in `mdm_apple_audit`; an audit export/viewer and retention
policy are not yet implemented. Protect database access because inventory and
audit metadata are operational data even though credentials and payloads are
encrypted. No remote wipe, lock, App Store/VPP deployment or iOS app self-service
is included in this branch.

## Verification and acceptance

Use an isolated PostgreSQL database whose role can create temporary schemas.
Tests create and drop only their uniquely named schemas; never point tests at a
production database. The test URL is separate from the normal `DATABASE_URL`.

```sh
export APPLE_MDM_TEST_DATABASE_URL='postgres://openuem_test:local-test-only@127.0.0.1:55439/openuem_test?sslmode=disable'
go tool templ generate
go test -race -count=1 ./internal/mdm/apple ./internal/controllers/webserver/handlers ./internal/views/mdm_views
go test -count=1 -run TestDeploymentTestSuite ./internal/models
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./...
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./...
```

Without the test database variable, PostgreSQL and device TLS integration tests
skip. The added GitHub workflow supplies PostgreSQL so these tests run in CI.
Browser-rendering fixtures are synthetic data; they do not establish device
compatibility. A separate local runtime check also exercised the actual Docker
console with PostgreSQL and NATS, authenticated browser forms, mutual-TLS
enrollment, profile revision/removal verification, queued work across a server
restart, and DDM compliance transitions using a protocol simulator. The live Apple
release catalog was fetched successfully with TLS verification enabled. This
check used fixture device credentials with outbound APNs blocked; real push
delivery, device installation behavior and Windows agent execution remain subject
to the hardware checklist below.

The full upstream models suite has known SMTP/user expectation
failures reproduced at unmodified upstream commit
`5604db7e4b4ac0fef5f95aad0ef279722966bd9d`:
`TestUpdateSMTPSettings`, `TestAddOIDCUser`, and `TestConfirmEmail`.

Before a production rollout, record these checks on actual managed hardware:

- [ ] Public TLS and APNs delivery with the real push certificate.
- [ ] iPhone/iPad enrollment; correct model, serial, OS/build and installed apps.
- [ ] Install a harmless profile, revise it, observe UUID verification, remove it.
- [ ] Set an available update with a test deadline; observe declaration status and
      the final OS/build after reboot. Repeat with an offline/locked device.
- [ ] Restart the console with queued work; reconnect the device and verify recovery.
- [ ] Renew the APNs certificate while preserving an existing enrollment.
- [ ] Checkout, revoke an abandoned invitation, and enroll the same device anew.
- [ ] Deploy and uninstall an approved test application on an actual Windows
      endpoint through the existing OpenUEM workflow.

The protocol follows [Apple's device-management schemas](https://github.com/apple/device-management).
Fleet Community's separation of desired state, command acknowledgement and
inventory verification informed the design; no Fleet Enterprise or NanoMDM code
was imported.

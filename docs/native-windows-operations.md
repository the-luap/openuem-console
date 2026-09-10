# Native Windows listener, gateway and schedule worker

The console server can now register the four native Windows device endpoints on
an optional separate HTTPS listener. The gateway forwards only their exact
public methods and paths. The same lifecycle starts and stops the durable update
schedule worker. This is implementation and synthetic acceptance evidence;
production deployment and physical Windows acceptance have not been performed.
The [enrollment/device console](native-windows-console.md) now provides CA setup,
one-time credentials, scoped inventory and device access revocation. Command/update
console forms remain implementation work. WIN-02 remains in progress.

## Configuration

Set these options on the console process before startup:

| Variable | Meaning |
| --- | --- |
| `OPENUEM_PUBLIC_ORIGIN` | Canonical public HTTPS origin, for example `https://uem.example.test`; shared with the gateway and console |
| `WINDOWS_MDM_LISTEN_ADDR` | Enable the native Windows listener, for example `127.0.0.1:1329` |
| `WINDOWS_MDM_MASTER_KEY` | Canonical standard Base64 encoding of 32 independently generated random bytes; protects native Windows CA, enrollment, command and update records |
| `WINDOWS_MDM_PROVIDER_ID` | Optional immutable enrollment provider identity; defaults to `OpenUEM` |
| `WINDOWS_MDM_DISPLAY_NAME` | Optional enrollment display name; defaults to `OpenUEM Windows Management` |
| `WINDOWS_MDM_TLS_CERT`, `WINDOWS_MDM_TLS_KEY` | Optional PEM server identity override; both are required together, otherwise the console TLS files are used |
| `OPENUEM_TRUSTED_GATEWAY_CERTIFICATES` | Existing shared PEM file of pinned gateway client certificates; required when using the gateway topology |

With every `WINDOWS_MDM_*` option unset, the listener and worker stay disabled.
Any partial Windows configuration fails startup. Setup validates the origin,
enrollment identity, TLS files and encrypted store, then migrates Windows tables
after the existing access schema. Listener binding must succeed before the
worker starts. Initialization errors use fixed messages without submitted key,
certificate or database details.

The Windows master key uses a different encoding contract from the legacy
`ENCRYPTION_MASTER_KEY`; do not substitute a raw 32-character string. Preserve
the key securely across restarts. Changing the public origin, provider ID or
display name changes the enrollment configuration digest. Existing devices are
bound to their original digest and cannot silently move to a new configuration.
Key rotation, endpoint migration and restore workflows still require implementation.

Add `--windows-url https://console.internal:1329` to the gateway invocation after
configuring the private listener and its TLS trust. This is the private origin;
discovery/provisioning advertise the configured public origin. The backend TLS
server certificate must validate for the private origin, while the gateway
preserves the public HTTP Host. No Windows option makes console pages public.

| Public path | Methods |
| --- | --- |
| `/EnrollmentServer/Discovery.svc` | GET, HEAD, POST |
| `/EnrollmentServer/Policy.svc` | POST |
| `/EnrollmentServer/Enrollment.svc` | POST |
| `/mdm/windows/syncml` | POST |

Queries (including an empty `?`), encoded aliases, suffixes, extra segments and
other methods are excluded from public routing. Discovery advertises initial
OnPremise enrollment version 3. Federated/Entra, certificate renewal and
Autopilot flows are not advertised by this listener.

## Transport and resource boundaries

Direct TLS mode requests a client certificate but allows anonymous discovery,
policy and initial enrollment. SyncML requires the enrolled leaf and its private
key proof, then rechecks issuer, fingerprint, live scope, revocation and the
enrollment configuration within the existing session transaction.

With gateway pins configured, every private request requires the pinned gateway
TLS identity, including discovery and enrollment. The gateway strips incoming
certificate aliases and emits the actual client leaf using RFC 9440. The Windows
handler resolves this header only after gateway authentication, reparses the leaf
and performs the same device checks. It never replaces the original TLS state
with a forwarded certificate. Direct mode ignores forwarded identity headers.
TLS session resumption does not bypass per-request gateway or device checks.

The Windows listener has 32 concurrent request slots with immediate empty HTTP
429 and `Retry-After: 5` when full. Each admitted request gets a 30-second context;
socket read/write deadlines are 45 seconds, header timeout is 10 seconds, idle
timeout is 90 seconds and headers are limited to 32 KiB. Existing individual
SOAP/SyncML body limits apply. Protocol responses retain explicit Content-Length,
no chunked transfer and no-store cache headers through the gateway. Raw protocol
requests, TLS errors, credentials and database errors are not logged here.

## Schedule lifecycle

`RunUpdateSchedules` processes up to 25 due plans immediately after startup,
then waits 15 seconds after each completed pass. A pass has a 30-second context;
passes do not overlap within a process. Durable transactions arbitrate multiple
servers and recheck the original operator authority and reviewed cohort.
Queue backoff and terminal outcomes follow the
[schedule contract](native-windows-update-schedules.md). Errors produce fixed
log messages and a later retry, without exposing protected plan data.

Console shutdown cancels the worker and request base context, closes the listener
and active connections, and waits for its worker to exit. Listener serving
failure also cancels the worker. A later startup resumes eligible persisted
plans. This worker controls server-side policy activation; it does not impose a
Windows installation/reboot maintenance window or prove patches were installed.

## Automated evidence

The synthetic PostgreSQL test exercises discovery, authenticated XCEP, WSTEP
issuance/retry, encrypted provisioning, scheduled full-policy activation and all
seven update steps over real public and private TLS. It verifies byte-identical
retries, explicit response lengths, device TLS resumption, revocation and direct
private-backend rejection. Additional tests cover pinned/forged/missing/duplicate
certificate headers, optional gateway routing, wrong hosts/methods/paths,
concurrent admission, canceled requests, partial configuration, worker retry,
concurrent shutdown and startup migrations with persisted-credential restart.
The full local PostgreSQL 17/race suite, Vet and Linux/Windows builds pass.
Both complete workflows pass for listener commit `85cac95`
([push](https://github.com/the-luap/openuem-console/actions/runs/34421236660),
[pull request](https://github.com/the-luap/openuem-console/actions/runs/34421239217)).
No test installs a certificate or changes
host settings.

Use the [reserved PostgreSQL fixture](native-windows-mdm.md#scoped-enrollment-credentials)
for database checks:

```sh
go test -race -count=1 ./internal/mdm/windows/...
go test -race -count=1 ./internal/gateway ./internal/security/clientidentity
go test -race -count=1 ./internal/controllers/webserver
```

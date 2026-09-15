# Individual agent command provisioning service

`cmd/openuem-agent-commands` runs the durable command-consumer reconciler. It uses
its own private provisioning NKey and requires registry migration
`002_command_consumers.sql` to have been applied by enrollment setup. It cannot
issue identities, read organization CA keys, authorize device connections or
publish commands. Console enrollment/installer integration and the complete
reference deployment remain separate work.

Build with `go build ./cmd/openuem-agent-commands`. Supply its protected database
URL file with `OPENUEM_AGENT_DATABASE_URL_FILE` and mount that file read-only:

```sh
OPENUEM_AGENT_DATABASE_URL_FILE=/run/openuem/database.url \
openuem-agent-commands \
  --broker-urls tls://broker.internal:4222 \
  --broker-ca /run/openuem/broker-ca.pem \
  --provisioner-key-file /run/openuem/provisioner-user.seed \
  --health-listen 127.0.0.1:1327
```

Use the `provisioner-user.seed` produced by the Certificate Manager's
`individual-broker` command. Install only that seed for this process. Keep the
issuer/authentication, revocation, worker and console seeds with their respective
services. The generated broker configuration gives this user only the fixed
stream/consumer APIs and its reply inbox. It explicitly bypasses the device auth
callout while still requiring its own NKey signature and account permissions.

Private files must pass Unix ownership/mode or Windows DACL checks. TLS verification
is mandatory, broker discovery is disabled, and no cleartext or legacy shared-key
fallback exists. Optional `--broker-client-cert` and `--broker-client-key` flags
support a private broker that also requires native-client mutual TLS.

The database URL file contains at most 8192 printable non-space ASCII bytes and
a network PostgreSQL host/database, plus an optional single LF/CRLF terminator.
Use verified TLS and the intended CA in that URL. Missing, malformed, symlinked
or overly accessible files fail without revealing their values. The existing raw
`OPENUEM_AGENT_DATABASE_URL` source remains supported but cannot be combined with
the file source. No invalid file falls back to raw or legacy credentials. The
provisioner does not receive the console's encryption master key.

The service first verifies schema availability and completes an initial bounded
reconciliation. It then polls once per second. Issuance, revocation, renewal and
site ownership changes record durable desired state atomically; polling also
detects certificate expiry. Each batch has at most 32 devices, eight concurrent
operations and three-second broker operation limits within a 20-second pass budget.
Failed or uncertain work remains retryable. Stale acknowledgments request another
check of the current desired state. An hourly check repairs broker data loss or a
crash between the broker operation and its database acknowledgment.

`GET /healthz` is available only on the configured numeric loopback address. It
returns 204 when the broker/database are reachable and reconciliation has succeeded
within 30 seconds; otherwise it returns 503. Responses are not cached. Readiness
does not imply every pending device has completed provisioning. Initial failures
and asynchronous messaging/permission errors stop the process for supervised
restart. Temporary failures after startup retain pending work and emit a generic
warning. SIGINT/SIGTERM cancels reconciliation and closes the broker and database.

Do not expose this HTTP listener or the private broker listener publicly. The
gateway's public `/agent-channel` route remains the device transport boundary.

The service's race-tested PostgreSQL/TLS fixture starts a broker from the generated
stock configuration, authenticates the provisioner with its protected seed, creates
the consumer for an issued identity, repairs a missing consumer, removes it after
revocation, withdraws readiness on broker loss and stops cleanly. The CI sets
`AGENT_ENROLLMENT_TEST_DATABASE_URL` and runs the complete `internal/desktop/...`
suite. This is automated evidence, not physical endpoint or firewall acceptance.

The fixture now supplies the database URL through a protected file. Setting
`OPENUEM_COMMAND_SERVICE_TEST_BINARY` to the compiled command exercises the actual
process, readiness, reconciliation and SIGTERM shutdown. The isolated PostgreSQL
setup suite runs that process with generated credentials and private database TLS
together with the authorization service and worker process fixtures.

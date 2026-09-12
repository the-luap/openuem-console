# Individual console broker connection

The console can use the dedicated individual-agent broker's console NKey. Both
the foreground `start` command and the installed Linux/Windows service select
this mode before reading legacy broker and SFTP settings:

```dotenv
OPENUEM_INDIVIDUAL_AGENT_MODE=true
OPENUEM_AGENT_BROKER_URLS=tls://nats.internal:4222
OPENUEM_AGENT_CONSOLE_KEY_FILE=/run/openuem-console/console.seed
OPENUEM_AGENT_BROKER_CA_FILE=/run/openuem-console/backend-ca.pem
```

Use the separate console seed from the individual broker initializer. Mount only
that role's protected file into this service. The broker, its authorization
service, registry and command-consumer provisioner must already be running.
The URLs are explicit private TLS origins, without credentials, paths, discovery
or public WebSocket fallback. The gateway's WSS route is for enrolled devices.

The broker's private CA is independent of `--cacert` / `Certificates.CACert`,
which remains the console authentication server's administrator trust input.
Do not substitute backend trust for administrator trust. The console's database,
session encryption, JWT key, listener certificates and remaining CLI/INI settings
are still required. The [protected administrator bootstrap](first-administrator-bootstrap.md)
initializes the first account from a private provisioning file. The complete
reference installation and automatic secret distribution remain separate work.
The [installation secret provisioner](installation-secrets.md) generates durable
runtime keys and the start password. Individual startup requires both runtime
keys; mount them through `JWT_KEY_FILE` and `ENCRYPTION_MASTER_KEY_FILE`.

If a private broker additionally requires a client TLS identity, configure both
`OPENUEM_AGENT_BROKER_CLIENT_CERT_FILE` and
`OPENUEM_AGENT_BROKER_CLIENT_KEY_FILE`. The generated individual broker uses NKey
authentication on its private TLS listener and does not require this optional
pair. The console never borrows its HTTPS listener key as a broker credential.

The mode accepts exactly `true`, `false` or an unset value. `false` and unset
retain legacy operation. Invalid or incomplete individual configuration is an
error; it cannot select legacy authentication. In individual mode `NATS_SERVERS`,
`--nats-servers`, `NATS.NATSServers`, `--sftpkey` and `Certificates.SFTPKey` are not
used. Legacy CLI operation still requires its broker URLs and SFTP key.

## Runtime behavior

The console connects before its HTTP listeners start. It creates a JetStream
publisher but does not create/update streams, create consumers, inspect
`SERVERS_STREAM` or join the legacy software-catalog election. The separate
provisioner owns command-stream and consumer management; the console's broker
grant remains restricted to device command publication and private replies.

Temporary broker outages reconnect with the same individual service key and
configured origins. A terminal connection or asynchronous permission failure
stops the main console listener and joins its serving goroutine. Normal console
closure also closes the connection and waits for the library's seed cleanup.

Legacy notification, user-certificate, worker-health and broadcast subjects do
not fit this broker grant. Console publish/request calls reject those subjects
synchronously, rather than reporting success before a broker permission error.
Those operations require separate internal-service integration. Server updater
JetStream operations remain outside this connection's permissions. The legacy
software-catalog election is not run in individual mode.

## Endpoint inbound access

This mode disables direct SFTP browsing/upload/download/mutation, SFTP device
logs, VNC, RDP-file generation and RustDesk session controls, including scoped
route aliases. The handlers reject these operations before key access, database
work or endpoint connections. The UI hides remote-assistance and log actions and
file-browser controls; disk inventory remains visible with a deployment notice.
These functions need a separately designed reverse channel or VPN before they
can be enabled in the reference deployment.

## Verification

`internal/desktop/consolebroker` runs against stock NATS with the actual rendered
individual broker configuration. It proves retained command publication, broker
restart/reconnection, denied stream administration, terminal permission failure,
protected-key/CA rejection and joined closure. Handler tests cover disabled
inbound operations, synchronous subject rejection and absence of legacy fallback;
listener tests cover failure admission and joined HTTP shutdown. Rendered
navigation checks preserve ordinary management actions while hiding inbound
features. Linux/Windows CLI tests exercise the actual flag set with no SFTP file
or legacy broker argument, plus explicit legacy mode and early INI-mode denial.

The `Individual console broker` workflow runs on native Linux amd64, Linux arm64
and Windows. Its Linux jobs also run the affected tests with the race detector.
This fixture does not claim physical-device or full reference-stack acceptance.

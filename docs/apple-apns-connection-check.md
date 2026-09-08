# APNs connection check before credential activation

Both Apple push credential import paths now require a successful connection check
before they commit a replacement. A failed check preserves active settings and
pending request keys. Correct the certificate or network problem and retry the
same upload. There is no administrator option to skip the check.

## What is checked

After offline Apple certificate-chain, usage, key, date and topic validation, the
console opens a new TCP connection to `api.push.apple.com:443`. It uses the
candidate certificate and its matching private key, not the active credential.
TLS requires version 1.2 or later, validates the server hostname and chain against
the system trust store, and negotiates HTTP/2. The server must request a client
certificate, and the candidate must actually be selected during that handshake.
The fresh connection does not reuse a TLS session or an HTTP connection pool.

The console then sends an HTTP/2 PING and requires its matching acknowledgement
on an open connection. This reads beyond the TLS handshake, including a TLS 1.3
peer's delayed rejection. It sends no HTTP request, device token, push payload or
management command. The dial, handshake, protocol initialization and PING share a
ten-second deadline. Cancellation closes the underlying socket, including when
the peer stops reading or never acknowledges the PING. There are no automatic
retries, redirects, alternate endpoints or proxy-environment settings in this
probe. Outbound TCP 443 must reach the APNs production endpoint directly.

Apple describes certificate-based connection establishment and refusal of revoked
certificates in [Establishing a certificate-based connection to APNs](https://developer.apple.com/documentation/usernotifications/establishing-a-certificate-based-connection-to-apns).
The PING acknowledgement is defined in
[HTTP/2 RFC 9113, section 6.7](https://www.rfc-editor.org/rfc/rfc9113.html#name-ping).
The implementation uses Go's TLS stack and `golang.org/x/net/http2`; it does not
implement its own TLS or HTTP/2 parser.

This is a connection check, not a notification submission or proof of device
delivery. It does not independently retrieve CRLs or OCSP responses, prove future
certificate acceptance, or show that an enrolled device remains managed after
renewal. Actual Apple issuance, connection/renewal and enrolled-device continuity
still need deployment acceptance. No Apple credential or real device was used in
the automated test evidence below.

## Persistence and administrator feedback

The organization advisory lock and request/revision checks remain in force during
the bounded probe. Certificate-chain validity is checked again after networking
and before saving. Settings, the certificate fingerprint, connection-check time,
request consumption, invalidation of other pending keys and audit events commit
together. A later audit failure rolls back all these database changes even if the
external connection check succeeded.

Migration `008_push_connection_check.sql` adds nullable historical check time and
a SHA-256 fingerprint of the checked leaf certificate. Existing settings have no
check record until their next successful import; migration does not invent one
or disable existing management. The setup page shows the time and fingerprint
only to organization certificate administrators. The fields are excluded from
device JSON and read without decrypting keys. They describe the last successful
import check, not a continuous health signal.

`apple.push_connection.verify` records the organization, administrator and leaf
fingerprint in the same transaction as the replacement. Neither keys, network
errors, device tokens nor protocol payloads are included. The request import route
returns HTTP 503 with a fixed retry message when the connection check fails.
The existing pair-upload form shows the same fixed message. Underlying peer,
DNS and TLS diagnostics are not echoed to the administrator.

## Automated evidence

- Real loopback TLS 1.2 and TLS 1.3 servers verify the exact candidate certificate;
  repeated checks establish separate connections and send no HTTP requests.
- Negative tests reject the wrong hostname, untrusted server roots, a peer that
  does not request a client certificate, TLS client-certificate rejection,
  unsupported TLS/ALPN, GOAWAY, connection closure and missing or wrong PING ACKs.
- Cancellation interrupts a stalled handshake. Raw HTTP/2 fixtures verify that
  each PING is received and that sockets close after success or failure.
- PostgreSQL tests run the actual loopback probe through both import paths:
  rejection preserves active keys/CA, request keys, revision and historical check
  record; a later audit failure also rolls back; a corrected retry commits exactly
  one new check record and invalidates stale request keys.
- A missing internal checker fails closed even during initial setup. Production
  constructors always install the fixed-endpoint checker. Test-only dialers and
  roots are unexported; no runtime environment or UI can select them.

Most pre-existing persistence tests isolate networking using an unexported test
callback. Their synthetic successes are not production APNs evidence. The
dedicated tests above exercise actual TLS and HTTP/2 on loopback without public
network traffic or changes to the system trust store.

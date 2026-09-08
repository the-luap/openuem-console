# Apple device identity renewal

The Apple maintenance worker schedules an enrollment-profile replacement when
an enrolled iPhone/iPad identity has 30 days or less remaining. The device
generates its replacement key through SCEP. The service activates that identity
only after the device uses it for both TokenUpdate and the command channel.
The device record, organization/site, UDID, profile assignments, update policy and
history remain attached to the same enrollment.

This is implemented and tested with PostgreSQL and synthetic TLS device peers,
directly and through the native gateway. Physical iPhone/iPad installation,
Apple's actual profile-replacement behavior for each enrollment method, real APNs
and uninterrupted hardware management remain acceptance requirements. In
particular, the legacy PKCS#12 migration test proves server behavior, not that
every manually installed profile can be replaced on every OS version.

## Operation and prerequisites

Migration `011_identity_renewal.sql` adds public enrollment layout metadata,
renewal generations and a durable per-device scheduling cursor. New enrollments
save their top-level, MDM, root and identity payload UUIDs when creating the
profile. This metadata survives deletion of the browser's temporary retry copy.

Renewal runs with the Apple worker enabled by `APPLE_MDM_LISTEN_ADDR`. Replicas
share the database and encryption master key. A sweep claims at most 25 devices
with row locks and advances each attempted device's cursor by six hours. Only
one queued or issued generation can exist per device. Pending, failed-setup or
offline records cannot monopolize the first scheduling slot.

The device identity and Apple push certificate must still be valid to start
issuance. The original public origin, push topic and supported access rights
must match the saved enrollment. The enrollment CA must be usable and capable
of extending the current identity by more than 24 hours. A new certificate lasts
up to one year, capped at CA expiry. This does not rotate the organization CA,
master encryption key, push credential or desktop-agent identity.

The replacement preserves the installed profile identifier and UUID, MDM payload
identifier and UUID, server/check-in URLs, topic and access rights. It gives the
SCEP identity payload a new UUID and updates `IdentityCertificateUUID`. Existing
root metadata is retained; older profiles without a root payload gain one. A
PKCS#12 device key is never copied into the replacement.

## Issuance and activation

| State | Meaning and authority |
| --- | --- |
| `queued` | An encrypted InstallProfile command and a hashed 256-bit challenge exist. The current device identity remains active. |
| `issued` | One candidate certificate has been issued. The active certificate and push data remain unchanged. Candidate check-in may stage encrypted push data; DDM, checkout and unrelated command responses remain unavailable. |
| `confirmed` | Candidate TokenUpdate and a subsequent Idle or acknowledgement of its renewal command prove use of the new identity. Certificate pin, expiry, push data and payload metadata switch atomically. |
| `failed`, `expired`, `cancelled` | Authorization and staged push secrets are removed. This candidate can no longer authenticate. Failure alone does not revoke the previous active identity. |

The bounded endpoint is:

```text
GET or POST /mdm/apple/<device UUID>/scep/<renewal UUID>
```

Both UUIDs must be canonical. The gateway allows this exact route; the Apple
backend requires an enrolled device, matching active base fingerprint, live
generation and delivered command. GetCACaps/GetCACert cannot expose an
undelivered renewal's authority. The same HTTPS, request-size, rate, concurrency,
DER, RSA, SHA-2 and AES restrictions as [initial SCEP enrollment](apple-scep-enrollment.md)
apply. Public discovery never decrypts a private key.

The normal replacement uses PKCSReq with its one-use challenge and proofs of
the request signer and CSR key. The generation endpoint also accepts RenewalReq
with the exact currently active device certificate as signer, an independently
signed CSR with a different key, and a matching challenge if one is supplied.
A certificate from the same CA is insufficient. The initial enrollment endpoint
does not gain renewal authority. The service still advertises only its existing
AES/POST/SHA-2 capabilities, not general `SCEPStandard` or `Renewal` support.

Issuance authorization and the InstallProfile command expire after seven days,
or at the old identity's expiry if sooner. Within that window, identical CSR,
signer certificate and transaction ID retries return the same public certificate;
a different request cannot consume the challenge again. The CSR cannot choose
certificate identity, CA status, SANs or broader usages.

Candidate TokenUpdate stores encrypted push data under that generation's secret
purpose. It does not overwrite the working old token. Successful command-channel
confirmation promotes all state in one transaction and clears staged secrets.
No candidate is activated solely because the CA issued it or the old identity
acknowledged InstallProfile. When observed device use proves success without an
actual command ACK, command history records **Verified on device**. A real ACK is
recorded separately as **Acknowledged**.

For up to ten minutes after confirmation, bounded by the old certificate's expiry,
the immediately retired identity may acknowledge only that exact renewal command.
It cannot receive commands, replace push data, submit inventory/DDM or check out
the device. Every consuming transaction rechecks the actual authenticated peer
fingerprint against current database state, including requests authenticated
before a concurrent renewal, failure or revocation. An old APNs response cannot
overwrite status or delay delivery for a newer encrypted push token.

## Offline devices, errors and recovery

An issued candidate survives the issuance/command deadline: an offline device
may already have installed it. It can later submit TokenUpdate and confirm while
that candidate certificate remains valid, including after the old identity has
expired. No second candidate is automatically created while that evidence is
pending. After issuance authorization expires, the SCEP endpoint itself closes;
the device must already possess its candidate certificate.

Explicit installation Error/CommandFormatError, including a late error after the
command deadline, retires the candidate. Checkout and administrator revocation
cancel renewal immediately. Unused authorization and expired candidate
certificates are reconciled by maintenance. Eligible devices can start a fresh
attempt after the six-hour retry delay. Generic command retry cannot revive an
obsolete renewal profile or extend its challenge; the console hides that action
for renewal commands.

The device's **Device identity** section shows its current expiry, scheduling
problems and the latest ten attempts with stage, dates, fingerprints and command
reference. History uses the same organization/site scope as device inventory.
Challenges, CSR bodies, private keys and push secrets are not included.

Older enrollment records without saved UUIDs first request ProfileList. Recovery
accepts only the exact known OpenUEM profile and supported payload structure;
duplicate/missing UUIDs, extra payloads and ambiguous profiles are rejected rather
than guessed or silently removed. Reported UUID spelling is preserved. Apple's
payload UUID inventory requires iOS/iPadOS 17 or later; this requirement applies
to metadata recovery, not new enrollments that already retain their layout.

If the current identity expires without a usable candidate, remove the old
enrollment profile on the device and enroll again. An unavailable/expiring CA
requires separate operational recovery or migration. Preserve the complete
database and original encryption master key; encrypted backup/restore and CA/key
rotation workflows remain separate roadmap work.

## Verification evidence and remaining acceptance

Automated tests exercise concurrent exact retries, scope and signer checks,
independent old/new key proofs, transaction rollback at issuance and activation,
service recreation, metadata recovery, legacy PKCS#12 migration, expired
authorization, offline candidate confirmation, late failure, revocation, retained
ACK restrictions, stale authenticated objects and stale push responses. The full
renewal flow crosses real TLS both directly and through the gateway. No test
contacts real APNs or manages a physical device.

The English detail page was rendered from test data and checked in Chromium at
390, 768 and 1440 CSS pixels, including expanded fingerprints and keyboard
activation of the disclosure. Page and identity section had no horizontal
overflow. This is a rendered console check, separate from hardware acceptance.

Release acceptance still requires real iPhone and iPad coverage for manual and
supported managed enrollment, renewal after restart/offline periods, old/new-key
request ordering, installation rollback, private-root trust and APNs continuity.
Confirm assignments and update policy continue to work after renewal. ENR-01 and
PKI-01 remain open for these checks and their other roadmap requirements.

## Primary protocol references

- [Apple: managing device and service certificates](https://developer.apple.com/documentation/devicemanagement/managing-certificates-for-device-management-services-and-devices).
- [Apple: deploying device management enrollment profiles](https://developer.apple.com/documentation/devicemanagement/deploying-device-management-enrollment-profiles).
- [Apple: MDM payload update restrictions](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.mdm.yaml).
- [Apple: common payload keys and UUID matching](https://github.com/apple/device-management/blob/release/mdm/profiles/CommonPayloadKeys.yaml).
- [Apple: ProfileList payload metadata availability](https://developer.apple.com/documentation/devicemanagement/profilelistresponse/profilelistitem/payloadcontentitem).
- [RFC 8894: SCEP enrollment, renewal and receipt limitations](https://www.rfc-editor.org/rfc/rfc8894.html).

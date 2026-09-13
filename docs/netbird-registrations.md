# Managed NetBird registration storage

`NetbirdRegistrationStore` implements reviewed, durable registration admission
and staged dispatch. The console now provides exact-site group selection,
review, submission, receipts, history, queued cancellation and read-only cleanup
checks. Startup owns and joins the registration dispatcher. The old registration
alias accepts only the same complete reviewed request; raw legacy settings cannot
bypass it. [Combined provider/agent resolution](netbird-registration-resolutions.md)
now supports retained-key requests with matching evidence. Installation,
authoritative provider-peer binding and real-provider acceptance remain open.

## Admission and authority

Review, request, dispatch and cleanup reconciliation require current
`ManageDeviceSecurity` authority for the exact device/site. Receipt reads use the
recorded site and `ReadDevices`, including after device removal. Admission
locks current device membership, installation generation, enrollment mode,
certificate/consumer identity, and provider settings against concurrent changes.
It requires a correlated live `registration-state` response. An older agent's
ordinary `state` response is insufficient, and no provider token is read before
that capability check. Selected groups must exist in a bounded provider lookup.

The review digest includes the source generations, live journal revision, sorted
selected group IDs and extra-DNS choice. Submission rechecks it and stores a
request UUID with a fixed two-minute lifetime. Connection and registration
requests share a device admission lock and reject request-ID reuse across both
families. A queued or unresolved registration blocks new connection operations.
Only an unattempted queued registration can be cancelled.

The device overview and history pages do not contact the provider or agent.
Opening group selection performs a live capability and provider-group read;
reviewing a selection does not create a key. Forms submit exact group IDs rather
than display labels. Explicit confirmation binds the request UUID, review digest,
groups and extra-DNS choice. Inputs reject repeated scalar fields, duplicate or
unknown group IDs, unsupported encodings, and oversized requests. Current route
capabilities, body/header CSRF checks, no-store responses and HTMX redirects cover
both the new routes and the old registration alias.

Receipts show key creation, device execution and key removal separately. A reader
can inspect recorded results without management controls. History uses a stable
50-record cursor in the original scope, including after a move or removal.
Unconfirmed receipts offer an eligible read-only key-removal check and a managed
resolution review. Resolution metadata is shown separately from the unchanged
original outcome, including in history. Key absence alone cannot release an
unknown device outcome.


## Credentials and retained evidence

The provider snapshot is encrypted using an independently derived HKDF-SHA256
key and AES-GCM with a fresh nonce. Its authenticated context binds the request,
device, actor, enrollment mode, tenant, site, reviewed revision and secret purpose.
The returned setup key is encrypted separately, additionally binding its exact
provider key ID. These new envelopes have no plaintext or legacy fallback.
Legacy settings are read through their existing bounded migration reader.

The snapshot retains the original HTTPS origin and token. Recovery therefore
cannot silently move cleanup to a different provider account after settings are
changed. Public records, audit events and normal formatting exclude both token
and setup key. The original token may have been revoked independently; such an
error keeps cleanup unconfirmed rather than selecting replacement credentials.

Migration `015_netbird_registrations.sql` adds permanent requests, stage attempts
and evidence. Attempts and evidence commit independently before an outer dispatch
transaction can roll back. They have no foreign key to its locked request row.
Database guards protect immutable identity/outcomes, stage prerequisites, exact
key policy, delivery correlation and confirmed absence. Startup rejects missing
or disabled guards. Existing bounded NetBird audit export and retention apply to
registration events; pruning events cannot erase the permanent duplicate barrier.

## External steps

1. Commit the exact provider creation-body digest, then send at most one POST.
   The policy is a one-off key, one use, a 24-hour provider lifetime, selected
   groups, reviewed extra-DNS choice and no ephemeral peer. Persist the validated
   provider response and encrypted full key before attempting device delivery.
2. Commit the complete version-two command digest, then publish once before the
   immutable command/certificate deadline. A matching completed agent receipt is
   persisted independently. The key reaches only the agent's `up` child through
   `NB_SETUP_KEY`; local journal records contain its digest, never the key.
3. Read the exact returned key ID using the captured provider origin/token. Its
   immutable creation policy must still match before removal. Commit a cleanup
   attempt before sending one fixed-ID DELETE. An exact-ID GET returning 404
   establishes absence; a successful DELETE reply alone is insufficient.

The provider returns the full key at creation and masks later reads. An
uncertain POST is never repeated, and a missing creation response cannot be
reconstructed by matching a name. See the official
[setup-key API](https://docs.netbird.io/api/resources/setup-keys) and
[registration guidance](https://docs.netbird.io/manage/peers/register-machines-using-setup-keys).
A failed or lost creation response can leave an untracked key until its provider
expiry; the local record remains unconfirmed and blocks further mutations.

Restart never repeats key creation or device registration. If a key was retained
before rollback, recovery may perform its first cleanup under current device
security authority. A recorded cleanup attempt is never sent again. Read-only
`ReconcileCleanup` can retain later proof of absence after a lost DELETE reply;
it preserves the original uncertain outcome and admission barrier.

A completed registration record means a correlated agent command result and
confirmed removal of its setup key. It does not establish lasting connectivity,
actual provider group membership, or authoritative peer ownership. In particular,
removing a setup key does not disconnect a peer already registered with it.
Reported hostname/IP and matching key names are not provider ownership evidence.

## Validation and integration remaining

Owned TLS, PostgreSQL, filesystem and NATS fixtures cover explicit capability,
scope and source changes, credential context substitution, concurrent admission,
permanent evidence, stage/audit rollback, lost responses, cleanup under captured
credentials, and restart without repeated effects. Existing NetBird connection
and coordinated-resolution tests remain part of regression validation.

Rendered view, real route and browser tests cover scoped permissions, CSRF,
confirmation, precise group policy, key-removal reconciliation, retained history,
keyboard submission, pending input locks and long provider labels. Registration
and combined-resolution pages have 117 browser cases at 390, 768 and 1,440 pixels. Owned database
tests cover empty group policy, 50-row pagination and joined dispatcher shutdown.

Combined resolution is implemented for retained keys and matching agent evidence;
its [failure ordering and remaining cases](netbird-registration-resolutions.md)
and [permanent withdrawal](netbird-registration-withdrawals.md)
and [explicit recovery attempts](netbird-resolution-retries.md)
are documented separately. Authoritative peer association, missing creation
responses and unsuccessful recorded removal still need explicit recovery policy;
do not clear journals, retry POST, or infer ownership from mutable reports. Trusted installers,
native Windows execution, interactive-desktop and physical/provider acceptance
must be validated separately from owned fixtures and cross-compilation.

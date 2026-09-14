# Reviewed resolution of uncertain NetBird installations

The delivery store now provides explicit recovery for an already attempted native
installation. `ReviewInstallationResolution`, `ResolveInstallation`,
`ReconcileInstallationResolution` and `ReadInstallationResolution` operate on the
original installation UUID and reviewed installation revision. They never invoke
or resend the native installation command. [Runtime dispatch](netbird-installation-dispatch.md)
now binds the store; lifecycle routes remain separate integration work.

## Review and admission

Review, resolution and reconciliation require current `software.assign` for the
original exact organization/site. Another currently authorized operator may
resolve the request. Historical reads require `software.read`. Recovery checks
current active individual enrollment, target membership, certificate, command
consumer and device generation. It does not reopen package sources or require an
old package approval to remain valid after authorized execution.

A live version-two receipt query includes the original request UUID, complete
command hash, installation revision and operation. The console also queries the
current journal when deciding whether a mutation is eligible:

| Evidence | Available action |
| --- | --- |
| Missing receipt and ready journal with capacity | Permanently withdraw the original command |
| Unconfirmed receipt, exact pending UUID/hash, and `CanRelease` | Explicitly release the uncertain journal entry |
| Completed receipt with no release identity | Retain completion using the normal observation rules |
| Owned withdrawal/release already visible | Reconcile the existing resolution |
| Missing, unavailable, busy, foreign or ineligible evidence | Keep the barrier; no mutation is authorized |

Only an eligible review receives a revision and expiry. Migration
`027_netbird_installation_resolutions.sql` retains its actor, exact receipt
observation, journal summary, state digest, sequence and permanent resolution ID.
The review lasts at most two minutes, bounded by certificate expiry. Before
admission, the console reauthorizes the actor and compares fresh recipient,
receipt and journal evidence with the retained digest. A changed target,
certificate, consumer, boot/journal revision, receipt, sequence or expired review
requires a new review.

The first admitted action retains one permanent resolution intent. Each admitted
control retains its own attempt UUID, actor, review, sequence, complete control
and digest. Intent, control and audit commit before transport. Database and
permission locks do not span the mutating RPC. Controls use database issue time,
a maximum ten-second lifetime and the earlier caller, review or certificate
limit. Replaying a consumed review returns history even after its expiry; it
cannot resend that control.

## Withdrawal, release and explicit additional attempts

Withdrawal uses version two and identifies the original command by UUID, complete
hash, revision and `install` operation. The resolution UUID becomes its permanent
withdrawal identity. The agent atomically retains withdrawal before accepting a
late original command. A missing receipt alone cannot end the console barrier.

Release uses the existing version-one `release` contract. The console verifies
both the original installation revision and operation in its response, in
addition to normal control correlation. The agent must independently permit
release under its durable journal, boot and process ownership rules. In
particular, a same-boot orphan with no joined result is not made releasable by a
console timeout or by this workflow.

If a control or its response was lost, a new explicit review can admit another
control under the same permanent resolution UUID. Every additional attempt has a
new review and sequence. A withdrawal that lost a race with native execution may
transition to release only after current exact unconfirmed evidence permits it.
Once release has been attempted, the workflow cannot return to withdrawal. No
control retry implies permission to retry the native installer.

## Retained results and read-only reconciliation

A correlated control response is retained separately from its attempt. Missing,
malformed, foreign or lost responses are stored as unavailable without transport
diagnostics. Result and audit persistence use a fresh bounded transaction even
after caller cancellation. If that transaction fails, the earlier committed
attempt remains pending; its consumed review still cannot cause redelivery.

Only an exact matching withdrawal or release receipt bearing this workflow's
permanent resolution UUID can produce a release proof. The proof references
retained evidence from an admitted control of the corresponding kind. The
installation receives separate `released_at`, `released_by` and `resolution_id`
metadata. Its original native result is preserved. Public delivery history shows
`released` separately from `completed` and exposes `OriginalOutcome`.

`ReconcileInstallationResolution` sends only a fresh current-identity receipt
query. It can confirm a lost reply after certificate renewal or later package
revocation. A matching UUID without an owned attempt of the appropriate kind is
insufficient. Foreign resolution IDs, missing receipts, unconfirmed entries with
no release identity and unavailable responses keep the barrier. An exact
completed receipt instead records normal completion without a release marker.

`ObserveInstallation` remains a general read-only observation operation. It can
record completion, but it cannot free a withdrawn or released entry. The explicit
resolution reconciliation operation is required to associate that evidence with
the retained operator intent. Already completed or released requests return
history without another query.

Cancellation, completion and release are mutually exclusive terminal states.
Cancellation remains forbidden after any native delivery attempt. Installation,
connection and registration admission share the updated active-device barrier;
released UUIDs remain permanently reserved. SQL triggers reject altered reviews,
intents, controls, results and proofs, exact-shape mismatches, stale admission and
release without matching retained evidence. Startup verifies all new guards.

## Verification and integration boundary

Owned PostgreSQL race tests cover both control versions, exact pre-transport
commit, source-free scoped history, immutable replay, fresh explicit retries,
withdrawal-to-release transition, expiry, current identity and permission
changes, orphan refusal, lost replies, revocation, foreign proofs, original-result
preservation, shared barriers and atomic audit failure. Independent SQL tests
submit invalid control and response shapes beside valid neighboring payloads,
exercise proof ownership and verify immutable/startup guards. These fixtures do
not download a package, run an installer or control an external device.

The shared agent contract and runtime pins are unchanged. The existing agent
continues to enforce installation, withdrawal and release ownership. Lifecycle UI, local removal and physical installation/upgrade/reboot
acceptance remain outstanding in the complete management workflow.

The complete inventory race suite and the complete audit race suite pass. The
focused resolution race suite also passes after the final proof-ordering guard,
including rejection of evidence observed before its corresponding owned control.
The full Linux ARM64 console build, handler compilation, owned NATS publisher
checks and registered console routes with PostgreSQL pass. Existing CI inventory,
audit and handler jobs include these changes.

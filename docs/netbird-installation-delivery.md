# Durable native NetBird installation delivery

`inventory.NewNetbirdInstallationDeliveryStore` connects reviewed package
preparation to one native installation command and read-only receipt recovery.
Its `Install` method requires a successful retained preparation. `ReadDelivery`
returns scoped public evidence; `ObserveInstallation` queries the current agent
for the original command receipt. Construction starts no automatic dispatcher or
route. [Reviewed withdrawal and release](netbird-installation-resolutions.md)
now use separate expiring reviews, immutable controls and exact owned proofs.
[Inventory startup](netbird-installation-dispatch.md) now binds its automatic
dispatcher. The [device lifecycle UI](netbird-installation-ui.md) now exposes
reviewed requests, retained evidence and explicit recovery.

## Fresh authority and exact prepared bytes

Installation admission requires current `software.assign` for the exact
organization/site, the original request actor and the original reviewed revision.
It locks the common device admission key and installation request, rejects
cancellation and expired request admission, and rechecks current package
approval/revocation, encrypted descriptor integrity, current individual
certificate/consumer, native target, membership and device generation. Explicit
preparation and installation capability responses must still report the reviewed
ready journal state.

The store reconstructs the exact original `PreparationRequest` from its retained
version, certificate and timestamps, the immutable installation request and the
freshly authenticated encrypted approval. It verifies the complete stored digest
and strict correlated `prepared` response. A matching payload hash or historical
prepared label alone is insufficient. The preparation must still be live and
bound to the current individual certificate.

Only then does database time define a fresh version-three `install` command.
Its issue time cannot precede preparation or its retained result. The request's
ten-minute deadline bounds admission; the newly admitted command receives its
own ten-minute execution maximum, shortened by certificate expiry. Download time
therefore does not consume the native installer's execution budget. The complete
command digest binds the exact package, recipient, original UUID/review and new
timestamps.

Migration `026_netbird_installation_delivery.sql` retains immutable delivery
attempt metadata before the publisher runs. Source URLs remain only in the
existing encrypted approval envelope. Attempt and audit commit atomically; no
transaction or authorization/approval lock spans native execution. A failure
before that commit cannot send a command. A committed attempt always prevents
another delivery, including after a caller or server restart.

## One native command and permanent uncertainty

`Handler.PublishNetbirdInstallation` accepts only a valid current version-three
command, sends it once on the exact direct command subject and decodes a matching
receipt. The existing connection/registration publisher continues to reject that
version, and the installer publisher rejects ordinary commands. No stream entry,
automatic retry, alternate source or legacy installer subject is introduced.

A matching `completed` receipt is retained with its audit before the common device
barrier opens. Other valid receipts are retained as unconfirmed evidence; empty,
malformed, foreign, lost or cancelled responses retain uncertainty without native
diagnostics. Result persistence uses a separate bounded transaction, including
after the caller disconnects. If persistence or audit fails, the committed attempt
remains pending and cannot be redelivered.

Local cancellation ends waiting; it cannot retract an installer message already
sent to an agent. The agent separately enforces its native deadline, prepared-file
ownership, durable journal and result verification. Neither cancellation nor a
successful transport exchange establishes rollback of remote native work.

After any delivery attempt, the cancellation API and database trigger both reject
cancellation, including when an UPDATE began waiting before the attempt committed.
Only cancellation before native delivery remains available. Completion,
cancellation and separately proved release are mutually exclusive and immutable. All installation, connection
and registration admission queries and the database admission function use the
same updated device barrier. Completed UUIDs stay permanently reserved.

## Read-only recovery under the current identity

`ObserveInstallation` requires current scoped assignment authority and active
individual target ownership; it may be used by another currently authorized
operator. It sends only a fresh version-two `receipt` control for the original
UUID, complete command hash, revision and operation. It uses the current
certificate and bounded control lifetime. A renewed certificate or subsequently
revoked package approval does not erase proof of work already authorized and
executed. No new installation or package access is needed for this observation.

The exact source-free control, its digest and matching response are appended with
an audit in a short transaction. Control issue time uses the database clock,
consistent with the retained evidence timestamp. Missing, malformed, unavailable,
unconfirmed, withdrawn or released evidence cannot open the console barrier.
Only an exact `completed` receipt with no release identity marks completion.
Original delivery results remain immutable: a later confirmed observation can
recover a missing or uncertain result without rewriting that original history.
Repeat observations of already completed or released work read the retained evidence.

A missing receipt is not proof that a delayed command can never arrive. Explicit
reviewed withdrawal and uncertain-attempt release now have their own
[console workflow](netbird-installation-resolutions.md), with an expiring review
and exact proof bearing the retained resolution UUID before admission opens. Existing agent boot, withdrawal
and release protections continue to apply. There is no cancellation or retry
fallback for an uncertain native delivery.

## Evidence and remaining integration

Public delivery history includes command hash/times, original result timestamp,
completion or separate release metadata, original outcome, correlated receipt
and latest observation summary. It
contains no private package, certificate or executable envelope. `software.read`
authorizes historical reads for the original exact scope, including after later
device changes. The database rejects rewritten attempts/results/observations,
forged receipt identities, unrelated control responses and completion without
retained positive evidence; startup verifies the new guards.

Owned PostgreSQL tests cover exact preparation reconstruction, new execution
budget, current authorization and revocation, immutable replay, cancellation
races, audit rollback, shared device/UUID barriers, result loss and recovery after
certificate renewal. Independent SQL cases reject forged result and observation
records. Owned NATS tests cover separate command families, exact correlation,
negative and lost replies and absence of installer stream records. Fixtures do
not download packages or run a real NetBird installer, daemon or provider.

The native macOS agent implementation verifies installer trust, protected paths,
receipt identity, complete payload hashes and the vendor CLI link. Physical
installation/upgrade/reboot acceptance, Linux
individual enrollment/publisher trust and
local removal remain necessary for the complete management workflow.

The focused delivery/observation PostgreSQL race suite passes in 33.892 seconds.
The complete inventory and audit race suites pass, as do the compiled Linux owned
NATS publisher tests, the registered console route fixture with PostgreSQL and the
full Linux ARM64 console build. CI already includes the complete inventory, audit
and handler suites. Consumers retain runtime contract pin
`v0.11.1-0.20260914054338-0060dbf7d6a4`; no shared wire field or agent code changes
are required for this delivery and receipt-recovery component.

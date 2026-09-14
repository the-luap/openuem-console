# Automatic native NetBird installation dispatch

Inventory startup now binds `Handler.NetbirdInstallations` to the existing direct
preparation, installation and control publishers. Its joined worker loop processes
reviewed installation requests automatically. It adds no legacy installer route,
new wire version, alternate package source or automatic control resolution. The
organization package approval pages and the [device installation lifecycle
routes and views](netbird-installation-ui.md) are connected.

## Selection and one-time delivery

`NetbirdInstallationStore.DispatchOne` selects an active request that has no native
attempt or retained dispatch stop. It accepts an unprepared request or a retained
successful preparation. Its selection query releases the database connection
before doing any work. The existing `Prepare` and `Install` methods then perform
current authorization and source checks and commit their own unique attempts
before their respective RPCs. Their complete command/request digests and results
remain the authority for delivery and recovery.

Concurrent workers may select the same request. The existing parent locks and
unique immutable attempts ensure that only one preparation and one native command
are delivered. Other workers read the committed pending/result evidence. No
transaction, database connection, permission lock or package approval lock spans
a download or native installer call.

A restart can continue a retained successful preparation with fresh native
admission, including all current approval, recipient, journal and expiry checks.
A preparation with no result or an uncertain result is never automatically
redelivered. Every native attempt, with or without a result, is excluded from
selection. Read-only observations and explicit reviewed resolutions remain the
only recovery paths after native delivery uncertainty.

## Durable stops before native delivery

Expired admission, lost assignment permission or changed source/recipient state
stops automatic preflight. A returned uncertain or rejected preparation also
stops progression. Migration `028_netbird_installation_dispatch.sql` retains one
immutable safe reason and audit before the dispatcher moves on. Unknown storage
failures are returned without private diagnostics; they do not manufacture a
successful or stopped result.

A dispatch stop preserves the shared device barrier. It does not label the
installation cancelled, completed or released. An operator with current scoped
assignment permission may explicitly cancel before native delivery and submit a
new reviewed request. Stopped UUIDs and reasons remain in history. The database
and public admission methods reject any new preparation/native attempt for a
stopped request, including direct SQL admission. A concurrent cancellation or
native delivery prevents insertion of a misleading pre-delivery stop.

`ReadDispatchStop` returns source-free history under the original exact scope and
`software.read`. Stop reasons never contain a URL, package contents, certificate,
command envelope or transport diagnostic. SQL prevents edits/deletion and startup
verifies the admission and immutable guards.

## Runtime and shutdown

`Run` polls every five seconds with at most four workers per console instance.
Individual RPCs retain their existing limits: preparation waits at most five
minutes and native execution uses its fresh maximum ten-minute command lifetime.
A dispatcher call has a sixteen-minute outer ceiling. No local waiting limit
changes remote execution ownership or proves rollback.

Inventory shutdown cancels and joins all installation workers together with
existing inventory, manual execution, connection and registration workers.
Cancellation before native admission can leave a retained prepared request for a
fresh process to continue. Cancellation after an admitted attempt never authorizes
redelivery; the existing bounded result transaction retains uncertainty even if
the caller disconnected. Explicit request cancellation remains possible while
preparation is in flight.

## Verification and device UI

Owned PostgreSQL race tests exercise queued and preprepared requests, process
restart, lost preparation/native replies, missing result transactions, preflight
revocation, immutable stops, original-barrier preservation, direct SQL exclusion,
concurrent workers and joined shutdown in both download and native phases. A
runtime test starts the actual inventory subsystem with an isolated schema,
checks installation-store binding and repeated startup, and joins shutdown
without a broker. No actual package, installer, daemon or external device is used.

The [device UI](netbird-installation-ui.md) exposes reviewed package choice,
queue/preparation/delivery state, scoped history, pre-install cancellation,
positive receipt observation and explicit expiring resolution review. Stopped,
cancelled, uncertain, released and completed evidence remain distinct. Existing
organization package approval/revocation pages are reused. Local removal and
physical installation/upgrade/reboot acceptance remain separate requirements.

The complete inventory race suite passes in 436.269 seconds, the focused
installation/dispatch/recovery suite in 70.268 seconds, and the complete audit
race suite in 11.072 seconds. The full Linux ARM64 console build, handler and
webserver test compilation, owned NATS publisher tests, registered console routes
and the actual inventory startup/shutdown fixture pass. Existing CI inventory,
audit, handler and webserver suites include these checks.

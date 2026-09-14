# Automatic native NetBird removal dispatch

The console now binds the reviewed removal store to the individual-agent control
transport and its distinct version-four publisher during inventory startup. Four
bounded workers process committed [removal requests](netbird-removal-requests.md).
They select the oldest eligible request and call the native delivery owner; no
package approval or installation preparation participates in removal.

Each delivery rechecks the original actor's current exact-site software authority,
individual identity, certificate, consumer, journal revision and complete native
descriptor. The immutable native attempt and audit commit before the one direct
RPC. No database connection remains reserved across native execution.

Concurrent workers and other console instances arbitrate through the same device
and request locks. Once an attempt exists, startup and subsequent polls never
select it for redelivery. A lost response, rejected receipt or failed result audit
retains the original uncertain or pending attempt. The existing explicit
[receipt observation and reviewed resolution](netbird-removal-resolutions.md)
remain the recovery paths.

## Retained dispatch stops

An expired request, lost software authority or changed/unavailable preflight
creates an immutable stop with a fixed reason. Recording its audit and stop is
atomic. The stop cannot overwrite a concurrent cancellation, completion, release
or already admitted attempt. It does not claim native success, cancellation or
permission to retry, and it preserves device exclusion.

Current scoped software readers can inspect a stop. An authorized operator can
cancel the original undelivered request and submit a fresh review. Public methods
and database guards both prevent native admission after a stop; startup also
rejects missing or disabled stop and admission guards.

## Bounded lifecycle and verification

Each selection has a ten-second database timeout and a twelve-minute parent
budget; the native command retains its independent ten-minute/certificate limit.
Shutdown cancels waiting workers and joins every native callback, including its
bounded result persistence. The server joins removal workers before closing
inventory dependencies. Logs use fixed messages without private transport errors.

Owned PostgreSQL race tests cover restart and competing delivery, committed
attempt visibility inside the callback, lost/rejected replies, result and stop
audit rollback, permission/certificate/descriptor drift, native absence,
unavailable inspection, expiry without native inspection, and joined cancellation.
Direct SQL checks prevent stops after admission and attempts after stops, preserve
immutable history and reject disabled startup guards. Runtime startup tests bind
the stores once and join shutdown without a broker. Removal and adjacent
installation-dispatch regressions and the Linux ARM64 console build cover the
integration.

Scoped status/history pages and public removal routes remain open. Retained local
staging recovery and physical package/interruption/reboot/desktop acceptance are
separate; journal release never deletes local staging or proves removal.

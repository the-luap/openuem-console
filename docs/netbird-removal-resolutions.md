# Reviewed NetBird removal resolution

Uncertain [native removal delivery](netbird-removal-delivery.md) now has a separate
reviewed resolution lifecycle. It retains original native outcomes independently
of a confirmed journal withdrawal or release. A release does not prove removal,
rollback, stopped processes or safe deletion of retained local staging.

## Fresh review and permanent identity

`ReviewRemovalResolution` requires current software-assignment authority in the
request's original exact site and a current individual recipient. It reads the
original command receipt under that current certificate. It never requires the
original native package state still to exist and never starts another removal.

A missing original receipt plus a ready journal can support withdrawal of that
UUID. An original unconfirmed receipt supports release only when the journal
reports the exact pending UUID/hash and explicitly allows release. Busy, foreign,
inaccessible or changed state cannot become an eligible review. A matching original
completed receipt confirms removal through ordinary observation instead.

Eligible reviews are immutable, actor-bound, limited to two minutes and bounded
by certificate expiry. They retain the original request, proposed resolution UUID,
current receipt observation, journal state and snapshot fingerprint. Before a
control is admitted, the service rechecks current identity, authority, receipt,
journal, control sequence and review expiry under the common device and request
locks.

The first admitted resolution keeps one permanent UUID. Its exact control,
sequence and audit commit before transport. A lost response does not permit
automatic retry. Replaying a consumed review only reads retained history. An
additional control requires a new explicit eligible review under the same
resolution UUID; a prior release can never fall back to withdrawal.

## Exact proof and read-only reconciliation

The service retains each control result, including an unavailable result. The
original UUID, hash, revision, `uninstall` operation, current certificate and
resolution ID must correlate. Version-one release responses receive an additional
original revision/operation check because those fields are not in that control's
request grammar.

Only exact owned withdrawal/release evidence can create a permanent release proof
and set the request's release metadata. This opens console device admission while
leaving its original native result and completed timestamp unchanged. Ordinary
receipt observation cannot open the barrier for a withdrawn or released request
by itself.

`ReconcileRemovalResolution` uses only a current-identity original-receipt query.
It can recover a lost control reply if its returned resolution ID matches an
already admitted control of the corresponding kind. A foreign resolution ID,
missing result, changed operation/hash or release without an owned prior attempt
keeps exclusion intact. It sends no withdrawal, release or native removal.

Database constraints and guards preserve original intent, review, sequence,
control, result and proof. Completion and release remain mutually exclusive;
neither can be fabricated by a timestamp update. Startup migration verification
also requires all removal request, admission, result, observation and resolution
guards enabled with their expected trigger functions and event types.

## Verification and remaining work

Owned PostgreSQL races cover reviewed control-before-transport ordering, scoped
software rights, certificate/consumer/site drift, expired or changed reviews,
lost replies before and after control acceptance, new-review-only retry, completed
receipt recovery, original-result retention and exact read-only reconciliation.
Recovery still works after certificate renewal and native package absence without
another native-state inspection. Direct SQL fixtures independently test malformed
controls/results, exact proof ownership, immutable records and failed-startup
guards; valid neighboring records ensure duplicate keys cannot mask those checks.
Audit failures roll back metadata and retain the original unresolved attempt.

The full NetBird inventory race suite and Linux ARM64 console build cover this
integration. Fixtures do not mutate vendor software or enrolled endpoints.
Joined automatic dispatch, scoped status/history UI and retained local staging
recovery remain open. Journal release does not clear staging; the
[native execution owner](https://github.com/the-luap/openuem-agent/blob/aa1262dd95fa086649d7bc3bdee8beb08b0e13ad/docs/netbird-removal-execution.md)
continues to reject a fresh removal while interrupted staging remains. Physical
package, interruption, reboot and desktop acceptance remains separate.

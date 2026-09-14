# Explicit NetBird resolution recovery attempts

A release or withdrawal request can be lost before reaching the agent. Open the
original receipt and review its resolution again. **Confirm recovery attempt**
is available only when current evidence permits another control under the same
resolution ID. Every attempt requires an unchecked confirmation and fresh review.
**Check agent receipt** and **Check retained evidence** remain read-only.

## Eligible recovery

| Original resolution | Current evidence | Recovery action |
| --- | --- | --- |
| Connection or registration release | Matching unconfirmed receipt, no retained release, exact pending journal entry and ended local execution | Send another release under the original resolution UUID. |
| Connection or registration withdrawal | Version-two missing receipt, ready journal with capacity and no previously recorded release recovery | Send another permanent withdrawal under the original resolution UUID. |
| Connection or registration withdrawal overtaken by execution | Matching unconfirmed receipt with ended local execution | Explicitly authorize a release phase under the original resolution UUID. The original withdrawal intent is preserved. |
| Already retained matching proof | Exact resolution UUID and original command metadata | Confirm through a read-only evidence check. No recovery transmission is offered. |
| Active execution, unavailable storage, foreign resolution, unsupported recovery or missing current authority | Insufficient evidence | Keep further commands blocked. |

Registration recovery requires independently retained absence of the exact setup
key. A recovery attempt does not create a provider key, repeat registration or
repeat DELETE. An unattempted cleanup still uses the existing reviewed continuation
flow. A missing provider creation response or an unsuccessful recorded DELETE
needs separate recovery work.

Execution can win a withdrawal race before or after the initial agent control
was recorded. After local execution ends, a fresh review can authorize a release
phase in either case. Once that phase has been recorded, a later missing receipt
cannot revert the resolution to withdrawal. A completed receipt can still resolve
through the existing evidence check. No path rewrites execution as withdrawal or
changes the original console outcome from `unconfirmed`.

## Permanent attempts and exact replay

Migration `018_netbird_resolution_retries.sql` adds permanent recovery attempt
rows shared by connection and registration resolution. Each row retains the
family, original request and resolution UUIDs, a separate form UUID, actor, fresh
review fingerprint, action, sequence, canonical control and digest. Its audit
resource includes the attempt UUID. The row and audit commit together in an
independent transaction before any transmission. There is no foreign key that
could wait on the original request locked by the coordinating transaction.

The fresh control uses the original resolution UUID on the wire, the original
command UUID/digest and current device identity. Its deadline is bounded by ten
seconds and the current certificate expiry. The agent's existing idempotent
release/withdrawal handling uses the unchanged resolution UUID. No original
command or private setup key is transmitted again.

The outer transaction holds current permission, device/site, enrollment and
request locks through review, the bounded control and final evidence commit.
Certificate renewal changes the review fingerprint while preserving the original
command digest. Revocation, expiry, an inactive consumer or a moved device stops
new recovery attempts. Historical read access alone cannot authorize a control.

Replaying the same form UUID with identical actor, revision and request bindings
returns retained metadata without an external query or transmission. Altered
bindings conflict. Concurrent forms serialize on the original request; a newly
committed attempt changes the review fingerprint, making another form from that
review stale. A later attempt requires another review and confirmation.

Intent or attempt-audit failure prevents transmission. Loss of a control or its
reply preserves the independently committed attempt. Final evidence, release
metadata and release audit still commit atomically. A final audit rollback can
be recovered through the read-only evidence check without another mutation.
Database guards accept release/withdrawal proof only from the original admitted
control, an exact retained recovery control or a correlated receipt query. Both
new guards are checked at startup. Attempts cannot be updated or deleted.

## Visibility and verification

The review and original receipt show the total recovery attempts and the latest
attempt's UUID, action, actor and time. Reads load only that bounded summary;
all earlier attempt rows remain permanent. The existing immutable resolution
identity, initial actor/revision and original outcome stay unchanged. Browser forms
mutually exclude pending recovery and evidence-check submissions.

Owned PostgreSQL fixtures exercise lost requests/replies, concurrent confirmations,
replay, stale evidence, audit failures, current identity and scope, release after
a withdrawal race, immutable attempts and malformed control rejection. Actual
routes exercise permission, CSRF and strict form handling. Twenty-seven browser
cases cover recovery, separate attempt identity, keyboard confirmation, long
content and pending form exclusion at 390, 768 and 1,440 pixels.

The full inventory PostgreSQL race suite passes in 216.401 seconds; the full
audit race suite passes in 8.774 seconds. Affected view race tests, registered
console routes and the full Linux arm64 console build pass. The complete browser
matrix passes all 2,343 cases, including the 27 recovery cases above.

This change uses the existing agent recovery protocol. No real provider,
installed NetBird executable or physical endpoint is invoked by its tests.
Unavailable or coherently rolled-back journal storage cannot be repaired by
resending controls or deleting the journal. [Connection-command withdrawal](netbird-connection-withdrawals.md)
is now wired into the console. Provider peer ownership/deletion, trusted installers and physical acceptance
remain separate work.

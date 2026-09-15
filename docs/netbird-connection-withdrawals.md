# Permanent withdrawal of a NetBird connection command

A connect, disconnect or profile-switch request can remain unconfirmed when its
response is lost. A missing receipt does not prevent the original command from
arriving later. Open the original receipt, choose **Review resolution** and use
**Confirm withdrawal** when the current agent proves support and has capacity.
The original outcome remains `unconfirmed`; separately confirmed evidence opens
admission for further commands.

## Review and confirmation

Review first queries the original command UUID and digest. A legacy missing
receipt triggers a separately correlated version-two query carrying the original
revision and operation. An unsupported or mismatched reply cannot establish
withdrawal capability. A fresh live journal query must report readiness and
remaining capacity. Active execution, a full journal, unavailable evidence or a
foreign resolution keeps admission blocked.

The review fingerprint binds current scope and identity generations, exact agent
receipt, journal state and existing resolution/recovery metadata. Current device
security permission, actual device/site association, valid certificate and active
provisioned command consumer are required. An expired, revoked or moved identity
cannot send a new control. Certificate renewal preserves the original command
digest while requiring a fresh review for the new current identity.

The unchecked confirmation describes the permanent denial and its execution
boundary. The console independently commits the resolution UUID, prepared control,
canonical digest and audit before transmitting once. The control expires within
ten seconds and the current certificate lifetime. It carries the original
request UUID, source revision, operation and complete command digest. No command,
provider token or setup key is sent again.

The agent serializes withdrawal with execution admission. If no execution attempt
exists, it permanently stores the denial before returning a matching `withdrawn`
receipt and the exact resolution UUID. Later delivery of the original request
cannot execute, including after journal reopen. Existing execution attempts
cannot be rewritten as withdrawn. A profile switch is bound to its complete
original digest, including the reviewed profile handle.

## Loss, retries and execution races

Replaying the original form returns its retained intent without another external
call. **Check agent receipt** is read-only and uses version-two queries for a
withdrawal intent. A matching receipt can recover a lost response or final audit
rollback. Confirmation proof, release metadata and release audit commit atomically.

If the withdrawal request itself was lost, a fresh review can offer an explicitly
confirmed [recovery attempt](netbird-resolution-retries.md). Every transmission
has its own permanent attempt record and audit, while retaining the original
resolution UUID on the wire. Once a release recovery phase has been recorded,
a later missing receipt cannot resume withdrawal.

If execution wins the withdrawal race, an active or uncertain execution keeps
admission blocked. A matching completed receipt can resolve through the read-only
check. An unconfirmed execution that has ended requires a freshly reviewed,
explicit release phase under the same resolution UUID. Both the initial withdrawal
intent and original console outcome remain unchanged. The UI distinguishes
retained withdrawal from execution that completed before withdrawal.

A late completion can also be discovered during capability review, before any
resolution intent exists. The exact version-two completed receipt can be
acknowledged directly. This handling applies to both connection commands and
managed registrations; it does not infer completion from a missing response.

## Storage and validation

Migration `019_netbird_operation_withdrawals.sql` adds the withdrawal intent kind
and validates new intents against the exact original operation, device, scope,
mode and permanent delivery attempt. It extends recovery and evidence guards for
version-two withdrawal and receipt queries. Release controls remain version one
and must match an admitted initial or recovery control. An unconfirmed receipt
cannot replace withdrawal without a separately admitted release phase. Startup
verifies the new intent guard; all previous immutable records remain intact.

Owned database tests cover all three commands, lost requests and replies, replay,
concurrent confirmations, execution races, current identity, audit rollback,
full journals, unsupported agents, exact metadata and recovery-phase boundaries.
Actual console routes check permissions, CSRF, explicit confirmation and the
unchanged original receipt. Thirty additional browser cases cover confirmation,
retained proof, late completion, recovery, capacity and long text at 390, 768 and
1,440 pixels. Owned agent broker tests deliver withdrawn commands late and reopen
the journal, verifying zero execution callbacks for connect, disconnect, profile
switch and registration. Fresh same-ID withdrawal controls retain the same proof.

The full inventory PostgreSQL race suite passes in 216.401 seconds and the full
audit race suite in 8.774 seconds. Affected
view race tests, registered console routes and the Linux arm64 console build
pass. All 2,343 browser cases pass, including the 30 new connection-withdrawal
cases. Agent command and journal race suites pass on macOS and Linux.

No installed NetBird executable, real provider or physical endpoint is used in
these tests. Connection withdrawal does not establish current connectivity or
provider peer ownership. Unknown provider creation responses, unsuccessful
recorded key removal, trusted installers and native/physical acceptance remain
separate roadmap work. Journal deletion or restoration of rolled-back history is
not a recovery procedure.

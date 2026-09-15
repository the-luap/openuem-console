# Console certificate issuer trust

Certificate authentication and protected certificate sessions share the public
client CA configured by the console. Startup validates its bounded DER, CA and
certificate-signing constraints and current lifetime, then publishes it before
the console accepts requests. The database retains only public certificate bytes
and a random generation UUID. It does not store another CA private key.

Replacing the configured CA changes the generation transactionally. Restoring
earlier CA bytes changes it again, so earlier authentication evidence cannot
become valid merely because the configuration looks unchanged. Publishing the
same DER at another startup preserves the generation. Rolled-back changes also
preserve existing authority. Direct generation replacement, deletion and
truncation are rejected by database guards.

## Admission and protected requests

Initial authentication verifies actual TLS possession and captures the current
issuer generation before its bounded signed OCSP check. Owner association and
final initial admission must still match that original generation. Callers cannot
substitute a newly loaded generation after verification.

Pending MFA and completed sessions retain the original issuer UUID alongside
their account, method and certificate-registry generations. They also retain the
exact public leaf DER. Each certificate authorization parses that bounded DER,
checks its signed identity, and verifies a current client-auth chain against only
the configured CA. There is no operating-system root fallback. A valid leaf with
an expired CA is rejected.

The admission transaction locks configuration and account state before the issuer
row, revocation table and certificate registry row. A shared issuer lock lasts
through confirmation or MFA consumption. Immediately before commit, authorization
rechecks chain validity and the retained generation. Expiry or a changed
generation rolls back confirmation and MFA consumption; no session stamp is
returned. Public MFA enrollment operations using a pending certificate proof
apply the same issuer checks.

Untrusted, expired or retired evidence returns HTTP 401 and clears session
authority. Unavailable or malformed configured trust and bounded database lock
failures return HTTP 503 without discarding otherwise valid retry evidence. A
rolled-back lock holder permits retry. Repairing committed issuer state creates
a new generation, so earlier sessions must sign in again.

## Upgrade and scope

Session-generation migration 5 seeds one unconfigured issuer row. Trusted startup
configuration supplies its CA. Repeated migration preserves the UUID and checks
the required row and active guards; it does not silently recreate lost authority.
Database writers must retain the guards and their generation-table permissions.

Stop older console and authentication readers/writers before this coordinated
upgrade. All instances must use the same trusted CA configuration. Legacy
certificate sessions and pending proofs without an issuer UUID require a fresh
sign-in. Password session metadata is unchanged. Publishing a different startup
CA intentionally retires existing certificate sessions, including sessions on
another instance sharing the database.

Request-time revocation still uses the local registry. These changes do not add
periodic OCSP refresh, per-certificate issuer/key identifiers to that legacy
registry, automatic CA issuance or a coordinated CA rollout interface. Initial
sign-in retains its existing OCSP verification. Production renewal and device
continuity require separate lifecycle acceptance.

## Verification

Owned mutual-TLS/OCSP tests cover CA expiry, replacement and restoration with
plaintext and encrypted session-token storage and no MFA, TOTP and backup codes.
Initial admission tests change and restore trust after TLS/OCSP verification;
pending-proof tests reject old or unbound generations. Transaction tests cover
held issuer locks, late CA expiry, final confirmation changes and rolled-back MFA
receipts/counters. Missing, malformed and temporarily locked trust have distinct
retirement/retry checks. Migration tests cover repeated startup, disabled guards,
lost state and schema-pinned trigger execution.

The full PostgreSQL/race session suite, targeted issuer regressions, shared OIDC
account regression and registered console routes with owned TLS providers pass.
Affected package race checks pass on macOS and Linux; startup integration and the
full application build are checked on Linux. No browser UI changed.

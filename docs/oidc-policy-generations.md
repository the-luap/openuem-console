# Durable OpenID configuration generations

Changing an OIDC setting and later restoring its previous value no longer
revives earlier authorization flows, pending MFA or completed sessions. A random
UUID generation identifies the configured policy under which authentication
started. The original generation remains attached to that evidence throughout
provider verification, account resolution, final admission and subsequent use.

## Changes that retire earlier evidence

Database triggers rotate the generation when an effective OIDC value changes:

- OIDC enablement;
- issuer URL, client ID or provider adapter;
- required role or group;
- automatic account creation or approval.

Authentication-row identity changes, insertion, deletion and truncation also
rotate the generation. Recreating the same configuration cannot restore its
earlier UUID. Changes away and back within one committed transaction still
retire earlier evidence. A transaction rollback restores the original generation
with its original policy and preserves valid retries.

No-op saves and changes limited to password/certificate enablement, public
registration or the OIDC flow-cookie encryption key do not rotate this OIDC
policy generation. Cookie-key replacement retains its existing cookie-decryption
behavior; local password/certificate generations remain independent.

## Admission and request checks

The console captures current policy values and their generation in a bounded
transaction before contacting the identity provider. The encrypted browser flow
retains that generation with its state, nonce, PKCE verifier and redirect. The
callback requires the same current generation before exchanging its code.
Account resolution and session creation keep the original captured generation;
they cannot refresh stale evidence to the latest policy after provider checks.

Final callback and MFA admission compare the complete policy and generation
while holding configuration, binding and account locks. MFA enrollment, recovery
code creation and disabling MFA use the same original policy binding. Existing
identity revisions, account eligibility, one-use primary evidence and TOTP
counter checks remain in force.

Protected requests reject missing or changed generations and clear authenticated
session state. A transient database failure returns service unavailable and
preserves the session for retry. Configuration row waits obey that distinction:
committed changes retire old evidence, while rollback permits the original
session to continue. Requests already admitted before a change may finish;
domain operations retain their own authorization boundaries.

## Migration and operations

OIDC account migration `002_policy_generation` seeds a singleton generation and
installs schema-bound triggers on the existing authentication table. Repeated
startup preserves the UUID and rejects missing generation rows or disabled or
missing triggers. A relevant configuration write fails if its generation cannot
be updated. Trigger functions use the application schema even when a writer has
a different search path.

Deploy the updated console instances together and stop older authentication
readers before migration; old readers do not enforce generation comparison.
Authentication writers must retain access to the generation table and must not
disable its triggers. Existing account bindings, grants and provider mappings
remain intact. Previously started browser flows and sessions without generation
evidence require a fresh OpenID sign-in after upgrade. This is not an identity
provider logout or a replacement for account-specific binding revocation.

## Verification

Owned PostgreSQL/race tests cover restoration of all seven policy fields,
configuration deletion/recreation and truncation, no-op/unrelated writes,
rollback, repeated migration, missing protection and pinned trigger search paths.
Old resolution, admission, session and MFA evidence is rejected; fresh policy
capture succeeds without changing the account's binding revision. MFA staging,
confirmation and disabling also reject restored policy values.

Registered Linux routes use a real owned TLS discovery/JWKS/token/UserInfo
provider and both plaintext and encrypted database session-token IDs. They test
old browser flows and completed sessions after every policy-field restoration,
legacy missing-generation evidence, fresh sign-in and changes between earlier
verification and final callback/MFA admission. Transient binding/configuration
locks preserve valid retries. The full OpenID account PostgreSQL/race suite
passes in 28.435 seconds; the final generation/MFA regression passes in 14.850
seconds and shared protected MFA enrollment in 23.743 seconds. macOS/Linux
package race checks and the full Linux build pass. Broader results are recorded in
[implementation status](implementation-status.md). These tests establish local
authentication behavior; production identity-provider acceptance remains
separate.

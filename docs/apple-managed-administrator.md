# Managed Mac administrator

A new ADE enrollment profile can request one managed local administrator, with a
short name, optional full name, hidden-login-window setting, primary Setup
Assistant account mode, and a manual or 1–365 day password rotation interval.
The policy is immutable and applies only to new admissions. Existing profiles and
manual enrollments do not acquire an administrator policy retroactively.

The implementation uses Apple's device-channel `AccountConfiguration`,
`DeviceInformation.AutoSetupAdminAccounts`, and `SetAutoAdminPassword` commands.
It requires ADE, a Setup Assistant hold for creation, reported supervision,
current device inventory, and a valid management identity. Apple lists conflicting
supervision requirements in its command schema and web documentation; OpenUEM
requires reported supervision conservatively. Its standard inventory obtains
that field on macOS 10.15 and later.

## Creation and setup

Every admitted Mac receives a separate random 256-bit password. The database
stores it with authenticated encryption, bound to its tenant and credential ID.
Apple receives only a nested SALTED-SHA512-PBKDF2 plist containing a random
32-byte salt, 40,000 iterations, and 128-byte derived key. Neither a password nor a
hash is stored in the shared ADE profile definition or public page model.

The setup hold cannot be released until macOS acknowledges account configuration
and the normal inventory/profile readiness checks pass. That acknowledgement
means command processing, not completed local account creation. After acceptance,
OpenUEM requests account inventory and binds the configured short name to the
reported GUID. The GUID is immutable. Missing accounts, duplicate matches,
malformed IDs, and changed GUIDs prevent rotation. Delayed inventory uses the
request creation time; replies from before account configuration acceptance do
not establish the account identity.

## Password changes and recovery

A password change requires a current report of the bound account and an ended
MDM configuration hold. Manual and scheduled changes retain a new encrypted
candidate and command atomically with their audit event. Scheduled changes run
only after a previous acknowledged operation; failures and unknown outcomes stop
the schedule. An authorized operator can pause or resume future scheduling per
device. A pause persists across acknowledgements, permits explicit manual changes,
and does not recall already queued or sent commands. Resume starts a new interval
when the last operation is acknowledged; unresolved/failed mutations remain
blocked from automatic retries. Normal six-hour inventory refreshes supply account observations.
At most 128 passwords are retained per enrollment; reaching this limit stops
further password generation rather than discarding recovery history.

An unanswered sent mutation is not automatically redelivered. An explicit
`NotNow` response permits deferred delivery of the same command and candidate.
A sent command that expires becomes uncertain and blocks further mutations.
A late terminal response for that exact command can resolve it. Duplicate older
responses cannot restore a previous credential. A failed creation can be retried
explicitly only while Setup Assistant still awaits configuration.

Command acknowledgement does not verify an actual login. An error may leave the
password outcome unverified. The UI therefore identifies the **last acknowledged
password**, not a proven current login password. Previous and proposed passwords
remain available through an explicitly confirmed, audited POST with a protected,
uncached text response. Revocation or checkout stops scheduling and retains
credentials for recovery. Generic command retries cannot replay these mutations.

Creating or assigning an administrator-bearing ADE profile and requesting password
changes requires device security management rights in the relevant scope.
Retrieval requires recovery-key retrieval rights. The store rechecks authorization
inside the mutation/reveal transaction; a failed audit prevents disclosure.

A remote local administrator password change **does not change its Secure Token
password**. It must not be represented as a FileVault unlock-password reset.
This feature does not yet install or configure Platform SSO.

## Validation and remaining acceptance

Synthetic tests cover the independent PBKDF2 vector, generated salt, policy
validation, wire structures, durable provisioning and setup order, account
identity binding, password history, manual/scheduled changes, NotNow, expiry,
late responses, scope/permission boundaries, failed-audit rollback, and checkout.
Protocol tests and template generation pass locally. The initial implementation
at `2a04e66` passed all four jobs in both
[push CI](https://github.com/the-luap/openuem-console/actions/runs/34310149557) and
[PR CI](https://github.com/the-luap/openuem-console/actions/runs/34310152746), including
PostgreSQL/race tests, Linux/Windows builds, console routes, gateway authorization,
and existing agent lifecycles. Its five synthetic UI states passed keyboard,
confirmation, permission-control, and overflow checks at 390, 768, and 1440 pixels.
Follow-up commits add route-specific, audit attribution, concurrency, observation
ordering, and pause/resume checks. Their results are retained in the
[branch workflow history](https://github.com/the-luap/openuem-console/actions).
The generated console fixtures are preserved as CI artifacts for browser checks.

No account or password was changed on the development host or on a real device.
Real Apple/ADE admission, Setup Assistant account creation, login with the
retained credentials, rotation, Secure Token behavior, and loss/recovery scenarios
still require explicitly authorized physical Mac acceptance.

## Apple references

- [AccountConfiguration](https://developer.apple.com/documentation/devicemanagement/account-configuration-command)
- [SetAutoAdminPassword](https://developer.apple.com/documentation/devicemanagement/set-auto-admin-password-command)
- [Password hash format](https://developer.apple.com/documentation/devicemanagement/passwordhash/salted-sha512-pbkdf2-data.dictionary)
- [Set up local macOS accounts](https://support.apple.com/guide/deployment/set-up-local-macos-accounts-depca092ad96/web)

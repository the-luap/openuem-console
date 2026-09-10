# Protected first-administrator bootstrap

The individual console deployment initializes its first administrator from a
protected password file. Account creation, the administrator grant, its audit
entry and permanent completion record commit together. Startup errors cannot
leave an account without its intended access or grant access to a pre-existing
uninitialized account. The password is not printed, returned or stored in clear
text in the database.

```dotenv
OPENUEM_INDIVIDUAL_AGENT_MODE=true
OPENUEM_BOOTSTRAP_ADMIN=openuem
OPENUEM_BOOTSTRAP_PASSWORD_FILE=/run/openuem-setup/initial-password
```

The account name defaults to `openuem`. It has 1–128 ASCII characters, starts with
a letter or digit, and otherwise allows letters, digits, `.`, `_`, `@`, `+` and
`-`. The protected file contains a generated password of 32–128 printable ASCII
characters without spaces. One final LF or CRLF is accepted. The file must be a
private regular file; a final symbolic link, directory or broadly accessible file
is rejected. Keep its parent directories trusted. Unix files must be owned by
the service identity or root with no group/other permission; Windows uses the
shared protected-file ACL checks.

The first login requires choosing a different password. Reusing the initial
password is rejected. After successful initialization,
remove the initial-password mount when it is no longer needed for first login.
Subsequent starts do not read that file. Changing its contents cannot reset the
account. Password changes, MFA, revoked grants and deletion of the original
account survive restarts. A retained completion binding also prevents silently
changing the configured first-account name. Restore the installation's database
records as part of recovery; this mechanism is not an account-repair tool.

The [reference composition](reference-composition.md) supplies that mount through
the explicit `compose.bootstrap.yaml` overlay. Its initialized base definition
omits both the mount and file environment setting. The separate-container fixture
completes first login, shuts down and recreates the console without the overlay,
then verifies the retained password through the gateway and preserves the original
protected provisioning file.

The console rejects `--reset-openuem-user` / `resetopenuemuser` while protected
bootstrap is selected. The CLI and installed Linux/Windows services load the
configuration before normal startup, and both immediate and delayed database
startup paths use the same initializer. An initialization failure prevents
listener startup. The installed individual service also reads
`ENCRYPTION_MASTER_KEY`, matching the existing foreground CLI configuration.

An already bootstrapped legacy installation is recognized by its permanent access
bootstrap record and receives no new account or grants. An occupied account
registry without that record is rejected: finish its explicit legacy access
bootstrap before switching deployment modes. Setting
`OPENUEM_BOOTSTRAP_PASSWORD_FILE` also explicitly selects protected setup without
the individual broker mode. Legacy mode without that setting retains its existing
manual account initialization behavior.

This component consumes a protected provisioning input. The offline
[installation secret provisioner](installation-secrets.md) now generates and
retains that input together with the runtime signing/encryption keys. Secret
distribution, the complete setup wizard, separate administrator PKI,
container volume ownership and the full reference composition remain separate
installation work. Existing JWT, encryption, listener, broker and database
configuration is still required.

## Password replacement authorization

The real console password-change route now requires a verified server-session
proof. Starting email recovery identifies the account but cannot authorize a
password change. A correct initial password, a verified unexpired recovery code,
or a valid account invitation grants at most 15 minutes to choose a password.
Recovery/invitation expiry can shorten that interval.

The proof is bound to the current password hash and exact recovery/invitation
record. A database transaction checks those bindings under an account row lock,
writes the new Argon2id hash, consumes recovery and invitation material and deletes
the account's existing session rows. Only one competing replacement can commit;
stale, expired, unverified or superseded proofs cannot change the new password.
An invitation's GET link no longer consumes it before the password transaction.
Recovery links use the configured console origin, and rejected recovery codes
are not written to logs.

Existing password-replacement sessions from before this change have no verified
proof and must restart the appropriate flow. The authenticated account-settings
password-change workflow remains separate.

## Evidence

`internal/setup/administrator` uses PostgreSQL and the real Ent schema to test
atomic initialization, audit-failure rollback, exact retries, competing initializers,
retained account/MFA/grant changes, deleted accounts, legacy adoption, changed
binding and missing completion state. File tests cover bounds, ownership/access
controls and invalid material without logging passwords or hashes.

The actual console router, CSRF middleware and PostgreSQL session store cover
initial login, forced password replacement, old-password rejection, a second stale
browser session, restart without the setup file, unverified/wrong/superseded email
recovery codes, successful verified recovery and encrypted account invitations.
The email fixture captures notifications in a local NATS process; it sends no mail.
Additional transaction tests reject expired/replayed proofs and roll back password
changes when session retirement fails.

The native console workflow checks Linux/Windows configuration and protected
files. The main PostgreSQL CI job also runs the full initializer and router tests
with the race detector.

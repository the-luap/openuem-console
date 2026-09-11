# OIDC sign-in verification

OIDC uses the configured issuer and public client with Authorization Code Flow
and S256 PKCE. The callback URL is the configured console origin plus
`/oidc/callback`; request hosts, forwarding headers and referrers cannot change
it. No redirect address is shared between requests. Register this exact callback
at the identity provider.

An encrypted, host-only, Secure/HttpOnly/SameSite=Lax cookie binds state, PKCE
verifier, nonce, issuer, client, callback and access-policy configuration. Its
ten-minute expiry is checked by the server. The callback clears the cookie and
rejects duplicate cookies, malformed/duplicate security parameters, expired
flows and changed configuration before calling the provider. Responses use
`no-store` and `no-referrer`. Previously started sign-ins using the old separate
state/verifier cookies must be restarted after upgrading.

Before reading UserInfo or creating a session, the callback verifies the ID
token's signature, exact issuer, client audience, expiry, issued-at value and
nonce through the existing go-oidc verifier and additional claim checks. Issued-at
values may be at most one minute ahead. An authorized-party claim must identify
the client; multiple audiences require that claim. A provided access-token hash
must match. UserInfo must identify exactly the same subject. Missing ID tokens,
non-Bearer token responses, invalid identities and provider role failures cannot
create a console session. These checks follow the
[OIDC token-validation requirements](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation)
and [UserInfo subject binding](https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse).

All provider traffic uses HTTPS, normal certificate verification, a shared
twenty-second request deadline and one-MiB response limits. Redirects are not
followed. Token/UserInfo/role responses require HTTP 200 and valid UTF-8 JSON.
Access tokens are limited to 32 KiB and ID tokens to 256 KiB. Provider response
bodies and credentials are not returned in errors. OAuth tokens are not passed
into the local session-admission object or stored in the console session.

Authentication settings reject issuer URLs containing credentials, queries or
fragments, and reject non-HTTPS issuers. Configure HTTPS before upgrading an
installation that previously used an HTTP identity provider. Invalid settings
do not disable existing emergency certificate/password authentication overrides;
those overrides change only after a successful settings save.

Authelia, Authentik and Keycloak continue to use the configured UserInfo group
requirement; Zitadel uses its authenticated role endpoint. Policy changes during
sign-in invalidate the flow, and session admission rechecks the same policy.
The selected local account must permit OIDC exclusively. Automatic approval
cannot reactivate a revoked account. Existing organization/site grants continue
to be checked by the console's authorization layer.

## Account identity and existing-account migration

The verified, case-sensitive `(issuer, sub)` pair selects the local account.
`preferred_username`, name and email never select or merge accounts. Changes to
those profile claims cannot transfer existing permissions. UserInfo may omit
`preferred_username`. Issuer changes require an explicit new binding, even when
the new provider reports the same subject.

Before upgrading an installation that uses OIDC, retain a tested password or
certificate administrator account. Existing OIDC accounts are not automatically
bound by username and cannot sign in until an administrator registers their
subject. If a valid fallback administrator exists but its authentication method
is disabled, the console's existing `--re-enable-passwd-auth` or
`--re-enable-certificates-auth` startup option can restore that method during
migration. These options do not create an account or grant administrator rights.
Keep the fallback available until the migrated identities have been tested.

1. Sign in as a server administrator and open **Manage OpenID account identities**
   from Users or Authentication settings, or visit `/admin/oidc-accounts`.
2. Enter the existing local account ID and review its name, configured issuer and
   client ID. Obtain the provider's exact subject for this client through a
   trusted administrative channel. Pairwise subjects may differ between clients;
   an email address or displayed username is not sufficient evidence.
3. Enter the subject, confirm the target account and select **Link identity**.
   The account's existing grants remain unchanged. Organization administrators,
   operators and viewers cannot register identities.
4. Test the user's sign-in and required organization/site access. Review the
   identity history and retain the fallback administrator until acceptance is
   complete. A changed account revision or provider configuration requires a
   fresh review before saving.

Each issuer/subject pair permanently belongs to one account. An account can have
one active subject per issuer and at most 100 retained bindings. For a subject
replacement, disable the current binding first, then explicitly link its
replacement. Disabled pairs remain reserved, preventing automatic registration
or another administrator from transferring them to a different local account.
They can be enabled again only for their original account. An administrator
cannot disable their own identity; another server administrator must do so.
Bindings for a different configured issuer remain dormant until that issuer is
selected again. Review them before changing the provider back.

Changing a binding invalidates this account's existing OpenID sessions on their
next protected request. Disabling also blocks future sign-ins. Remove the
account's access grants and review other sessions under Active sessions when
retiring it. Accounts with identity records cannot be deleted and recreated:
database foreign keys preserve the permanent association and its audit history.
The UI explains this restriction instead of exposing a database error.

When automatic creation is enabled, a previously unseen verified pair creates a
new opaque `oidc-<UUID>` local ID, its binding and an audit event atomically. It
never adopts an existing account's ID or permissions, including when its name
or email matches an administrator. Automatic approval controls its registration
state; explicit access grants are still required. With automatic creation
disabled, an administrator must create an OIDC account and link its identity.
Repeated or concurrent first sign-ins reuse the same binding.

Authentication configuration is rechecked under a database lock during account
resolution. Administrator changes recheck current server permissions within the
same transaction, serialize binding changes, compare the account revision and
require committed audit evidence. Account creation, binding changes and revision
increments roll back if auditing fails. The page shows the latest 25 changes;
records are retained.

OpenID sessions carry the admitted local account, subject, binding revision and
authentication policy, without provider tokens. Every protected console request
checks the current binding, account mode/approval and configured policy within a
five-second database deadline before second-factor or authorization processing.
Missing legacy evidence, changed policy or binding revision, inactive identities,
revoked/unapproved accounts and account-mode changes reject the request and clear
its authenticated session state. Disabling then re-enabling a binding does not
revive old sessions. Temporary database errors return service unavailable and
leave the valid session available for a later retry. Requests that already passed
this check may finish; this does not claim atomic cancellation of in-progress
operations. Changes reverted to the same policy before a session is checked are
not a permanent policy-revocation mechanism; change the identity binding to
invalidate that account's existing OpenID sessions permanently.

Every successful OIDC callback starts a fresh session, including a repeat login
to the same account. Previous second-factor and password-recovery flags are
cleared, and the previous session token is retired. Local second-factor checks
must be completed again when required by the account. The authenticated cookie
is written only after session-owner association and login confirmation succeed.
Login confirmation also refuses to reactivate an account revoked after identity
resolution. On failure, authentication values are cleared before bounded session cleanup,
so a cleanup error or the session middleware's later save cannot issue the
failed account's authenticated session. This is failure-safe admission, not a
single transaction spanning the session store and all account operations.

Provider-specific production configuration, actual IdP acceptance and the other
SSO/SEC-01 requirements remain open.

Regression evidence includes the previously referrer-controlled callback,
owned TLS discovery/JWKS with real RSA-signed tokens, invalid signature/issuer/
audience/nonce/expiry/issued-at/authorized-party/hash cases, bounded transports,
flow expiry and changed configuration. Disposable PostgreSQL tests exercise the
real router, PKCE exchange, all four provider adapters, actual session cookies,
single-use authorization codes, role denial, mismatched UserInfo, other account
modes and revoked accounts. The production authentication form is also tested
against unsafe issuer URLs and unchanged settings/overrides on rejection.

Additional disposable PostgreSQL race tests cover explicit existing-account
migration with preserved grants, issuer isolation, disabled/revoked identities,
account-mode conflicts, competing administrator links, twelve concurrent first
sign-ins, audit rollback and protected account deletion. Real console routes
exercise administrator-only reads/mutations, CSRF, confirmation, stale forms,
provider changes and redacted deletion failures. Browser tests cover unlinked,
active, disabled, ineligible, long and disabled-provider states at 390/768/1440
pixels, including keyboard confirmation and exact hidden account/provider fields.
Owned regression fixtures also reproduce and reject inherited 2FA/recovery flags
and authenticated sessions after owner-association or confirmation failures.
The fixed cases cover both account switching and reauthentication, old-token
retirement, and injected session-store and cleanup failures.
Session creation now shares the failure-safe operation used by the other login
methods. Actual local TOTP completion preserves the current OpenID identity while
renewing the token; missing identity evidence requires reauthentication instead of
promoting the partial session.
Protected-route tests cover live identity/policy changes, revocation and account
mode/approval changes, missing legacy evidence, database lock cancellation and
recovery, and an account revoked by a database trigger during admission.
This matrix also runs with encrypted database token IDs; shared storage behavior
and remaining lifecycle limits are documented in [session storage](session-storage.md).

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
The selected local account must permit OIDC. A provider username cannot select
a password-only or certificate-only account, and automatic approval cannot
reactivate a revoked OIDC account. Existing organization/site grants continue
to be checked by the console's authorization layer.

The local account lookup still uses `preferred_username` for existing OIDC
accounts. Immutable issuer/subject-to-account registration and its explicit
administrator migration remain separate implementation work; these protocol
checks do not claim to complete that account-linking requirement or SSO/SEC-01.
Provider-specific production configuration and actual IdP acceptance also remain
open.

Regression evidence includes the previously referrer-controlled callback,
owned TLS discovery/JWKS with real RSA-signed tokens, invalid signature/issuer/
audience/nonce/expiry/issued-at/authorized-party/hash cases, bounded transports,
flow expiry and changed configuration. Disposable PostgreSQL tests exercise the
real router, PKCE exchange, all four provider adapters, actual session cookies,
single-use authorization codes, role denial, mismatched UserInfo, other account
modes and revoked accounts. The production authentication form is also tested
against unsafe issuer URLs and unchanged settings/overrides on rejection.

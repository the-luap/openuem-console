# Desktop invitations in the console

The Desktop enrollment page now creates release-bound Windows/macOS invitations
for the explicitly selected organization and site. This connects console operators
to the [native agent enrollment command](https://github.com/the-luap/openuem-agent/blob/8bc63f8ed7272eef1f0414d31449531e637245dc/docs/native-enrollment-command.md).
It is an administrator workflow with a [public installation page](desktop-public-protocol.md)
for each created link. Finished signed end-user installers, guided native consent
and installer-driven activation remain open. Administrators can use the separate
[Windows activation command](https://github.com/the-luap/openuem-agent/blob/0649326763aa426a8f7cc4505d6a27b7e4b30f19/docs/native-windows-activation.md)
after completed enrollment; macOS service registration is still outstanding.

## Availability and scope

The organization authority, configured public desktop listener, dedicated bootstrap
signer and a current approved release must be available. Only release targets with
separate signed installed-agent size/hash bindings appear in the form. Older preview
packages cannot authorize this flow. The page reports missing setup rather than
offering an unusable create button. When viewing all sites, choose a specific site;
the page includes direct site links even when the organization has only one site.

Readers can see scoped invitation metadata. An operator with `EnrollDevices` in
the selected scope can create or revoke invitations. Organization-wide certificate
setup and device-identity revocation retain their separate permissions. Each POST
reloads the session principal. The handler derives organization/site IDs from the
authorized route and public origin from server configuration, never from submitted
scope fields or a request host.

## Creation

Choose an available computer type, 1–1000 computers, and a validity of up to one
hour, four hours, one day, three days or seven days. The default is one computer
and one day, with no computer type selected and no preselected confirmation.
The displayed release expiry can shorten the chosen validity. Confirm the selected
organization/site before submitting.

The form carries the exact reviewed release digest. A stale digest returns a
conflict with the current form, preserving valid selections for review. The handler
checks each of six fields appears once and rejects additional scope/origin fields,
query parameters, unsupported targets, missing confirmation and invalid limits.
Native forms use the existing cookie/token and same-origin CSRF controls. The
logical form is bounded to 8 KiB; the outer console CSRF parser retains its existing
4 MiB network bound for ordinary forms before the route's narrower checks.

Before committing an invitation, the catalog opens and hashes the selected package
and the store rechecks the current approved release, invitation lifetime, authority
and actual site ownership in its transaction. Invitation creation, release binding
and the scoped actor audit commit together. A withdrawn/changed release or changed
package cannot publish an invitation. GET requests never create or consume one.

## Token handling

The successful POST displays the installation link and canonical limited token once, with selected target,
organization/site IDs, release, capacity and exact expiry. The response uses
`Cache-Control: no-store`, `Referrer-Policy: strict-origin` and escaped HTML. No token
is placed in a redirect, query string or session; subsequent lists expose only
invitation metadata. The database retains its hash. Browser-local copies of the
initial response or clipboard remain the administrator's responsibility.

An administrator securely provisions the token into the native command's private
invitation file and supplies independently authorized origin/scope and release keys.
The token does not contain a permanent endpoint key or organization CA private key.
Creating it does not install an agent, activate a service, issue a device identity
or prove the computer is online. Revocation stops further use while existing
individual identities retain their separately controlled lifecycle.

## Verification

The real console router, session/permission store, Ent schema and PostgreSQL registry
tests cover reader/operator separation, foreign-site denial, CSRF, ambiguous fields,
invalid limits, unsupported/preview targets, stale releases, package mutation,
missing signers, exact expiry/scope, atomic audit and token-free subsequent lists.
Rendered-form regression checks also enforce real HTML boolean-attribute semantics
so the default expiry and unselected target survive browser parsing.

A disposable browser fixture exercised native authority setup, single-site
navigation, required confirmation, successful creation and the subsequent list.
The form/result fit 390-, 768- and 1440-pixel viewports; light and dark rendering were
inspected. This browser-only fixture can use `OPENUEM_DESKTOP_BROWSER_HTTP=1` on
`localhost` without changing browser/system certificate trust. It is opt-in test
code, supplies only an isolated test session and drops its schema on exit. Its
configured public enrollment origin remains HTTPS; the actual gateway/native
protocol continues to be tested separately through both TLS legs.

Console commit `e75f777` passed [native/console CI](https://github.com/the-luap/openuem-console/actions/runs/34195300064),
including scoped invitation creation and Linux/Windows builds. The subsequent public
page adds browser instructions and read-only downloads without changing issuance.

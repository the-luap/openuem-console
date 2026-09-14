# Reviewed native NetBird removal in the console

The native device NetBird page now links to local removal review and retained
removal history. The exact-site route family is
`/tenant/:tenant/site/:site/computers/:uuid/netbird/removals`.
It uses the [native removal request](netbird-removal-requests.md),
[joined dispatcher](netbird-removal-dispatch.md) and
[reviewed recovery](netbird-removal-resolutions.md) lifecycles.

## Review, queue and cancellation

Opening `/review` requires current `software.assign` authority at the device's
explicit organization and site. The individually enrolled agent must provide
fresh native package, service and process ownership evidence. The review displays
the exact installed version, platform, architecture and state fingerprint, and
explains connection interruption and retained local settings/provider state.

Positive native absence produces an informational page without a removal form.
It never resolves an earlier uncertain request by itself. An eligible present
review supplies a fresh request UUID, installed-descriptor digest and review
revision. Its unchecked confirmation is required before POST can queue that exact
intent. Current authority and native evidence are rechecked on submission.

Request POST commits the immutable intent for asynchronous dispatch. It does not
wait for native removal. Replaying the same form reads its original request without
another inspection or delivery. Both ordinary forms and HTMX retain the exact
request path; the latter disables pending controls and suppresses duplicate sends.

Undelivered requests expose an explicit, revision-bound cancellation form with
its own permanent UUID. Cancellation remains available after an immutable
preflight stop. An admitted native attempt excludes cancellation in the service
and database, including races with background delivery.

## Coherent status and original evidence

`GET /:request` and `GET /` require current `software.read` authority in the
original site. They read retained evidence without contacting the agent or
depending on its current enrollment, installed package or provider state. A
shared lock on each parent request joins original intent, native delivery,
dispatch stop and resolution into a coherent status; stage writers hold that
same parent's exclusive lock.

History returns twenty requests at a time. Its immutable cursor belongs to the
same device and exact original scope. Status distinguishes queued, stopped,
cancelled, dispatched/pending, unconfirmed, completed and explicitly released
requests. The original delivery outcome and record time remain separate from
later receipt observations, verified completion and recovery proof. Release does
not claim removal success or deletion of retained local recovery data.

Pages offer manual status reload. Readers and terminal receipts have no removal
actions. Native delivery exposes explicit read-only receipt observation and an
expiring recovery review. Review confirmation uses the original request revision,
one permanent resolution UUID and its temporary review revision. Replaying a
consumed review reads history; an additional control needs another explicit
review. Lost replies can be reconciled through a read-only receipt query.

## Routes and form protection

The route group registers authenticated GET history, review, receipt and recovery
review, plus POST request, cancellation, receipt observation, reviewed resolution
and resolution reconciliation. Its central capability mapping uses software
rights for every route. Native connection/provider operations retain their own
authorization and command grammars.

Pages are not cached. Actions require strict canonical UUIDs/digests, expected
single-valued fields, explicit confirmation and production CSRF validation.
All five POST paths apply an eight-KiB raw-body limit before token extraction or
form normalization, including unknown-length, header-token and ordinary browser
forms. Query/body mixing, duplicate fields and unknown fields are rejected.

## Verification and remaining work

Owned PostgreSQL races cover scoped, source-free status and twenty-row history,
identity drift and preservation of original unconfirmed results after reviewed
release. Registered HTTP routes cover reader/operator permissions, native
absence, queue and exact replay, current-scope failures, explicit cancellation,
ordinary-form redirects, CSRF and all five padded unknown-length POST paths.
The same route fixture dispatches four inert native callbacks and verifies
completion, later original-receipt observation, lost withdrawal reply with
read-only reconciliation, reviewed release and consumed-form replay.

Rendered view and middleware races cover escaped metadata and protected forms.
Seventy-eight Chrome cases exercise twenty-three review/absence/progress/history/
recovery states at 390, 768 and 1440 pixels, including keyboard confirmation,
pending progress, duplicate suppression, scoped pagination and long metadata.
The complete browser matrix includes these cases alongside existing workflows.
The full inventory race suite and Linux ARM64 console/handler builds cover the
integration. Fixtures do not remove vendor software or contact enrolled devices.

Retained local staging recovery remains required. Its [private combined
observer](https://github.com/the-luap/openuem-agent/blob/22899bf2e5110b988516aba52d28c3b9ddc66e39/docs/netbird-removal-staging-recovery.md)
now distinguishes exact original evidence, partial moves/purge and unknown
replacements, binding current service/process ownership and native receipt state.
Native absence uses successful typed package lists, including an empty database.
Native continuation and its reviewed public lifecycle remain open.
Journal release never removes staging, and fresh native removal continues to
reject interrupted staging.
Physical package, interruption, reboot, desktop and provider acceptance remain
separate from owned fixture evidence. The legacy unreviewed uninstall route stays
unavailable; local removal uses this reviewed lifecycle.

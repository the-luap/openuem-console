# Scoped desktop inventory refresh

Open a computer from **Device management**, then use **Request fresh inventory**.
The inventory page at `/computers/:uuid/inventory` is available to every role
that can read that device. Operators and organization/server administrators can
request a new report in their permitted organization and site. Viewers can inspect
the last request but cannot submit one. The organization/site URL prefixes are
supported for both reads and requests.

The legacy agent menu now opens this form. Its previous implementation started
an unjoined background publication and returned success before the broker
acknowledgement. Both `POST /computers/:uuid/refresh` and the retained
`POST /agents/:uuid/forcereport` aliases now use the same protected request path.
Clients must submit exactly one `request_id` UUID and the normal CSRF field;
request body fields cannot select a different organization, site or device.

## Request and delivery states

| State | Meaning |
| --- | --- |
| Waiting to send | The request and its audit event are committed; no handoff has been attempted |
| Delivery not yet confirmed | A handoff was attempted without a committed confirmation; the retained request will retry |
| Accepted for delivery | The expected command stream acknowledged the request; the device still needs to collect and send its report |
| Stopped before delivery | The request expired or its authority, device assignment, enabled state or command channel changed before an attempted handoff |
| Delivery could not be confirmed | Automatic retries stopped after an attempted handoff without a committed confirmation |

The latest device report may also come from the agent's regular schedule. A
request is never marked as a completed report solely because the command service
accepted it. An offline agent receives a retained command through its normal
durable consumer when it reconnects, subject to the command stream's retention.

There is one pending request per device and a one-minute admission cooldown.
Reposting the same request ID with the same actor, device and actual scope returns
the retained request without creating new work. Reusing it with different bindings
is rejected. Reload the inventory page to inspect delivery status.

The console tries at most five handoffs within ten minutes of admission. Retry
delays are 5, 10, 20 and 40 seconds. It uses the original request ID as the broker
message ID and requires acknowledgement from `AGENTS_STREAM`. Broker deduplication
has a finite window: collecting a report more than once remains possible after a
lost acknowledgement, long outage or database commit failure. This action requests
fresh inventory and does not execute arbitrary commands or carry configuration.

## Authorization and persistence

Admission and each handoff independently check current `devices.refresh` grants.
The device must have exactly one site across all memberships, belong to the
selected scope, and be enabled or awaiting contact. Individual-agent deployments
also require a current, unrevoked identity in that exact scope and a reconciled,
active command consumer. An old or foreign device ID cannot redirect the command
to another subject; device IDs are restricted to a single safe subject token.

The request transaction records `inventory.refresh.request`. During dispatch,
the console holds the permission, request, device and site locks. A shared lock
on the membership table prevents an extra hidden site edge from being inserted
between validation and publication. Readers remain available; membership writes
can wait during the bounded handoff. The publisher has a two-second deadline, and
each complete dispatch transaction is limited to ten seconds.

Before contacting the broker, the dispatcher commits `inventory.refresh.attempt`
through a second database connection. This evidence survives rollback of the
dispatch transaction or process loss after publication. The console must have at
least two database connections available. Failure to record admission or the
attempt prevents publication. A lost acknowledgement or failed completion commit leaves durable
uncertainty and the same request ID for recovery; it never becomes an unrecorded
success.

Queue rows and audit events use additive `uem_inventory_*` migrations. The worker
starts with the console, uses database ownership to coordinate replicas, and joins
cancellation on shutdown. Broker initialization can finish after startup; its
publisher slot is synchronized with the worker. Changing between legacy and
individual-agent mode stops pending requests from the previous mode.

The [audit log](audit-log.md) exposes the `inventory-refresh` source with actor,
action, device identifier, scope and outcome. It excludes report contents and
broker error text. Reviewed organization retention applies to terminal requests' audit events;
attempt evidence for queued requests is retained so pruning cannot reset retry
counts or erase uncertainty. Request records retain their original scope when a
device moves, and its current inventory cannot expose a former scope's requests.

## Verification

The integration suite uses the real Ent and registry schemas, current role grants,
an isolated PostgreSQL database and an owned NATS server. It covers role and URL
aliases, malformed/duplicate fields, CSRF, foreign and ambiguous memberships,
idempotent submission, cooldown, exact stream/message binding, individual identity
revocation/expiry/consumer changes, grant replacement and membership writes during
handoff, independent attempt commits, audit rollback, bounded retries, cancellation
and retention of active evidence. Device collection and delivery over real endpoint
networks remain part of physical Windows/Mac acceptance.

The [browser regression](../tests/browser/README.md) covers complete/incomplete
inventory and viewer/operator refresh states at 390, 768 and 1440 pixels. It checks
keyboard submission, exact form bindings, accessible delivery status, horizontal
overflow and the refresh anchor's clearance below the fixed header. The direct
server-close regression also verifies cancellation and joining before shutdown
returns, including when no HTTP listener has started.

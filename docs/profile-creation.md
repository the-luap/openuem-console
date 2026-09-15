# Legacy profile creation

Creating a desktop task profile now holds current server-administrator authority
and the selected organization/site through one transaction. The profile,
audience associations and audit event commit together. Global profiles have no
organization or site association; organization profiles have one organization
edge; site profiles have that organization and its verified current site.
A changed or mismatched site parent prevents creation.

New profiles retain the existing defaults: type winget, disabled false and
apply-to-all false, with no tasks or tags. Creation itself does not select
devices or send any task. Assignment mode, tasks and status continue through
their separate actions. The old direct model creation method has been removed.

The ten-second transaction shares the profile authority helper used by existing
status, metadata, tag, audience and deletion actions. Scoped requests hold the
organization/site rows as well as current server authority. Permission
revocation or a concurrent site move cannot overtake final audit commit.
Association failure, audit failure or cancellation leaves no partial profile.

The creation form shares the editor's bounded UTF-8 name validation and
full-width multiline field. It accepts one name and optional single
CSRF/pagination/sorting values in an 8 KiB URL-encoded POST. Assignment, status,
profile identity, alternate audience fields, duplicate values and query
parameters are rejected. The production CSRF/origin middleware enforces the
wire limit before token extraction. The native form requires a name, supports
keyboard submission and configures the Create button to be disabled while
HTMX has a request in flight.

Audit migration 21 adds inventory.profiles.create with the selected scope,
actor and new profile ID. The event is committed before the ID is returned and
is available in existing scoped audit browsing, export and retention. Global
events remain server-only. Apply the migration and stop older console writers
before using the new creation path.

Each accepted creation request creates a new profile. This endpoint does not
yet provide an idempotency key; an unavailable response instructs the user to
check the profile list before repeating the request.

Owned PostgreSQL/race tests cover all scopes, current roles, exact empty
defaults, name bounds, mismatched site parents, association/audit rollback,
cancellation and final permission/site locks. The actual route test reproduced
creation without an audit event and now verifies the retained scoped event.
Registered routes also verify CSRF, strict forms and saved state in all three
scopes. Browser tests use the actual form and bundled HTMX at 390, 768 and
1440 pixels for required-name validation, keyboard submission and exact scoped
request fields. Existing profile action regressions cover the shared helpers.

Cloning, other editor reads, task lifecycle and immutable definition history
remain separate workflows.

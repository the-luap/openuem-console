# Apple update plans

Select a site and open **Management pages → Apple update plans**. Plans retain
reviewed platform, OS version, build, device-local deadline and optional HTTPS
information URL. Their names and descriptions distinguish intended rollout
stages such as pilot and broad deployment. A plan is a reusable source; it is
separate from each device's current policy and observed update result.

The catalog and revision history now connect to
[immediate dynamic group assignments](apple-update-groups.md), with current
eligibility, reviewed policy replacements and immutable original request evidence.
[Scheduled group activation](apple-update-schedules.md) retains the same review
for a UTC activation window. Exceptions, promotion and per-cohort result tracking
remain separate implementation work. The existing device action continues to use
[transaction-bound update policy admission](apple-update-policy-admission.md).
Saving, revising or archiving a plan creates no device policy or notification.

## Scope, revisions and reads

Every plan belongs to one exact organization/site pair. Organization-level URLs
cannot create site plans through the console's usual site fallback. A moved site
makes the original plan unavailable in its previous organization; it does not
transfer the plan. There is no plan move or hard-delete action.

Current `devices.read` authority permits catalog/history reads. Current
`updates.manage` authority permits creation, revision, archival and reactivation.
These permissions, account state and current organization/site ownership are
checked and locked inside each bounded transaction. Read audits must commit before
returning a response. Mutation and audit failure roll back the new revision and
current pointer together.

A save requires the current revision. Concurrent submissions of the same revision
produce one next revision; the other receives 409. Archival is another retained
revision and does not alter existing device work. Readers cannot edit; operators
can review an older history page while their form still carries the current
revision. Lists and history have 25-entry pages. List cursors must identify a plan
in the selected site. History cursors are exclusive revision numbers belonging
to that plan's contiguous revision sequence.

Apple migration 044 installs stable plan identities and immutable revisions.
Each revision encrypts its complete definition. Authenticated associated data
binds the ciphertext to the plan, organization, site, revision, actor and exact
recording time. SQL forbids revision updates/deletion, plan deletion, scope changes,
revision rollback and skipped revisions. A deferred foreign key requires the
current pointer to resolve to a stored revision at commit. Ordinary formatting
and public structured serialization of plan values omit their protected contents.

## Validation and bounds

Plans select iOS, iPadOS or macOS explicitly. Versions use numeric dotted OS
versions; builds use 1–32 ASCII letters/digits. A deadline must be an exact
`YYYY-MM-DDTHH:MM:SS` without an offset, interpreted in each device's local time.
The browser's minute-only form value is normalized to zero seconds. Plan saving
validates the definition, not live device compatibility or catalog availability;
future assignment must check those conditions again.

Names allow 120 UTF-8 bytes, single-line descriptions 1,024 bytes and information
URLs 2,048 bytes. URLs require HTTPS without embedded credentials. Invalid UTF-8
and control characters are rejected. Definitions are limited to 8 KiB before
encryption; reads bound ciphertext before decrypting and reject unsupported or
malformed stored definitions. Responses never include internal error causes.

The limit is 1,000 plan identities per site, including archived plans; creation
uses a database transaction lock to serialize that limit across replicas.
Existing plans can still be revised at the limit. All operations have a ten-second
deadline. Save forms accept only an 8 KiB URL-encoded body with unique allowed
fields and an exact body CSRF token. Query overrides and unsupported media or
encoding are rejected. The global CSRF middleware enforces this limit before
normalizing form fields.

## Verification

Owned PostgreSQL 17/race tests cover current rights, site movement, competing
revisions, archival/history retention, no device work, immutable SQL boundaries,
protected serialization, ciphertext substitution, current/history pagination,
audit rollback and the 1,000-plan limit. Targeted tests pass in 6.240 seconds. The complete Apple PostgreSQL/race suite
passes in 476.388 seconds, including the new migration and existing protocol
workflows.
Registered Linux console routes exercise reader access and mutation denial,
explicit site selection, creation, archival, retained original history, stale
revisions, duplicate fields and query conflicts. Linux/macOS handler, middleware,
view and locale race tests and the full Linux build pass.

Eighteen Chrome cases cover list, empty, current, archived, viewer and long text
states at 390/768/1440 pixels, including keyboard save, exact current revision,
archive state, historical values and scoped paging. The twelve management
navigation cases also pass with the new site-only link. These are owned synthetic
checks and do not establish physical Apple update or provider acceptance.

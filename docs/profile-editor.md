# Scoped legacy profile editor

Opening a desktop task profile now checks current server administrator authority
and the complete global, organization or site audience inside one bounded
transaction. The editor reads editable metadata, a page of task summaries and
bounded tag choices. It does not load task definitions, passwords, SSH
passphrases or issue graphs. The audit receipt commits before a result returns.

## Scope and read consistency

The selected route must match the profile's complete audience: no organization
or site for global profiles; exactly the selected organization and no site for
organization profiles; exactly the selected organization/site pair with the
site's current parent for site profiles. Ambiguous, foreign or incomplete
associations cannot be read through a smaller route. Delegated tag-catalog
permissions do not grant legacy profile access.

Current authority, audience relations and the profile remain locked through the
receipt. Existing task and applied tag/edge rows are held, and the parent lock
prevents incoming task and tag associations. Available tag rows selected for the
response are held as well. Changes to names, memberships, ownership and grants
cannot change this reviewed source before commit. The operation has a ten-second
context bound; failure or cancellation returns no partial result.

Task summaries retain stable stored-order/ID sorting and dense display positions.
The read does not normalize stored task order or modify execution history.
Task pages accept 1–1,000 entries and page numbers up to 1,000,000, clamping to
the last available page. Invalid default page sizes fall back to five entries.

Editable profile names are limited to 2,048 UTF-8 bytes. A larger legacy name
produces a bounded preview and an empty required replacement field. Saving an
implicitly truncated name is therefore impossible. Other summary and tag labels
are bounded before they leave PostgreSQL.

## Tag management

The panel shows at most 50 applied tags and 50 available choices. Applied tags
have independent previous/next paging. Available tags support a literal,
case-insensitive name substring or an exact numeric tag ID; a 51st match produces
a prompt to refine the search. Queries accept at most 256 UTF-8 bytes, rejecting
NULs and malformed encoding. Available choices exclude existing assignments.

Global profiles can select tags across organizations. Organization/site profiles
can select only tags belonging to their organization. Labels include organization
and tag IDs. Existing foreign or unscoped assignments remain visible and removable
from the correctly scoped source profile. Mutation rechecks current ownership.

Separate native forms isolate metadata, tag search, addition and removal. Tag
search and paging preserve unsaved metadata and the current task page. Starting a
search clears the old selection. Pending requests disable editor fieldsets and
share request synchronization; a second panel request is dropped while one is
running. Search restores focus to its query, while other panel responses focus
the tag heading. The layout wraps long labels and retains a contained horizontal
scroll area for task tables at 390 pixels.

Adding a tag atomically changes the saved assignment to tags. Removing a tag
preserves `apply_to_all`. Native panel mutations use `ChangeProfileTagAndRead`:
the mutation, bounded response data and existing assignment audit commit together.
The fragment also replaces the assignment control to reflect that explicit
change. Unsaved profile names and task paging remain intact. A failed read or
audit cannot publish a panel for an uncommitted change.

## Routes and receipts

All routes have global, organization and site variants:

- `GET /profiles/:uuid` reads the scoped editor. It accepts bounded task paging
  and legacy sorting context; task order remains fixed by stored order and ID.
- `GET /profiles/:uuid/tags` reads the independent panel with `page` and `q`.
- `POST /profiles/:uuid/tags` adds using a bounded URL-encoded body.
- `DELETE /profiles/:uuid/tags` removes using query parameters and no body.

Mutations require the production CSRF cookie/header and origin checks. The
canonical route ID must equal `agentId`, and `tagId` must be canonical. Unknown,
duplicate, mixed-source and oversized fields fail before mutation. Small form
limits apply before CSRF parsing can cache a normalized body. Read endpoints
reject bodies, content encoding and unexpected query fields; responses use
`Cache-Control: no-store` and the editor disables HTMX history caching.

Profile creation and metadata save now return a scoped `204`/`HX-Redirect` after
commit, without a second database read. Cached tag forms targeting the whole
editor use the same redirect behavior. A separately failing read can no longer
turn a successful write into an apparent write failure.

Audit migration 30 adds `inventory.profiles.read` and
`inventory.profile_tags.read` for the three exact scopes. Resources identify the
profile and returned page dimensions. Search strings, tag labels, names and
secret values are omitted. Existing assignment actions retain their profile/tag/
revision receipt. Scoped browsing and JSON export cover the new actions. Apply
migrations and stop older console writers before enabling these routes.

## Verification and remaining scope

Owned PostgreSQL/race tests cover scope/role denial, current grants, summary-only
reads, legacy names, global and scoped choices, foreign associations, paging,
literal/ID search, cancellation, audit rollback and mutation/panel atomicity.
An advisory audit gate verifies held source, task, membership, tag and permission
locks and prevents results from returning before commit. The full inventory and
audit suites pass in 81.881 and 9.430 seconds respectively.

Registered Apple/OIDC console route tests use production CSRF and owned fixtures.
They cover all three scopes, strict queries/forms, private-field exclusion,
independent fragments, assignment replacement, redirects and generic read errors.
The browser suite adds 117 cases at 390, 768 and 1440 pixels, including native
keyboard submission, isolated parameters, long names, paging, retained unsaved
state and held XMLHttpRequest completion with pending controls/focus cleanup.
Mobile views were visually inspected. Affected macOS/Linux race checks and the
full Linux build pass. The complete 1,872-case Chrome matrix passes in 93.704
seconds.

[Profile report history](profile-issues.md) now has scoped, bounded read paths
that retain orphan records. [Manual execution](manual-desktop-execution.md) now
requires review and a durable single-attempt request. Package/provider/settings routes, broader
secret lifecycle, immutable revisions, delegated legacy permissions and
physical/provider acceptance remain open in the expanded roadmap.

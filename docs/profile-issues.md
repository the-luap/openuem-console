# Scoped profile report history

Opening legacy profile reports now requires current server administrator
permission and the exact global, organization or site profile audience. The
read preserves existing history. The two former model queries, which deleted
all endpoint-less profile issues across the database during GET requests, have
been removed from the web path and deleted.

## Authorized, bounded reads

`ReadLegacyProfileIssues` returns profile metadata and a page of issue summaries.
It selects bounded error previews and stored task-report counts, without task
configuration, passwords, SSH passphrases or task output. Results use descending
report time, NULL times last, and descending ID for stable ties. The default page
size is 25; explicit sizes from 1 to 100 and canonical page numbers up to
1,000,000 are accepted. Requests beyond the last page return that last page.

`ReadLegacyProfileIssueReports` independently verifies the exact issue/profile
relationship and returns 25 task reports per page in ID order. Each output/error
is limited to 4,096 characters with a visible truncation notice. Profile-level
error previews use 1,024 characters. Task/profile names, endpoint labels and raw
completion timestamps are bounded before leaving PostgreSQL.

The transaction holds current authority, the complete profile audience and the
profile. Existing issues are locked against incoming reports; existing report
rows preserve outcomes, output and counts through the receipt. Endpoint records,
complete site membership and referenced organization/site rows are held while
current identity is selected. Detail reads hold current referenced task rows.
Cancellation, lock conflicts or audit failure return no partial result. Each
transaction has a ten-second context bound.

Only an endpoint with exactly one valid current site can produce an endpoint
link. Its current organization/site must match the selected scoped profile;
global profiles can link endpoints across organizations. Links use the endpoint's
actual site, including when the profile is global or organization-wide. A foreign,
ambiguous, unscoped or missing endpoint does not disclose current identity through
an incompatible profile route. Its stored profile report remains accessible to
the authorized server administrator.

A current task label/link is shown only when that task still belongs to the
reviewed profile. Reports with unavailable tasks remain readable without exposing
a foreign current task's metadata. A currently disabled task does not suppress
its stored outcome or output. NULL report times show “Not reported”; valid
completion instants retain their RFC3339 nanosecond value and timezone-aware
presentation. Unrecognized reported timestamps retain a bounded, labeled raw
value instead of being interpreted as a different instant.

## Navigation and audit

The three scope variants expose:

- `GET /profiles/:uuid/issues`: paged summaries with `page` and `pageSize`.
  Bounded legacy sorting context is accepted, while ordering remains fixed.
- `GET /profiles/:uuid/issues/:issue`: independent detail pages with `page`,
  `issuePage` and `issuePageSize`. The latter two preserve the list destination
  for back navigation and do not affect authorization.

GET requests reject bodies, content encoding, duplicate/unknown fields and
invalid dimensions. Errors describe the read failure without database content.
Responses use `Cache-Control: no-store`, and HTMX history caching is disabled.

The full-width history uses separate summary and detail pages. Native links omit
inherited form data and retain the exact profile/issue and originating list page.
Navigation requests share replacement synchronization, and a completed page swap
focuses the new heading. Output wraps within bounded, keyboard-scrollable areas.
Empty history, missing endpoints/tasks, currently disabled tasks, invalid times
and truncated output have explicit text. The old embedded report modals,
duplicate IDs and nullable-task counter dereferences have been removed.

Audit migration 31 adds `inventory.profile_issues.list` and
`inventory.profile_issues.read` for the exact three scopes. Receipts identify the
profile, issue where applicable, and returned page dimensions. Endpoint names,
error/output content and task configuration are absent from audit resources.
Browse/export tests cover these actions. Apply migrations and stop older console
writers before enabling the new read paths.

## Verification and limits

Owned PostgreSQL/race tests cover scope/role denial, exact issue parentage,
retained unrelated orphan rows, disabled and unavailable tasks, endpoint moves
and ambiguous membership, stable paging, bounded Unicode output, NULL/invalid
times, audit rollback and cancellation. A gated audit verifies that source,
report, endpoint membership, task and current permission changes wait through
commit. The full inventory and audit suites pass in 85.605 and 9.399 seconds;
final focused history tests pass in 4.804 seconds.

Registered Apple/OIDC console tests cover the three scopes, strict GET inputs,
private-field exclusion, independent summaries/details, failed read receipts and
preservation after repeated requests. Affected macOS/Linux race checks and the
full Linux build pass. Seventy-two focused Chrome cases cover native navigation,
empty/orphan/disabled/long reports, timestamp values, current endpoint links,
isolated query fields, page URL/focus restoration and 390/768/1440-pixel layouts.
Mobile report views were visually inspected. The complete 1,944-case Chrome
matrix passes in 95.094 seconds.

These reads preserve the records that currently exist. They do not introduce
immutable execution history or alter worker report updates and task-deletion
semantics. One-off dispatch, package/provider/settings routes, wider secret
lifecycle, immutable revisions, delegated legacy access and physical/provider
acceptance remain open in the expanded roadmap.

# Account display language

Open **My Account**, choose **Display language**, then select **Save language**.
A new account follows `Accept-Language` from its browser, with English as the
fallback. An explicit selection applies to that account on every browser. Select
**Follow browser language** to restore independent browser negotiation.

The selector uses the existing English, Catalan, French, German, Norwegian,
Portuguese and Spanish catalogs. New copy is authored in the English catalog and
uses the existing translation library's fallback. Several newer management pages
still contain English copy; the preference does not claim full translation
coverage. Shared application, login and registration documents now identify the
active catalog through their HTML `lang` attribute.

The preference is persisted in `uem_user_preferences`, separate from authentication
and device permissions. Console startup applies its additive migration under a
transaction-scoped advisory lock. Existing accounts require no backfill. Deleting
an account deletes its preference. Each authenticated request reloads the value,
so existing sessions and new logins observe the latest committed selection. No
language value is accepted from another account ID, an arbitrary cookie or a URL
parameter. Simultaneous changes use the last committed selection.

`POST /myaccount/language` accepts only the canonical bundled code (or an empty
value for browser negotiation) and a form CSRF token. It uses the authenticated
account, rejects duplicate/unknown form fields and query parameters, bounds the
request to 8 KiB and uses the production token and Origin checks. A successful
save redirects to the account page with a confirmation. Account and save responses
use `no-store`. Invalid or unavailable storage never produces a successful save.
When preference loading fails, ordinary rendering falls back to the browser
language; the profile shows an unavailable state instead of an editable selector.

PostgreSQL race tests cover restart persistence, account isolation, all bundled
codes, invalid input, cancellation, account deletion, concurrent initial migrations
and failed saves. The real console router, session cookies and CSRF middleware
cover two existing sessions, a new login, browser reset, foreign account fields,
malformed forms, cross-origin requests and a missing preference table. Rendered
profile states cover all seven catalogs, browser default, storage unavailability
and long account values. The permanent Chrome matrix exercises those ten states
at 390/768/1440 pixels, native keyboard submission, exact form fields, locale
metadata and page overflow. [Report timestamps](localized-report-times.md) use the selected catalog while
keeping UTC explicit. Remaining date/number formatting, complete locale-key
migration and wider accessibility acceptance remain separate UX-01 work.

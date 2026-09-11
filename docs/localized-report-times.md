# Localized report timestamps

Native Apple management, shared software history, scoped computer reports and
desktop enrollment use a shared timestamp component. Audit events and retention
history use the same browser formatting with second precision. Display follows
the catalog selected by the account's language preference or browser negotiation.
The time zone remains explicitly **UTC**, regardless of the browser's local zone
or daylight-saving rules.

Each timestamp contains an ISO 8601 `datetime` value and a readable UTC fallback.
The browser formats the existing instant with `Intl.DateTimeFormat`, preserves
minute or second precision as specified by the page and always appends `UTC`.
The original ISO value remains available in the element and its native title.
Missing reports remain **Never reported** rather than becoming an epoch date.

The formatter writes text only. It observes inserted timestamp elements so that
partial-page navigation works without requiring a full reload. Each timestamp
carries its server-selected language; a later response can therefore use a new
account preference even in an already open page. Unsupported formatting or an
invalid instant leaves the server's text in place. JavaScript is not required to
read a timestamp. No report values are sent to an external formatting service.

This component represents instants. It does not convert device-local Apple update
deadlines, date-only certificate summaries, reported software installation-date
strings, form input values or signed request expiry fields. Audit filters, export
values, retention cutoffs and database timestamps retain their existing semantics.
Legacy native views and native Windows MDM pages with other date helpers still
need their own conversion; number/plural formatting and full locale coverage
remain UX-01 work.

Go view tests preserve exact UTC instants, minute/second fallback text, missing
reports and all seven language catalogs. Browser fixtures cover fixed-offset
input, UTC hours across a daylight-saving boundary, language-specific month text,
second precision, inserted content, unavailable formatting, invalid values and
untouched device-local deadline text. The existing production-page browser suite
also exercises the integrated component, including label/time spacing and narrow
screens. Real console router tests and full Linux ARM64 builds cover integration.

# Native Windows certificate health

The **Certificate health** link in native Windows management opens an audited
expiry and renewal overview. It requires current `certificates.manage` and
`devices.read` permission. Organization administrators can inspect one site or
all sites in their organization; device readers and operators cannot access this
report. Every device and renewal link names its concrete organization and site.
The public device gateway does not publish these console routes.

`GET /windows/certificate-health` is registered with the default selection,
organization and organization/site route prefixes. The default view shows
**Needs attention** with a 30-day warning period. The period accepts 1–365 whole
days. Search matches a literal, case-insensitive reported name or device ID;
SQL wildcard characters remain literal. Pages contain at most 25 devices,
ordered by access retirement, current certificate expiry and device ID. Applying
filters resets pagination. Page links preserve search, filter and warning period.

## Interpreting the report

The authority section shows its actual certificate expiry and the earlier end
of full-lifetime issuance: CA expiry minus the configured device certificate
lifetime and a five-minute margin. This is the same boundary enforced during
issuance. Its warning state remains readable after issuance becomes unavailable
or the CA expires; reading health does not authorize new issuance.

Each device shows the original enrollment certificate or latest confirmed renewal
generation. It also shows when that certificate enters the server's renewal
admission window. A pending replacement appears independently, with its own
expiry and status. A still-valid pending replacement does not hide an expired
current certificate. Canceled replacements are excluded from pending health and
remain available in renewal history. Confirmation evidence links to the verified
handoff record; earlier replaced certificates do not create additional device rows.

**Needs attention** includes active identities with an expiry warning, an open
renewal window, a pending replacement, a revoked or not-yet-valid identity, or an
issuer warning. Additional filters select all devices, the open renewal window,
expiry within the warning period, expired certificates, pending replacements or
revoked device access. These filters can overlap. Revoked device access is a
separate state from an individual certificate's revocation. Authenticated
disconnection reports, when present, retain their original receipt time and do
not prove local cleanup.

The displayed assessment timestamp is the database time used for expiry
comparisons. It is not a last-contact time or a historical snapshot of the whole
fleet. Refreshing obtains a new assessment. The server's renewal admission window
does not establish client scheduling, automatic renewal or Windows ROBO support.
No notification, scheduled renewal or device operation is triggered by this page.

## Integrity and verification

The report authenticates encrypted issuer policy, certificate DER and fingerprints,
relevant sealed renewal proof and confirmation evidence, and any included sealed
disconnection report. It holds fresh authorization and scope locks, then locks
selected device generations for the read. If confirmation changes the selected
generation while the page waits, it returns the current generation or a conflict
requiring a refresh; it never presents the superseded generation as current.

The transaction records `certificate_health.read` plus relevant protected-history
reads. Audit failure rolls back nested audits and returns no report. Migration
014 extends the allowed console audit actions without rewriting existing history.
Generic JSON/XML/YAML and formatted output omit protected report metadata.
HTTP responses use `no-store` and `strict-origin`; unknown, repeated, malformed or
out-of-range query fields fail.

The complete Windows PostgreSQL/race suite passes in **141.818 seconds**, with
the protocol suite also passing. Focused health tests cover inclusive expiry and
issuance boundaries, an expired issuer, expired current identity with a valid
pending replacement, canceled/confirmed handoffs, retirement, live permissions,
site moves, search/paging, tampering, audit rollback and migration preservation.
A real database lock wait exercises a concurrent authenticated confirmation.
Final console integration and Windows handler tests pass under the race detector
in **12.418 seconds**, Windows views in **4.530 seconds** and gateway tests in
**1.775 seconds**. Vet and Linux/Windows builds pass. Gateway tests verify that
the health paths remain administrative routes. Full CI for this extension is
pending.

An owned synthetic browser fixture passes 18 page checks at 390, 768 and 1440
pixels, covering valid, due, soon-expiring, expired, retired and empty states.
Long escaped names and fingerprints remain contained. The browser checks verify
one selected filter, labeled controls, keyboard focus and GET submission with
search/warning values and reset pagination. These are synthetic checks, not
physical Windows renewal acceptance. Deployment notification delivery, automatic
renewal configuration, CA rotation and the remaining WIN-02/PKI-01 work stay open.

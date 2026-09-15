# Apple pilot promotions to organization groups

Open an original assignment's **Current cohort progress**, choose **Review pilot
promotion**, select the destination plan, then choose **Organization groups**.
Review the original pilot evidence, the complete eligible destination selection
and all policy replacements before confirming.

The destination group's current rule is evaluated only within the selected
target site. Members elsewhere are outside this promotion. At least one eligible
destination enrollment must be outside the original pilot. Pilot devices that
also match the destination are explicitly included and receive the reviewed
destination policy again. **Site groups** preserves the existing site workflow.

This extends [reviewed pilot promotion](apple-update-promotions.md); its readiness
rules remain unchanged. Every original pilot enrollment needs qualifying fresh
OS evidence, matching current policy values, an active identity and no active
exception. The destination must retain the pilot's platform, version and build;
its deadline and information URL may differ. This is an explicit confirmation,
without automatic promotion or continuous group reconciliation.

## Source scope and authority

Preview and confirmation require current organization-wide `devices.read` and
target-site `updates.manage` plus `devices.read`. These grants can be composed
from an organization reader and a site operator. A site operator alone cannot
list or inspect an organization destination. Every route requires an explicit
target site; organization-only URLs cannot choose a default site.

Source kind remains in chooser, pagination, review and breadcrumb links. The
confirmation carries `group_source=organization` with both source revisions,
the request UUID, all reviewed native IDs and current-policy tokens, explicit
confirmation and body CSRF. The strict nine-field form retains its 16 KiB limit
and accommodates 100 targets. Unknown or duplicate source kinds are rejected.
Omitting the source keeps the old site-only behavior and cannot select an
organization group.

SQL restricts membership to the selected site before applying the complete
100-member bound. Source group, organization, target site and current authority
remain locked through admission. The canonical union of original pilot and
destination enrollments, at most 200 IDs, is locked before evaluating policies
and pilot evidence. Current source revision, plan revision, membership, policies,
identity, exceptions and release eligibility are rechecked in one transaction.
Pilot evidence, destination policies, notifications, child assignment, promotion
receipt and audits commit together. Late audit failure or evidence expiry rolls
back the complete admission.

## Original receipts and retries

New promotion receipts use encrypted intent version 2 to retain destination
group scope separately from the target site. The destination child assignment
must carry the same source scope, alongside all existing identity, revision,
selection and time bindings. Substituting a site child for an organization
parent, or the reverse, is rejected. The original pilot retains its own source
scope and evidence format independently.

Version-1 promotion receipts remain readable and retryable with their original
site source. Missing or invalid version-2 scope is rejected. No schema migration
or history rewrite is required; all instances reading newly written promotion
receipts need the updated reader.

An exact retry requires current authority, the original actor/grant revision and
identical intent, including source kind. Organization read rights are required
even for replay. Concurrent identical requests return one original promotion
and one child assignment. A later retry returns retained evidence before reading
mutable source or device state and cannot restore removed policies. Reusing its
request UUID with the other source kind returns a conflict.

Original target-site operators can read saved receipts and history after source
archival or later loss of organization visibility. Historical name, rule and
revision remain available. The link to the live organization group appears only
with current organization-wide read rights and uses the organization URL.
Device, destination receipt and progress links remain in the original target
site. History labels the retained source kind.

## Verification

Owned PostgreSQL/race tests cover composed grants, the site intersection,
injected other-site targets, original pilot evidence, current source and policy
changes, concurrent exact retries, final-audit rollback and retained history.
A gated final audit verifies that source group, site, pilot policy, destination
policy and permission changes cannot overtake admission. Tests also exercise
version-1 history and replay, version-2 validation and both directions of child
source substitution. The combined affected PostgreSQL/race regression passes
in 76.277 seconds. All 37 strict form cases, registered Linux routes, macOS/Linux
package race checks and the full Linux build pass. All 228 relevant Chrome cases
and the complete 1,284-case matrix pass. Mobile confirmation and historical
source details were visually inspected. Broader evidence is recorded in
[implementation status](implementation-status.md).

Console coverage includes strict form parsing, registered HTTP routes and
45 additional Chrome cases at 390, 768 and 1440 pixels. Browser fixtures cover
source choice, blocked readiness, overlap, exact keyboard confirmation, history,
role restrictions and long escaped metadata. These are owned synthetic checks;
physical installation, APNs delivery and pilot acceptance require separate
evidence.

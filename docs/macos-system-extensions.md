# Mac System Extensions profiles

The System Extensions editor creates an encrypted, versioned System profile.
Administrators can approve listed bundle identifiers, approve a developer team,
or block additional user approvals. Each editor profile selects one team;
uploaded profiles can contain multiple teams and payloads. The console requires
profile-management permission, CSRF protection and review confirmation.

## Policy behavior

The payload requires macOS 10.15 or later and user-approved MDM. User Enrollment
and the User channel are unsupported. Assignment checks the reported platform,
OS version and fresh security inventory. Application removal rules require macOS
12; SIP and System Settings/Finder removal restrictions require macOS 15.

The same team cannot have both team-wide and individual approval. An extension
cannot allow application removal and prohibit removal under SIP. Restricting
removal from System Settings/Finder can coexist with application removal. Types
and approvals combine across installed profiles; any profile disabling additional
user approvals preserves that restriction. Installing an allowing profile can
activate a pending extension; removing it can deactivate an extension.

The editor explicitly selects driver, network and endpoint security types.
Clearing all types writes an empty type list. Empty removal lists are omitted.
Switching modes disables inactive fields; the server rejects submitted inactive,
repeated, unrelated or query fields. Team identifiers, bundle lists, dictionaries,
booleans and extension types are validated before saving. Uploaded optional keys
remain optional. Presence of an empty version-specific dictionary still enforces
its minimum OS version.

## Assignment and retained revisions

Assignment serializes policy checks with the native device lock. Incompatible
batches, revision updates and restores roll back their snapshots, commands,
reservations and audit together. Known approval/removal conflicts are checked
against each potentially installed revision of every other assigned profile.
Alternative revisions of one profile are compared independently. Overlapping
individual approvals, compatible removal rules and different developer teams
remain allowed.

Migration 034 records only tenant, device, profile and retained revision identity.
Existing assigned and dispatched revisions are backfilled; missing historical
snapshots remain explicitly unknown. Policies capable of conflicting with unknown
history require verified replacement or removal first. A block-only policy has no
approval or removal mapping and can still be assigned.

Old reservations survive catalog changes, cancellation, command acknowledgements
and outdated profile UUIDs. Only fresh, accepted profile inventory verifying the
current replacement or removal releases them. Profile deletion retains the
immutable revision history. Reservation rows contain no plaintext policy data;
comparison reads the encrypted retained snapshots through the existing protected
store.

## Validation and remaining acceptance

The isolated parser check passes with unchanged production code, platform and
version helpers, and data types. Cases cover all editor modes, boolean/list types,
identifier bounds, platform/channel/OS limits, stale or future security inventory,
User Enrollment, conflicts across payloads, empty bundle/type lists and the
separate SIP/UI removal semantics.

All 34 migrations apply in an isolated PostgreSQL 17 transaction. All 291 extracted
production application/profile statements prepare with inferred parameter types.
The migration fixture verifies assigned/dispatched/unknown history; actual release
SQL preserves unresolved and foreign-tenant reservations and releases old entries
only for verified replacement or removal. The transaction is rolled back.

The full native suite includes mixed-device rollback, stale management approval,
macOS 15 revision rollback, concurrent conflicting assignments, audit rollback,
retained sent revisions, fresh replacement/removal and legacy migration recovery.
Console cases cover permissions, CSRF, strict forms, all approval modes, no allowed
types, removal distinctions and escaped labels. Template generation and JavaScript
syntax checks pass. Linux/Windows builds, native Windows checks, scoped console handlers and rendering
pass in the [`c4fb18d` push workflow](https://github.com/the-luap/openuem-console/actions/runs/34350292179);
the full native suite is still running. Twelve browser cases use its actual
rendered page at 390/768/1440 pixels. They cover all three approval modes and
empty type selection, mandatory fields, inactive-field omission, retained input
after mode changes, keyboard checkbox selection and submission, reset, CSRF and
scoped routes. No horizontal overflow occurred; the narrow layout was inspected.
The harness sets native select values directly, so native dropdown arrow-key
behavior is not independently verified. A follow-up also rejects inactive or
non-text bundle fields in the builder and tests empty version-specific dictionaries.

These synthetic checks do not install a profile or activate/deactivate extensions
on the development host. Physical Mac acceptance must verify provider signatures,
activation, type restrictions, removal behavior and interaction with other
installed profiles. Delivery status alone does not prove runtime behavior.

Source checked 9 September 2026:
[Apple System Extensions schema](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.system-extension-policy.yaml).

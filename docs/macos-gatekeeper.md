# Mac Gatekeeper profiles

The profile editor configures allowed application sources, the Finder exception
menu and the blocked-malware submission prompt. Saving creates an encrypted,
versioned profile; assignment uses the ordinary native profile lifecycle and
requires profile-management and assignment permissions in the selected scope.

## Settings and compatibility

The application-source choices are App Store and identified developers, App Store
only, or disabled Gatekeeper assessment. The editor writes explicit boolean
assessment settings. It omits the developer-source key when assessment is disabled.
The Finder exception menu can remain at the macOS default, be allowed, or be
restricted. The editor stores this setting in a separate System Policy Managed
payload with its own identifier and UUID.

Assessment requires System scope and macOS 10.8 or later. The separate Finder
exception payload also supports User scope when uploaded and assigned through a
managed Mac user channel. Both editor and uploaded profiles reject non-boolean
switches. Optional settings in uploaded profiles remain optional.

Allowing or suppressing the prompt to submit blocked malware to Apple requires
macOS 15 or later. Leaving the default selected omits that key. The assignment
check also applies when the key is explicitly false. This option controls the
submission prompt; it does not establish that a file was submitted or change the
separate delivery status of this profile.

A batch containing an incompatible device fails atomically. Editing or restoring
a revision rechecks active assignments and rolls back the new snapshot and all
commands if a device is incompatible. Removal uses the existing verified profile
removal workflow. Another installed policy and other macOS protections can still
affect application launches.

## Validation and acceptance

The isolated core check uses the unchanged production Gatekeeper validator,
platform detection, version comparison and relevant data types. It passes boolean,
System/User, platform and macOS version boundaries. Formatting and code generation pass for the template and its containing profile
page.

Full-suite cases cover separate assessment/Finder payloads, omitted defaults,
explicit false values, uploaded User policies, mixed-platform assignment rollback,
macOS 15 revision rollback, installation and removal observations. Console cases
cover role restrictions, CSRF, confirmation, repeated or unrelated fields, query
parameter rejection and persisted choices. Linux/Windows builds, native Windows
bootstrap checks, console rendering and scoped route tests pass in the
[`4d6fe4d` PR workflow](https://github.com/the-luap/openuem-console/actions/runs/34347551705).
The native Apple race suite found that the shared inventory fixture reported
macOS 15 instead of the intended 14.7 in the revision rollback case. The fixture
now reports 14.7 explicitly and asserts the persisted version before that check.
The corrected [`bd6bcc6` push workflow](https://github.com/the-luap/openuem-console/actions/runs/34349544513)
passes all jobs, including native Apple race tests (515.450 s), console handlers
(10.868 s) and desktop lifecycles (26.677 s). The [matching PR workflow](https://github.com/the-luap/openuem-console/actions/runs/34349548399)
also passes every job.

Nine browser cases use that workflow's actual rendered profile page at 390, 768
and 1440 pixels. They cover all three source policies, omitted defaults, explicit
false values, required names and review confirmation, keyboard confirmation and
submission, scoped routes and CSRF. No horizontal page overflow occurred.
The harness sets native select values directly; these checks do not independently
verify native dropdown arrow-key behavior.

No application is launched, Gatekeeper configuration is changed, or profile is
installed on the development host by these tests. Profile inventory proves that
the selected configuration was reported installed. Physical application-launch,
Finder-exception and prompt behavior remain acceptance requirements.

Sources checked 9 September 2026:

- [Apple System Policy Control schema](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.systempolicy.control.yaml)
- [Apple System Policy Managed schema](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.systempolicy.managed.yaml)

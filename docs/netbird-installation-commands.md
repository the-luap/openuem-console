# Exact NetBird installation commands and journal boundary

The shared [version-three command](https://github.com/the-luap/openuem-nats/blob/d0a53880dcbf2ceae01c4484bf9b7f4429ff0281/docs/netbird-commands.md#exact-unix-installation-commands)
now binds a Unix installation to one exact
organization package approval and one individually enrolled device. It includes
the current certificate hash, device/organization/site, reviewed revision,
request UUID, full package descriptor and bounded issue/expiry times. Package
organization must equal recipient organization. Connection settings and provider
credentials are forbidden. The native execution deadline is at most ten minutes;
package preparation must finish separately before a fresh command is admitted.

Every descriptor field enters the immutable command hash, including its approval,
private source, native target/version, size and SHA-256. Nested and outer codecs
reject ambiguous, missing, null, unknown or wrongly typed fields. Incidental
serialization and diagnostic formatting cannot expose the source. Earlier
connection/registration command encodings and hashes remain unchanged.

The [agent journal](https://github.com/the-luap/openuem-agent/blob/60c0045034d5603f8bb1522b735c1fc4c07afb6f/docs/netbird-execution-journal.md)
recognizes installation attempts using the same permanent UUID
namespace and exclusion barrier as connection and registration. It retains no
package source. An uncertain install blocks subsequent operations; retries and
lost responses only recover the original evidence. Current individually enrolled
identity can query that evidence or explicitly withdraw an unattempted command.
Crash recovery retains the existing later-boot and explicit-release requirements.
A release preserves uncertainty and does not prove package installation success.

This is an integrated command/journal foundation, not an enabled installer. The
agent has no production native installation runner and rejects new installation
commands before writing an attempt. Retained results remain readable even without
a runner. The console connection/registration publisher explicitly rejects this
new command version; it cannot bypass future package-aware durable admission.
Ordinary and registration state queries do not establish installation capability.
The installation command adds no broker subject, stream filter, permission or
automatic retry. The separate preparation protocol has its own direct subject.

## Remaining installation integration

The [durable installation request store](netbird-installation-requests.md) now
authenticates the organization approval and exact individual target, supports an
absent client, and retains intent/cancellation under the common console barrier.
The [private native preparation](netbird-package-preparation.md) now has an
authenticated agent RPC, native ownership and bounded cleanup. It still needs
console delivery admission, a fresh approval/target check at command admission,
atomic prepared-package consumption, fixed native install/remove execution and
verified resulting-state recovery. Windows retains its software workflow;
Linux also requires extending the current individual enrollment support.

## Verification

Protocol tests cover the complete nested grammar, old-wire compatibility, package
and recipient correlation, privacy, lifetime boundaries and individual-identity
recovery. Owned agent callbacks and broker fixtures cover persisted admission,
duplicate/lost delivery, withdrawal, concurrency, restart, long native deadlines,
uncertainty and disabled-runner rejection. No NetBird installer is executed.
The console publisher test verifies that this new wire version is not delivered
through connection/registration admission. The complete shared race suite passes;
command decoder fuzzing processes 731,389 inputs. With the immutable shared pin
`v0.11.1-0.20260914033929-d0a53880dcbf`, macOS journal/command/preparation race suites
pass in 7.215/2.854/4.540 seconds and Linux suites in 4.841/1.580/3.829 seconds.
Native agent service regressions pass in 2.199 seconds. Additional final
installation/barrier cases pass in 1.977/1.584 seconds. All six complete builds
pass: Linux console, Linux/macOS/Windows agent, and Linux/Windows worker. Publisher
tests run against the compiled Linux handler package and an owned broker.
All NetBird inventory PostgreSQL race tests pass in 157.248 seconds. Worker
model/common PostgreSQL race regressions pass in 2.822/3.587 seconds. These checks
validate the updated shared contract alongside existing approval, registration,
connection, recovery and reporting behavior; they do not establish native
installation acceptance.

# Native Windows SyncML codec

`ParseSyncML` and `EncodeSyncML` provide the bounded XML wire format for the
native Windows management service. They complement [TLS device identity and
digest verification](native-windows-management.md) and [WSTEP provisioning](native-windows-enrollment.md).
The [durable session service](native-windows-sessions.md) now uses these primitives
for authentication, nonce transitions and an initial read-only probe. A parsed or
encoded message alone never authenticates a session, updates inventory, executes
a command or proves compliance.

## Representation and message boundaries

The codec accepts the `SYNCML:SYNCML1.2` namespace, VerDTD `1.2` and protocol
`DM/1.2`. A document contains one header followed by one body. Namespace prefixes
may vary; missing/foreign namespace bindings, duplicate fields, unexpected
attributes and unsupported elements are rejected. Body commands retain their
order, including nested groups. Final may appear once at the end and means the
end of a package, not proof that a management session completed.

Session and command IDs are bounded opaque strings; command ID `0` is reserved
for the header. Message IDs are canonical positive unsigned decimal values and
message references are canonical unsigned decimals, bounded to 64 bits. The
session service must enforce starting at one, increasing message numbers and
references to the actual dispatched message/command. A missing or empty CmdRef
is representable for header/error status cases and grants no implicit correlation.
The [MS-MDM message ID](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mdm/a011dc68-97fa-4783-9b91-ca961aff53b8)
and [command reference](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mdm/9b41d3e0-1085-4a7f-916f-50fb2f5376f5)
definitions distinguish these responsibilities.

The wire model includes Alert, Status, Results, Add, Replace, Delete, Get, Exec,
Atomic and Sequence. Exec has exactly one Item; ordinary item commands require
at least one. Group command IDs are unique across the entire message. Nested
Sequence-in-Sequence is rejected. Windows-specific restrictions on executable
group contents, individual CSP availability and scope still belong to the future
command service. The codec does not interpret a device-originated mutation as a
server action.

NoResp, NoResults and credentials inside commands are rejected. The supported
credential form is header-level `syncml:auth-md5` with canonical Base64 encoding
of a 16-byte digest. A missing credential remains representable so the session
service can issue a challenge. Status challenges require the matching digest
type, b64 format and a canonical nonce of 16–256 bytes. No digest comparison,
nonce consumption, authentication-status transition or algorithm fallback occurs
in this codec. Correlator is not enabled for Windows; Microsoft's
[Alert definition](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mdm/72c6ea01-121c-48f9-85da-a26bb12aad51)
explicitly excludes it.

Metadata supports direct children or a MetInf wrapper, with bounded Format,
Type, Mark, Version, NextNonce, Size, MaxMsgSize, MaxObjSize and repeated EMI.
Header source/target locations, response URI, item locations, status references
and device hints remain untrusted. No URI is fetched. The future session service
must bind the configured target to the authenticated transport and enforce
negotiated message/object limits.

## Payload preservation and encoding

Text Data preserves decoded characters and whitespace, including escaped XML or
CDATA. Self-contained XML Data is supported as a separate opaque value, including
mixed text and elements. The codec reparses the fragment without the outer
envelope's namespace context and compares expanded names and attributes. A
payload that would change meaning when detached is rejected. This follows the
namespace boundary in [MS-MDM Data](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mdm/65afcaa7-053b-46cb-8ef0-31301cc123d9).
The optional Microsoft originalerror attribute is retained as a bounded
hexadecimal hint; it never overrides a Status code or authorizes an operation.
MoreData remains an explicit incomplete-object marker, not a complete result.

The shared strict XML parser rejects DTDs, entity declarations, non-XML processing
instructions and invalid UTF-8. It now also retains element content slices so
embedded Data can be detached safely; returned public models own their strings
and do not alias mutable request bytes. Existing discovery/XCEP/WSTEP tests cover
the shared-parser change.

Encoding escapes text, preserves self-contained markup and emits protocol field
order. Explicit namespace handling avoids `encoding/xml` resetting the default
namespace on header/body children. Invalid UTF-8 or XML characters are rejected
before the library can silently replace them. A bounded writer suppresses partial
or oversized output, and the complete emitted document is validated before any
bytes are returned. Ordinary JSON/XML serialization and diagnostic formatting
omit or redact credentials, device hints and payload data; explicit
`EncodeSyncML` is required to produce a transport document.

The limits are 1 MiB per document, 256 KiB per individual Data content, 256 commands,
1,024 items, 1,024 status/result references and eight nested group levels. Shared
XML limits also apply: 4,096 nodes, depth 32, 32 attributes per element and 64
in-scope namespace bindings. Each boundary applies independently; reaching one
limit does not guarantee that a different combined limit remains available.

## Evidence and next integration

The final combined PostgreSQL 17 suite passes with race detection in **28.448
seconds**, at **91.3%** package statement coverage. `go vet`, formatting,
whitespace and local documentation-link checks pass. Final 30-second fuzz runs
pass after **499,328** message-codec executions and **202,307** constructed-data
executions; neither found a crash or a changed accepted payload.

Tests cover synthetic initialization, device information, login/generic alerts,
digest challenges, status/results, incomplete data, all supported command kinds,
group ordering, separate namespaces, independent XML decoding, exact input/data
limits, output suppression, invalid-character rejection and redacted diagnostics.
Separate fuzz targets exercise complete messages and byte-for-byte preservation
of constructed text payloads. CI includes both targets on Linux and portable
codec tests on native Windows. Both complete workflows pass for codec commit
`a3f5487`: [push](https://github.com/the-luap/openuem-console/actions/runs/34402932832)
and [pull request](https://github.com/the-luap/openuem-console/actions/runs/34402938583).

The normative references are [OMA DM Representation 1.2](https://www.openmobilealliance.org/release/dm/V1_2-20070209-A/OMA-TS-DM_RepPro-V1_2-20070209-A.pdf)
and the [SyncML Representation 1.2.2 DTD](https://www.openmobilealliance.org/release/Common/V1_2_2-20090724-A/OMA-TS-SyncML-RepPro-V1_2_2-20090724-A.pdf),
together with the Windows-specific definitions above. The codec supports the
configured XML path; it does not advertise WBXML or newer application protocol
versions. No Windows profile/certificate has been installed on the host, no
physical SyncML exchange has been accepted, and no production management route
has been registered. The subsequent [session implementation](native-windows-sessions.md)
and [CSP command extension](native-windows-csp.md) record their own evidence.
Typed policy/update workflows and production integration remain open; WIN-02
stays in progress.

```sh
go test -race -count=1 -timeout=3m ./internal/mdm/windows
go test -run '^$' -fuzz='^FuzzSyncML$' -fuzztime=30s -parallel=2 ./internal/mdm/windows
go test -run '^$' -fuzz='^FuzzSyncMLDataCodec$' -fuzztime=30s -parallel=2 ./internal/mdm/windows
```

Use the [reserved database fixture](native-windows-mdm.md#scoped-enrollment-credentials)
for the combined PostgreSQL suite. A native Windows run without this environment
variable exercises portable codecs and cryptography, not PostgreSQL persistence.

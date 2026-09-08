# Desktop installer release admission

`openuem-agent-releases` inspects, accepts, shows and withdraws installer releases.
Admission authenticates a release manifest, checks every declared package's bytes
and stores a monotonic checkpoint in PostgreSQL. It does not sign native packages,
perform Windows Authenticode verification or submit Mac packages for notarization.
The trusted release pipeline must complete and verify those platform steps before
signing a manifest. Public download routes and invitation/bootstrap integration
are still in progress; accepting a release does not enable those routes by itself.

## Trust and repository preparation

Build the command with `go build ./cmd/openuem-agent-releases`. Use the console's
private `OPENUEM_AGENT_DATABASE_URL` environment setting for database actions.
The console must first apply its additive `uem_desktop_*` migrations. This command
does not run schema migrations or load the encryption master key or organization
CA keys. Restrict it and its database credentials to trusted server administrators
and the authorized release pipeline; it is not a scoped end-user API.

Configure a protected PEM file containing one to eight pinned Ed25519 **public**
release keys. On Unix the file must belong to the current account or root and have
no group/other permissions, for example mode `0600`. Windows uses the shared
credential file ACL validation. Duplicate keys, private keys, other algorithms,
certificates and unrelated PEM content are rejected. These are dedicated release
keys, separate from organization CAs, TLS credentials and broker NKeys. Private
release keys stay in the protected release-signing environment.

The shared `enrollment/artifacts` package defines schema-1 manifests. The release
pipeline calls its `Sign` function after native package signing/verification.
An envelope contains a domain-separated Ed25519 signature over the exact payload.
That payload binds version, sequence, timestamps and each target's filename,
byte size and SHA-256 digest. Windows supports `exe`/`msi`, Mac supports `pkg`,
with explicit `amd64`/`arm64` selection. Unknown fields, ambiguous JSON, unsupported
targets and unapproved filenames are rejected. Validity is at most thirty days;
packages are bounded to 512 MiB each.

Inspect the envelope before arranging the repository:

```sh
openuem-agent-releases --action inspect \
  --trusted-keys /etc/openuem/release-public-keys.pem \
  --manifest /srv/openuem/releases/release.json
```

This needs neither database access nor package files. Its JSON status is
`candidate`, and `checkpoint.digest` identifies the required directory. Inspection
checks current signature/validity, but cannot compare the candidate to persisted
approval state. It does not approve or install anything.

Place the unchanged packages in this layout, using the exact signed filenames:

```text
releases/
  <manifest-payload-sha256>/
    openuem-agent-0.12.0-windows-amd64.msi
    openuem-agent-0.12.0-macos-arm64.pkg
```

Publish through atomic file/directory renames. The serving process must have
read-only access; never update a published file in place. The catalog rejects
nonregular files, final-file symlinks and symbolic-link release directories. Its
directory handles constrain access beneath the configured repository. After
hashing a download, it returns the same open file descriptor for serving, so an
atomic path replacement cannot substitute different bytes. Every subsequent open
checks file integrity again. Callers own and must close the returned descriptor.

## Admission, status and withdrawal

After staging every declared target, accept the envelope:

```sh
openuem-agent-releases --action accept \
  --directory /srv/openuem/releases \
  --trusted-keys /etc/openuem/release-public-keys.pem \
  --manifest /srv/openuem/releases/release.json \
  --actor release-pipeline
```

The command checks all package bytes before starting its database transaction,
then locks and reloads the checkpoint and verifies current validity again. It
persists approval, checkpoint and audit together. Concurrent approvals cannot
lower the final sequence. Output has status `accepted` and public metadata only;
raw database errors, connection credentials and key contents are not returned.
Operations have a two-minute context deadline.

Read the current signed metadata with `--action show`, the same `--directory` and
`--trusted-keys`. Current metadata is reverified against the configured key ring,
stored sequence/digest and current time. This reports approval; actual file
availability is checked during admission and each package open.

Withdraw a release by its exact current digest:

```sh
openuem-agent-releases --action withdraw \
  --digest <current-manifest-payload-sha256> \
  --actor administrator-id
```

Withdrawal requires only database access, so it works even if the repository or
public-key file is unavailable. The first withdrawal is audited, and an identical
retry is idempotent. The checkpoint is retained. A stale withdrawal cannot change
a newer current release. Requests already authorized may finish; new opens fail.

There is no automatic fallback after withdrawal, expiry, missing files or removal
of a trusted signing key. An identical publish cannot undo a withdrawal. Publish
a newly approved sequence to resume admission; returning deliberately to older
package bytes also requires a new sequence. Reusing a sequence for a different
payload is rejected. Trust-key rotation can re-sign the identical payload with an
explicitly configured new key without changing its digest or sequence, unless
the release has been withdrawn. Preserve the checkpoint with backups and do not
reset it to bypass admission failures.

## Evidence and remaining wiring

PostgreSQL tests cover concurrent approvals, conflicting sequences, unchanged
retries, migrations/restarts, withdrawal, missing/changed/linked files, canceled
operations, stored-signature revalidation and atomic path replacement. The real
administration runner is exercised through a second database connection, including
database-independent inspection, metadata-only output and file-independent
withdrawal. Shared-library tests cover key rotation, expiry, strict target/content
binding and bounded readers; native Windows CI covers the manifest parser and
credential ACL implementation.

The console's public enrollment portal, per-invitation release binding, package
HTTP handler, signed bootstrap configuration/installer flow and native release
signing jobs are the next integration steps. Test package bytes are non-executable
fixtures and provide no physical installation or native signing evidence.

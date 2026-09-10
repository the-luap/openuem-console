# Retained Windows and desktop bootstrap keys

`openuem-protocol-keys` creates two independent credentials for an existing,
complete installation. It runs offline on Linux/macOS and prints only the public
installation identifier. Secret values are never command arguments or command
output. It neither starts listeners nor contacts providers.

```sh
openuem-protocol-keys --directory /private/openuem/protocol \
  --installation /private/openuem/installation
```

The installation directory must already have been completed by
[`openuem-installation-secrets`](installation-secrets.md). It is read-only input:
missing directories, journal, exports or completion marker cause rejection;
this command cannot create, resume or repair that foundation. Both directories
must have trusted existing parents and suitable private ownership. The output
cannot contain the input or be nested within it, including through an ancestor
symlink or a second bind mount of the same directory. Existing file permissions are never broadened.

| Output | Purpose | Runtime recipient |
| --- | --- | --- |
| `windows.key` | Independent 256-bit Windows authority encryption key, canonical standard Base64 (44 characters) | Console via `WINDOWS_MDM_MASTER_KEY_FILE`, read-only |
| `desktop-bootstrap.key` | Independent Ed25519 bootstrap configuration signing key, PKCS#8 PEM | Console via `OPENUEM_AGENT_BOOTSTRAP_KEY_FILE`, read-only |
| `secrets.json` | Retained secret journal, bound to the installation ID and digest of its complete credential manifest | Provisioning/recovery only |
| `manifest.json` | Completion marker containing export digests | Provisioning/recovery only |

These keys are independent of the installation JWT/encryption credentials. The
bootstrap key signs enrollment configuration; it is not a release signing key.
Approved release public keys must be supplied separately. This command does not
create the native Windows CA, issue certificates, publish releases or configure
Apple push credentials.

## Retention and failure handling

The directory is created with mode 0700 and files with mode 0600. A completed
source with read-only file/directory permissions is accepted. The journal is
written and synced before any export; exports are completed before the marker.
Start consumers only after a successful command invocation, not merely after
observing one file appear.

A retry verifies existing exports byte for byte. It resumes a missing export only
when the retained valid journal exists and no completion marker is present. A
missing marker can be recreated after verifying every retained export. Partial
files, unexpected entries, invalid/noncanonical journals, changed credentials,
missing committed exports and unsafe permissions are rejected without replacement
or rotation. A competing writer may receive a state error and retry after the
other command finishes; exclusive creation prevents overwriting its files.

The command verifies the foundation again before and after completing its own
marker. Another installation, or replacement foundation credentials under the
same public installation ID, cannot reuse the output directory. Back up both
complete directories as private secret material. Removing a journal to force
regeneration is not a recovery operation. Restoring or rotating deployed keys
requires the corresponding retained database/enrollment state and a deliberate
recovery procedure; full restore acceptance remains separate work.

## Container use and verification

The `protocol-keys` target in [`Dockerfile.setup`](../Dockerfile.setup) contains
only this command and its license. For pre-created, correctly owned private
host directories:

```sh
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 64 --memory 128m \
  --mount type=bind,src=/srv/openuem/installation,dst=/installation,readonly \
  --mount type=bind,src=/srv/openuem/protocol,dst=/protocol \
  openuem-protocol-keys:local --directory /protocol --installation /installation
```

Use the intended non-root service account and matching bind ownership. The
[reference composition](reference-composition.md) invokes this distribution
command twice with a read-only foundation and then mounts only its two exported
keys into the console. Its fixture continues to supply synthetic public TLS,
administrator public trust and release public keys separately.

Tests cover cryptographic formats and signatures, independent installation keys,
interruption after every completed write, exact retries, damaged/missing files,
source binding and mutation, private/aliased paths, concurrency and cancellation.
The container fixture also rejects a writable bind alias of its read-only source
before creating any nested output.
The offline scratch smoke test runs the actual commands and verifies public
output and retained files. The seven-container fixture exercises generated keys
through the real Windows listener and desktop bootstrap-key discovery, then
restarts the services with retained state. These are synthetic local tests, not
physical endpoint enrollment or full production installer acceptance.

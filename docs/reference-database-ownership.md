# Reference database ownership and container acceptance

The Linux reference deployment can use one dedicated, non-root host UID/GID for
its private setup files and database runtime. Explicit `--user UID:GID` overrides
the setup images' default `65532:65532` and the PostgreSQL image's account. This
keeps generated input ownership consistent without granting group/other access
or running recursive permission repairs. Container mount boundaries still limit
which credentials each service receives.

The pinned official PostgreSQL 17 image supports initialization under a numeric
UID absent from its `/etc/passwd`: its entrypoint uses `nss_wrapper` for `initdb`.
The reference test exercises that entrypoint, not an alternate database launcher.
It supplies writable private database storage and bounded temporary filesystems;
the runtime root is read-only and all Linux capabilities are dropped.

Only PostgreSQL's generated administrator password and its separate server TLS
directory are mounted into the database container. The online bootstrap gets
the credential set, protected public metadata and public CA read-only, plus its
separate writable journal. The offline PKI authority and installation source are
not database mounts. All source and journal directories stay mode 0700 and their
private files have no group/other access.

The fixture binds TCP to loopback in an offline network namespace and publishes
no host port. A separate bootstrap container joins that namespace and verifies
`database.internal` against the generated CA. Its explicit HBA file requires
SCRAM over TLS for TCP and rejects cleartext. Local trust is limited by a mode
0700 Unix socket; a foreign runtime UID cannot use it. This isolated topology
tests ownership and bootstrap, not the final private service network.

## Automated acceptance

After building the images, run as a non-root POSIX host account:

```sh
python3 scripts/check-reference-database.py \
  openuem-installation-secrets:local openuem-database-credentials:local \
  openuem-private-pki:local openuem-database-bootstrap:local
```

The fixture creates temporary synthetic state, runs all four distribution images
with the host account's numeric UID/GID and starts the pinned official database.
It verifies protected generation and byte-for-byte retries, TLS role/database
bootstrap, retained source permissions and contents, cleartext denial, Unix
socket isolation, clean stop/restart and exact bootstrap verification afterward.
It removes its database container before removing the private temporary files.
Diagnostics from credential and database commands remain private.

Native Linux CI additionally requires a different runtime UID to fail reading
the bound administrator-password file. Docker Desktop virtualizes host bind-mount
access, so macOS execution explicitly reports that this negative permission gate
requires native Linux. Local macOS/Docker arm64 passes the remaining startup,
TLS, protected retry and restart checks; that does not establish Linux bind-mount
isolation. The native amd64/arm64 workflow requires the full Linux gate.

The test chooses a temporary account-owned directory. It does not create a host
service account, configure persistent installation paths, migrate existing file
ownership or prove complete service composition. A deployment must deliberately
choose its dedicated account, prepare trusted parents and persist separate state
and backups. Automatic installer preparation, administrator/device authorities,
complete reference composition and restore acceptance remain open.

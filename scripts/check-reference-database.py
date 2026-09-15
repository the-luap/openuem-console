"""Exercise private setup and PostgreSQL containers under one non-root host UID.

This fixture creates only temporary synthetic state. It publishes no port, uses
an offline network namespace, and removes every container and file it creates.
"""

import argparse
import contextlib
import hashlib
import json
import os
import pathlib
import platform
import stat
import subprocess
import tempfile
import time


POSTGRES = "postgres@sha256:051f7b7b3abdd564d5d1bd1e8c4b9c1b6e77087d1dd22020ede611c096a272e0"


def command(stage, *args, check=True, timeout=60):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError(stage + " did not complete") from None
    if check and result.returncode:
        # Private provisioning and database diagnostics must not enter CI logs.
        raise RuntimeError(stage + " failed")
    return result


def mount(source, target, readonly=True):
    return ["--mount", "type=bind,source=" + str(source) + ",destination=" + target
            + (",readonly" if readonly else "")]


def snapshot(roots):
    result = {}
    for root in roots:
        for path in [root, *root.rglob("*")]:
            metadata = path.lstat()
            assert not path.is_symlink()
            assert metadata.st_uid == os.getuid() and not stat.S_IMODE(metadata.st_mode) & 0o077
            result[str(path)] = (metadata.st_uid, metadata.st_gid, metadata.st_mode,
                                 hashlib.sha256(path.read_bytes()).digest() if path.is_file() else b"")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("installation_image")
    parser.add_argument("credentials_image")
    parser.add_argument("pki_image")
    parser.add_argument("bootstrap_image")
    args = parser.parse_args()
    if os.name != "posix" or os.getuid() == 0:
        raise RuntimeError("this bind-mount fixture requires a non-root POSIX host account")
    uid, gid = os.getuid(), os.getgid()
    account = str(uid) + ":" + str(gid)
    policy = ["--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
              "--pids-limit", "128", "--memory", "512m", "--user", account]
    offline = ["docker", "run", "--rm", "--network", "none", *policy]
    container = None

    def cleanup_database():
        nonlocal container
        if container:
            removed = command("database cleanup", "docker", "rm", "--force", "--volumes", container, check=False)
            if removed.returncode == 0:
                container = None

    try:
        with tempfile.TemporaryDirectory(prefix="openuem-reference-database-") as directory, contextlib.ExitStack() as cleanup:
            cleanup.callback(cleanup_database)
            root = pathlib.Path(directory)
            if "," in directory:
                raise RuntimeError("Docker bind mounts require a temporary path without commas")
            installation, credentials, pki, journal, data = [root / name for name in
                                                            ("installation", "credentials", "pki", "journal", "data")]
            for path in (installation, credentials, pki, journal, data):
                path.mkdir(mode=0o700)
            initialize = [*offline, *mount(installation, "/work", False), args.installation_image,
                          "--directory", "/work/state"]
            public = json.loads(command("installation secrets", *initialize).stdout)
            metadata = root / "database.json"
            metadata.write_text(json.dumps({"version": 1, "installation": public["installation"],
                                           "host": "database.internal", "port": 5432, "database": "openuem",
                                           "user": "console", "trust_file": "/run/database-ca.pem"}))
            metadata.chmod(0o600)
            generate = [*offline, *mount(credentials, "/work", False), *mount(metadata, "/config.json"),
                        args.credentials_image, "--config", "/config.json", "--directory", "/work/state"]
            command("database credentials", *generate)
            private_pki = [*offline, *mount(pki, "/work", False), args.pki_image, "private-pki",
                           "--directory", "/work/state", "--name", "reference-test",
                           "--console-dns", "console.internal", "--broker-dns", "broker.internal",
                           "--database-dns", "database.internal"]
            command("private database PKI", *private_pki)
            retained = snapshot((installation, credentials, pki))
            for stage, invocation in (("installation retry", initialize), ("credential retry", generate),
                                      ("private PKI retry", private_pki)):
                command(stage, *invocation)
            assert snapshot((installation, credentials, pki)) == retained
            print("protected setup images: creation, ownership and exact retries passed", flush=True)

            hba = root / "pg_hba.conf"
            hba.write_text("local all all trust\nhostssl all all all scram-sha-256\nhostnossl all all all reject\n")
            hba.chmod(0o600)
            database_mounts = [*mount(data, "/var/lib/postgresql/data", False),
                               *mount(credentials / "state/administrator-password", "/run/database-password"),
                               *mount(pki / "state/database", "/run/database-tls"),
                               *mount(hba, "/run/pg_hba.conf")]
            container = command("database container creation", "docker", "create", "--network", "none",
                                "--add-host", "database.internal:127.0.0.1", *policy, "--shm-size", "64m",
                                "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=32m",
                                "--tmpfs", "/var/run/postgresql:rw,nosuid,nodev,noexec,size=16m,uid=" + str(uid)
                                + ",gid=" + str(gid) + ",mode=0700", *database_mounts,
                                "--env", "POSTGRES_PASSWORD_FILE=/run/database-password",
                                "--env", "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 --auth-local=trust",
                                POSTGRES, "postgres", "-c", "listen_addresses=127.0.0.1", "-c", "ssl=on",
                                "-c", "ssl_cert_file=/run/database-tls/server.pem", "-c",
                                "ssl_key_file=/run/database-tls/server.key", "-c", "hba_file=/run/pg_hba.conf",
                                "-c", "unix_socket_permissions=0700").stdout.strip()

            def start_database():
                command("database container start", "docker", "start", container)
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    ready = command("database readiness", "docker", "exec", container, "pg_isready", "-q",
                                    "-h", "127.0.0.1", "-U", "postgres", "-d", "postgres", check=False)
                    if ready.returncode == 0:
                        return
                    running = command("database running state", "docker", "inspect", "--format",
                                      "{{.State.Running}}", container).stdout.strip()
                    if running != "true":
                        raise RuntimeError("unprivileged database startup failed")
                    time.sleep(0.1)
                raise RuntimeError("unprivileged database readiness timed out")

            start_database()
            bootstrap = ["docker", "run", "--rm", "--network", "container:" + container, *policy,
                         *mount(metadata, "/config.json"), *mount(credentials / "state", "/credentials"),
                         *mount(pki / "state/trust/backend-ca.pem", "/run/database-ca.pem"),
                         *mount(journal, "/work", False), args.bootstrap_image, "--config", "/config.json",
                         "--credentials", "/credentials", "--state", "/work/state"]
            result = command("private database bootstrap", *bootstrap).stdout
            assert command("database bootstrap retry", *bootstrap).stdout == result
            committed = snapshot((installation, credentials, pki, journal))
            assert snapshot((installation, credentials, pki)) == retained
            command("database input ownership", "docker", "exec", container, "test", "-r", "/run/database-password")
            denied = command("foreign runtime UID denial", "docker", "exec", "--user",
                             str(uid + 1) + ":" + str(gid + 1), container, "cat", "/run/database-password", check=False)
            if platform.system() == "Linux":
                assert denied.returncode != 0 and not denied.stdout and "Permission denied" in denied.stderr
            else:
                # Docker Desktop virtualizes host bind access. Positive startup
                # there does not prove native Linux denial for another UID.
                print("foreign UID bind-mount denial: requires native Linux CI", flush=True)
            foreign_socket = command("foreign UID socket denial", "docker", "exec", "--user",
                                     str(uid + 1) + ":" + str(gid + 1), container, "psql", "-w", "-U",
                                     "postgres", "-d", "postgres", "-c", "SELECT 1", check=False)
            assert foreign_socket.returncode != 0 and "Permission denied" in foreign_socket.stderr
            cleartext = command("cleartext PostgreSQL rejection", "docker", "exec", container, "psql",
                                "host=127.0.0.1 user=postgres dbname=postgres sslmode=disable connect_timeout=3",
                                "-w", "-c", "SELECT 1", check=False)
            assert cleartext.returncode != 0 and "pg_hba.conf rejects connection" in cleartext.stderr
            command("database clean shutdown", "docker", "stop", "--time", "10", container)
            assert command("database exit status", "docker", "inspect", "--format",
                           "{{.State.ExitCode}}", container).stdout.strip() == "0"
            start_database()
            assert command("retained database verification", *bootstrap).stdout == result
            assert snapshot((installation, credentials, pki, journal)) == committed
            assert data.stat().st_uid == uid and stat.S_IMODE(data.stat().st_mode) == 0o700
            command("database final shutdown", "docker", "stop", "--time", "10", container)
            command("database fixture removal", "docker", "rm", "--volumes", container)
            container = None
            print("official PostgreSQL: non-root UID, protected TLS inputs, bootstrap and restart passed", flush=True)
    finally:
        cleanup_database()


if __name__ == "__main__":
    main()

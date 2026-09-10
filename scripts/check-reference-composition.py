"""Exercise the reference manifest using owned, offline synthetic containers.

No host port is published. This fixture removes only its uniquely named project,
probe containers and temporary state. It never reads an installed deployment.
"""

import argparse
import contextlib
import json
import os
import pathlib
import re
import subprocess
import tempfile
import time
import uuid


def command(stage, *args, environment=None, check=True, timeout=60):
    try:
        result = subprocess.run(args, env=environment, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError(stage + " did not complete") from None
    if check and result.returncode:
        # Never expose setup output, credentials, driver errors or service logs.
        raise RuntimeError(stage + " failed")
    return result


def mount(source, destination, readonly=True):
    return ["--mount", "type=bind,source=" + str(source) + ",destination=" + destination
            + (",readonly" if readonly else "")]


def protected(path, data):
    with path.open("x", encoding="utf-8") as stream:
        path.chmod(0o600)
        stream.write(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("installation", "credentials", "pki", "bootstrap", "console", "broker",
                 "authorization", "commands", "worker", "gateway"):
        parser.add_argument(name + "_image")
    parser.add_argument("test_binary", type=pathlib.Path)
    args = parser.parse_args()
    if os.name != "posix" or os.getuid() == 0 or not args.test_binary.is_file():
        raise RuntimeError("reference composition requires a non-root POSIX account and its Linux probe")
    repository = pathlib.Path(__file__).resolve().parent.parent
    project = "openuem-reference-" + uuid.uuid4().hex[:12]
    uid, gid = os.getuid(), os.getgid()
    account = str(uid) + ":" + str(gid)
    policy = ["--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
              "--pids-limit", "128", "--memory", "512m", "--user", account]
    offline = ["docker", "run", "--rm", "--network", "none", *policy]
    with tempfile.TemporaryDirectory(prefix=project + "-") as directory, contextlib.ExitStack() as cleanup:
        root = pathlib.Path(directory)
        if "," in directory:
            raise RuntimeError("reference state needs a path without commas")
        for name in ("installation", "credentials", "pki", "broker", "journal", "database", "jetstream",
                     "console-logs", "public", "releases", "device", "ready"):
            (root / name).mkdir(mode=0o700)
        public = json.loads(command("installation secrets", *offline, *mount(root / "installation", "/work", False),
                                    args.installation_image, "--directory", "/work/state").stdout)
        metadata = root / "database.json"
        protected(metadata, json.dumps({"version": 1, "installation": public["installation"],
                                       "host": "database.internal", "port": 5432, "database": "openuem",
                                       "user": "console", "trust_file": "/run/database-ca.pem"}))
        command("database credentials", *offline, *mount(root / "credentials", "/work", False),
                *mount(metadata, "/config.json"), args.credentials_image,
                "--config", "/config.json", "--directory", "/work/state")
        command("private service PKI", *offline, *mount(root / "pki", "/work", False), args.pki_image,
                "private-pki", "--directory", "/work/state", "--name", "reference-composition",
                "--console-dns", "console.internal", "--broker-dns", "broker.internal",
                "--database-dns", "database.internal")
        command("broker setup", *offline, *mount(root / "broker", "/work", False), args.pki_image,
                "individual-broker", "--directory", "/work/state", "--name", "reference-composition",
                "--listen", "0.0.0.0:4222", "--websocket-listen", "0.0.0.0:9222",
                "--tls-cert", "/run/broker-tls/server.pem", "--tls-key", "/run/broker-tls/server.key",
                "--gateway-ca", "/run/broker-tls/gateway-leaves.pem",
                "--store-directory", "/var/lib/openuem/jetstream")
        protected(root / "pg_hba.conf", "local all all trust\nhostssl all all all scram-sha-256\nhostnossl all all all reject\n")
        probe_base = [*policy, "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=32m,uid=" + str(uid)
                      + ",gid=" + str(gid) + ",mode=0700", "--env", "OPENUEM_REFERENCE_FIXTURE=1",
                      "--env", "GOMAXPROCS=2", *mount(args.test_binary.resolve(), "/reference.test")]

        def probe(stage, test, network, mounts=(), values=()):
            invocation = ["docker", "run", "--rm", "--network", network, *probe_base, *mounts]
            for name, value in values:
                invocation += ["--env", name + "=" + value]
            result = command(stage, *invocation, "--entrypoint", "/reference.test", args.broker_image,
                             "-test.v", "-test.run=^" + test + "$", "-test.timeout=55s", check=False)
            if result.returncode or "--- PASS: " + test + " " not in result.stdout:
                # The fixture emits fixed errors instead of database/credential diagnostics.
                failures = re.findall(r"container_linux_test.go:\d+: ([^\n]+)", result.stdout)
                raise RuntimeError(stage + " failed" + (": " + "; ".join(failures[:3]) if failures else ""))

        probe("synthetic external inputs", "TestReferencePrepare", "none", mount(root, "/state", False))
        environment = {**os.environ, "OPENUEM_REFERENCE_STATE": str(root), "OPENUEM_RUNTIME_UID": str(uid),
                       "OPENUEM_RUNTIME_GID": str(gid), "OPENUEM_DOMAIN": "example.test",
                       "OPENUEM_ORGANIZATION": "Reference", "OPENUEM_PUBLIC_HOST": "uem.example.test",
                       "OPENUEM_PUBLIC_ORIGIN": "https://uem.example.test:8443", "OPENUEM_ADMIN_NETWORKS": "127.0.0.1/32",
                       "OPENUEM_INSTALLATION_ID": public["installation"], "OPENUEM_BOOTSTRAP_ADMIN": "first-admin"}
        for name in ("console", "broker", "authorization", "commands", "worker", "gateway"):
            environment["OPENUEM_" + name.upper() + "_IMAGE"] = getattr(args, name + "_image")
        override = root / "offline.json"
        protected(override, json.dumps({"networks": {"edge": {"internal": True}, "egress": {"internal": True}}}))
        base = ["docker", "compose", "--project-name", project, "--project-directory", str(root),
                "--env-file", "/dev/null", "--file", str(repository / "deploy/reference/compose.yaml")]
        invocation = [*base, "--file", str(override)]

        def compose(stage, *arguments, check=True, timeout=60):
            return command(stage, *invocation, *arguments, environment=environment, check=check, timeout=timeout)

        expected_networks = {"database": {"data"}, "broker": {"messaging", "broker_backend"},
                             "console": {"data", "messaging", "console_backend", "egress"},
                             "authorization": {"data", "messaging"}, "commands": {"data", "messaging"},
                             "worker": {"data", "messaging"}, "gateway": {"edge", "console_backend", "broker_backend"}}
        rendered = json.loads(compose("reference render", "config", "--format", "json").stdout)
        assert set(rendered["services"]) == set(expected_networks)
        for name, service in rendered["services"].items():
            assert not service.get("ports") and set(service["networks"]) == expected_networks[name]
        published = json.loads(command("publication render", *base, "--file",
                                       str(repository / "deploy/reference/compose.publish.yaml"), "config", "--format", "json",
                                       environment=environment).stdout)
        ports = [(name, p["target"], p["published"], p["protocol"]) for name, service in published["services"].items()
                 for p in service.get("ports", [])]
        assert ports == [("gateway", 8443, "443", "tcp")]
        cleanup.callback(lambda: compose("owned composition cleanup", "down", "--volumes", "--remove-orphans", timeout=60))
        compose("reference creation", "create", timeout=60)
        edge, data_network = project + "_edge", project + "_data"

        def remove(container):
            command("owned probe cleanup", "docker", "rm", "--force", "--volumes", container)

        admin = command("administrator probe creation", "docker", "run", "--detach", "--network", edge,
                        *probe_base, *mount(root / "public-ca.pem", "/trust.pem"),
                        *mount(root / "installation/state/initial-password", "/initial-password"),
                        "--entrypoint", "/reference.test", args.broker_image,
                        "-test.run=^TestReferenceIdle$", "-test.timeout=10m").stdout.strip()
        cleanup.callback(remove, admin)
        admin_state = json.loads(command("administrator address", "docker", "inspect", admin).stdout)[0]
        administrator_ip = admin_state["NetworkSettings"]["Networks"][edge]["IPAddress"]
        environment["OPENUEM_ADMIN_NETWORKS"] = administrator_ip + "/32"
        compose("database startup", "up", "--detach", "database")
        database = compose("database identity", "ps", "--quiet", "database").stdout.strip()
        def database_ready():
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if command("database readiness", "docker", "exec", database, "pg_isready", "-q", "-h", "127.0.0.1",
                           "-U", "postgres", "-d", "postgres", check=False).returncode == 0:
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError("reference database did not become ready")
        database_ready()
        command("database bootstrap", "docker", "run", "--rm", "--network", data_network, *policy,
                *mount(metadata, "/config.json"), *mount(root / "credentials/state", "/credentials"),
                *mount(root / "pki/state/trust/backend-ca.pem", "/run/database-ca.pem"),
                *mount(root / "journal", "/work", False), args.bootstrap_image,
                "--config", "/config.json", "--credentials", "/credentials", "--state", "/work/state")
        def broker_ready():
            probe("broker readiness", "TestReferenceBrokerReady", project + "_messaging",
                  [*mount(root / "broker/state/provisioner-user.seed", "/run/broker.seed"),
                   *mount(root / "pki/state/trust/backend-ca.pem", "/run/backend-ca.pem")])

        compose("broker startup", "up", "--detach", "broker")
        broker_ready()
        compose("console startup", "up", "--detach", "console")
        compose("gateway startup", "up", "--detach", "gateway")

        def administrator(restart=False):
            result = command("administrator login", "docker", "exec", "--env", "OPENUEM_REFERENCE_RESTART=" + ("1" if restart else "0"),
                             admin, "/reference.test", "-test.v", "-test.run=^TestReferenceAdministrator$", "-test.timeout=45s", check=False)
            if result.returncode or "--- PASS: TestReferenceAdministrator " not in result.stdout:
                failures = re.findall(r"container_linux_test.go:\d+: ([^\n]+)", result.stdout)
                identities = compose("failed runtime identities", "ps", "--all", "--quiet").stdout.split()
                states = json.loads(command("failed runtime status", "docker", "inspect", *identities).stdout)
                summary = [item["Config"]["Labels"]["com.docker.compose.service"] + ":" + item["State"]["Status"]
                           + ":" + str(item["State"]["ExitCode"]) for item in states]
                raise RuntimeError("administrator gateway login failed: " + "; ".join(failures[:3] + summary))

        administrator()
        compose("private services startup", "up", "--detach", "authorization", "commands", "worker")

        def health():
            for name, port in (("authorization", "1326"), ("commands", "1327")):
                container = compose("private service identity", "ps", "--quiet", name).stdout.strip()
                probe(name + " health", "TestReferenceHealth", "container:" + container,
                      values=[("OPENUEM_REFERENCE_HEALTH_URL", "http://127.0.0.1:" + port + "/healthz")])
            worker = compose("worker identity", "ps", "--all", "--quiet", "worker").stdout.strip()
            state = json.loads(command("worker runtime", "docker", "inspect", worker).stdout)[0]["State"]
            if not state["Running"]:
                raise RuntimeError("reference worker exited before readiness (code " + str(state["ExitCode"]) + ")")
            started = state["StartedAt"]
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                output = command("worker readiness", "docker", "logs", "--since", started, "--tail", "50", worker)
                if "individual agent worker subscriptions established" in output.stdout + output.stderr:
                    return
                time.sleep(0.1)
            raise RuntimeError("reference worker subscriptions did not become ready")

        health()
        trust = mount(root / "public-ca.pem", "/trust.pem")
        probe("public route separation", "TestReferencePublicRoutes", edge, trust,
              [("OPENUEM_REFERENCE_FORGED_SOURCE", administrator_ip)])
        print("reference console: private administrator and separate public protocol routes passed", flush=True)
        private = [*mount(root / "credentials/state/database.url", "/run/database.url"),
                   *mount(root / "pki/state/trust/backend-ca.pem", "/run/database-ca.pem"),
                   *mount(root / "installation/state/encryption.key", "/run/encryption.key"),
                   *mount(root / "device", "/device", False)]
        device = [*trust, *mount(root / "device", "/device")]
        probe("synthetic registry admission", "TestReferenceRegistry", data_network, private,
              [("OPENUEM_REFERENCE_ACTION", "enroll")])
        probe("public device worker request", "TestReferenceDevice", edge, device)
        probe("durable worker and consumer state", "TestReferenceRegistry", data_network, private,
              [("OPENUEM_REFERENCE_ACTION", "verify")])
        print("separate containers: protected setup, private login, public routes and device WSS worker request passed", flush=True)

        containers = json.loads(command("runtime inspection", "docker", "inspect",
                                        *compose("reference identities", "ps", "--quiet").stdout.split()).stdout)
        assert len(containers) == 7
        service_database = {"/run/database.url": "credentials/state/database.url",
                            "/run/database-ca.pem": "pki/state/trust/backend-ca.pem",
                            "/run/backend-ca.pem": "pki/state/trust/backend-ca.pem"}
        expected_mounts = {
            "database": {"/var/lib/postgresql/data": "database", "/run/database-password": "credentials/state/administrator-password",
                         "/run/database-tls": "pki/state/database", "/run/pg_hba.conf": "pg_hba.conf"},
            "broker": {"/run/broker.json": "broker/state/broker.json", "/run/broker-tls": "pki/state/broker",
                       "/var/lib/openuem/jetstream": "jetstream"},
            "gateway": {"/run/public": "public", "/run/gateway": "pki/state/gateway"},
            "authorization": {**service_database, "/run/issuer.seed": "broker/state/authorization-issuer.seed",
                              "/run/authorization.seed": "broker/state/authorization-user.seed",
                              "/run/revocation.seed": "broker/state/revocation-user.seed"},
            "commands": {**service_database, "/run/provisioner.seed": "broker/state/provisioner-user.seed"},
            "worker": {**service_database, "/run/worker.seed": "broker/state/worker-user.seed",
                       "/run/encryption.key": "installation/state/encryption.key"},
            "console": {**service_database, "/run/jwt.key": "installation/state/jwt.key",
                        "/run/encryption.key": "installation/state/encryption.key", "/run/initial-password": "installation/state/initial-password",
                        "/run/console.seed": "broker/state/console-user.seed", "/run/console-tls": "pki/state/console",
                        "/run/administrator-ca.pem": "administrator-ca.pem", "/run/windows.key": "windows.key",
                        "/run/desktop-bootstrap.key": "desktop-bootstrap.key", "/run/release-keys.pem": "release-keys.pem",
                        "/run/releases": "releases", "/var/log/openuem-server": "console-logs"}}
        writable = {("database", "/var/lib/postgresql/data"), ("broker", "/var/lib/openuem/jetstream"),
                    ("console", "/var/log/openuem-server")}
        for item in containers:
            name = item["Config"]["Labels"]["com.docker.compose.service"]
            host = item["HostConfig"]
            assert item["State"]["Running"] and item["RestartCount"] == 0
            assert item["Config"]["User"] == account and host["ReadonlyRootfs"] and not host["Privileged"]
            assert host["CapDrop"] == ["ALL"] and "no-new-privileges:true" in host["SecurityOpt"]
            assert not host.get("PortBindings")
            assert set(item["NetworkSettings"]["Networks"]) == {project + "_" + network for network in expected_networks[name]}
            declared = expected_mounts[name]
            assert {volume["Destination"] for volume in item["Mounts"]} == set(declared)
            for volume in item["Mounts"]:
                target = volume["Destination"]
                assert volume["Source"] == str(root / declared[target]) and volume["RW"] == ((name, target) in writable)
            raw_secrets = {"DATABASE_URL", "OPENUEM_AGENT_DATABASE_URL", "JWT_KEY", "ENCRYPTION_MASTER_KEY", "WINDOWS_MDM_MASTER_KEY"}
            assert not raw_secrets & {value.split("=", 1)[0] for value in item["Config"]["Env"]}
        for network in rendered["networks"].values():
            inspection = json.loads(command("offline network inspection", "docker", "network", "inspect", network["name"]).stdout)[0]
            assert inspection["Internal"]

        targets = []
        for item in containers:
            name = item["Config"]["Labels"]["com.docker.compose.service"]
            selected = {"database": ("data", [5432]), "broker": ("messaging", [4222, 9222]),
                        "console": ("console_backend", [8444, 8445, 8446, 8447, 8448])}.get(name)
            if selected:
                network, ports = selected
                address = item["NetworkSettings"]["Networks"][project + "_" + network]["IPAddress"]
                targets.extend(address + ":" + str(port) for port in ports)
        probe("public edge backend isolation", "TestReferenceNetworkIsolation", edge,
              values=[("OPENUEM_REFERENCE_PRIVATE_TARGETS", ",".join(targets))])

        compose("reference joined shutdown", "stop", timeout=60)
        stopped = json.loads(command("shutdown verification", "docker", "inspect", *[item["Id"] for item in containers]).stdout)
        assert all(not item["State"]["Running"] and item["State"]["ExitCode"] == 0 for item in stopped)
        compose("retained database and broker startup", "start", "database", "broker")
        database_ready()
        broker_ready()
        compose("retained console and gateway startup", "start", "console", "gateway")
        administrator(True)
        compose("retained private service startup", "start", "authorization", "commands", "worker")
        health()
        probe("retained device WSS admission", "TestReferenceDevice", edge, device)
        probe("retained durable state", "TestReferenceRegistry", data_network, private,
              [("OPENUEM_REFERENCE_ACTION", "verify")])

        held = command("live device probe", "docker", "run", "--detach", "--network", edge, *probe_base, *device,
                       *mount(root / "ready", "/ready", False), "--env", "OPENUEM_REFERENCE_ACTION=hold",
                       "--entrypoint", "/reference.test", args.broker_image,
                       "-test.v", "-test.run=^TestReferenceDevice$", "-test.timeout=45s").stdout.strip()
        cleanup.callback(remove, held)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and not (root / "ready/connected").exists():
            time.sleep(0.1)
        if not (root / "ready/connected").exists():
            raise RuntimeError("live device did not establish its WSS session")
        probe("durable device revocation", "TestReferenceRegistry", data_network, private,
              [("OPENUEM_REFERENCE_ACTION", "revoke")])
        assert command("live device disconnection", "docker", "wait", held, timeout=40).stdout.strip() == "0"
        output = command("live device result", "docker", "logs", held)
        assert "--- PASS: TestReferenceDevice " in output.stdout + output.stderr
        health()
        probe("revoked device re-admission denial", "TestReferenceDevice", edge, device,
              [("OPENUEM_REFERENCE_ACTION", "denied")])
        print("reference restart: retained login/device state, command reconciliation and live WSS revocation passed", flush=True)


if __name__ == "__main__":
    main()

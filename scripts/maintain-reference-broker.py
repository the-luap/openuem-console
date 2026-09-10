"""Review and resume the supported broker migration in an existing reference project.

All Compose inputs and images are explicit. This command never creates a fresh
installation, deletes persistent storage, pulls images or publishes new ports.
"""

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import pathlib
import re
import signal
import stat
import subprocess
import sys
import time
import uuid


class MaintenanceError(Exception):
    pass


ROLES = {"database", "broker", "console", "authorization", "commands", "worker", "gateway"}
CLIENTS = ("console", "authorization", "commands", "worker", "gateway")
NETWORKS = {"database": {"data"}, "broker": {"messaging", "broker_backend"},
            "console": {"data", "messaging", "console_backend", "egress"},
            "authorization": {"data", "messaging"}, "commands": {"data", "messaging"},
            "worker": {"data", "messaging"}, "gateway": {"edge", "console_backend", "broker_backend"}}
STEPS = ("clients-stopped", "broker-stopped", "configuration-applied", "broker-started", "services-ready", "complete")
OPERATION = "broker-worker-grant-v1"


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def pairs(values):
    result = {}
    for name, value in values:
        if name in result:
            raise MaintenanceError("duplicate metadata fields are not supported")
        result[name] = value
    return result


def decode(data):
    return json.loads(data, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(MaintenanceError("invalid numeric metadata")))


def private(path, directory=False):
    info = path.lstat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not kind(info.st_mode) or info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o077 or not directory and info.st_nlink != 1:
        raise MaintenanceError("maintenance state must have private ownership and permissions")
    return info


def read_record(path):
    if not path.exists() and not path.is_symlink():
        return None
    before = private(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        actual = os.fstat(source.fileno())
        if (before.st_dev, before.st_ino) != (actual.st_dev, actual.st_ino) or actual.st_size > 4 << 20:
            raise MaintenanceError("maintenance metadata changed while opening")
        data = source.read((4 << 20) + 1)
    value = decode(data)
    if data != encoded(value):
        raise MaintenanceError("maintenance metadata is incomplete or noncanonical")
    return value


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_record(path, value):
    data = encoded(value)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    sync_directory(path.parent)


def ensure_directory(path):
    try:
        path.mkdir(mode=0o700)
        sync_directory(path.parent)
    except FileExistsError:
        pass
    return private(path, True)


def mount(source, target, writable=False):
    if "," in str(source):
        raise MaintenanceError("bind paths cannot contain commas")
    return ["--mount", "type=bind,source=" + str(source) + ",destination=" + target + ("" if writable else ",readonly")]


def layout(root, bootstrap=False):
    database = {"/run/database.url": "credentials/state/database.url", "/run/database-ca.pem": "pki/state/trust/backend-ca.pem",
                "/run/backend-ca.pem": "pki/state/trust/backend-ca.pem"}
    files = {
        "database": {"/var/lib/postgresql/data": "database", "/run/database-password": "credentials/state/administrator-password",
                     "/run/database-tls": "pki/state/database", "/run/pg_hba.conf": "pg_hba.conf"},
        "broker": {"/run/broker.json": "broker/state/broker.json", "/run/broker-tls": "pki/state/broker", "/var/lib/openuem/jetstream": "jetstream"},
        "gateway": {"/run/public": "public", "/run/gateway": "pki/state/gateway"},
        "authorization": {**database, "/run/issuer.seed": "broker/state/authorization-issuer.seed", "/run/authorization.seed": "broker/state/authorization-user.seed",
                          "/run/revocation.seed": "broker/state/revocation-user.seed"},
        "commands": {**database, "/run/provisioner.seed": "broker/state/provisioner-user.seed"},
        "worker": {**database, "/run/worker.seed": "broker/state/worker-user.seed", "/run/encryption.key": "installation/state/encryption.key"},
        "console": {**database, "/run/jwt.key": "installation/state/jwt.key", "/run/encryption.key": "installation/state/encryption.key",
                    "/run/console.seed": "broker/state/console-user.seed",
                    "/run/console-tls": "pki/state/console", "/run/administrator-ca.pem": "administrator-ca.pem",
                    "/run/windows.key": "protocol/state/windows.key", "/run/desktop-bootstrap.key": "protocol/state/desktop-bootstrap.key",
                    "/run/release-keys.pem": "release-keys.pem", "/run/releases": "releases", "/var/log/openuem-server": "console-logs"}}
    if bootstrap:
        files["console"]["/run/initial-password"] = "installation/state/initial-password"
    writable = {("database", "/var/lib/postgresql/data"), ("broker", "/var/lib/openuem/jetstream"), ("console", "/var/log/openuem-server")}
    return {role: {target: (root / source, (role, target) in writable) for target, source in values.items()} for role, values in files.items()}


class Docker:
    def __init__(self, environment=None):
        self.environment = environment

    def run(self, stage, *arguments, check=True, timeout=45):
        try:
            result = subprocess.run(["docker", *arguments], capture_output=True, text=True, timeout=timeout, env=self.environment)
        except (OSError, subprocess.TimeoutExpired):
            raise MaintenanceError(stage + " did not complete") from None
        if check and result.returncode:
            raise MaintenanceError(stage + " failed")
        return result.stdout + (result.stderr if arguments and arguments[0] == "logs" else "")

    def objects(self, stage, *arguments):
        return decode(self.run(stage, *arguments))


class Maintenance:
    def __init__(self, arguments, docker=None, after_step=None):
        self.args = arguments
        self.docker = docker or Docker()
        self.after_step = after_step
        self.active = False
        self.done = False
        self.record = None
        self.roles = {}
        if os.name != "posix" or os.geteuid() == 0 or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", arguments.project_name):
            raise MaintenanceError("maintenance requires an explicit reference project and a non-root POSIX account")
        directory = pathlib.Path(arguments.project_directory)
        if not directory.is_absolute() or directory == directory.parent:
            raise MaintenanceError("project directory must be absolute")
        self.base = ["compose", "--project-name", arguments.project_name, "--project-directory", str(directory)]
        original = [*self.base, "--env-file", arguments.env_file]
        for name in arguments.file:
            if not pathlib.Path(name).is_absolute():
                raise MaintenanceError("Compose files must use explicit absolute paths")
            original += ["--file", name]
        source = self.docker.objects("reference configuration rendering", *original, "config", "--format", "json")
        if set(source.get("services", {})) != ROLES or source.get("name") != arguments.project_name:
            raise MaintenanceError("maintenance requires the complete seven-service reference definition")
        broker_files = {item["target"]: item for item in source["services"]["broker"].get("volumes", [])}
        broker_path = pathlib.Path(broker_files.get("/run/broker.json", {}).get("source", ""))
        if not broker_path.is_absolute() or broker_path.parts[-3:] != ("broker", "state", "broker.json"):
            raise MaintenanceError("broker state does not use the reference layout")
        self.root = broker_path.parents[2].resolve(strict=True)
        root_info = private(self.root, True)
        self.root_identity = (root_info.st_dev, root_info.st_ino)
        self.state = self.root / "maintenance" / OPERATION
        if self.state.exists() or self.state.is_symlink():
            private(self.root / "maintenance", True)
            private(self.state, True)
            self.record = read_record(self.state / "review.json")
            if self.record is None and set(item.name for item in self.state.iterdir()) - {"lease"}:
                raise MaintenanceError("maintenance review is missing from retained operation state")
        self.steps = self.read_steps() if self.record else []
        self.images = {}
        self.definition = {key: value for key, value in source.items() if not key.startswith("x-")}
        for role, service in self.definition["services"].items():
            image = self.image(service["image"])
            service["image"] = image["Id"]
            self.images[role] = image
        self.setup = self.image(arguments.setup_image, "/openuem-cert-manager")["Id"]
        self.probe_image = self.image(arguments.probe_image, "/openuem-reference-probe")["Id"]
        self.account = self.definition["services"]["broker"].get("user", "")
        if not re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*", self.account):
            raise MaintenanceError("reference containers require an explicit non-root UID and GID")
        bootstrap = any(item.get("target") == "/run/initial-password" for item in self.definition["services"]["console"].get("volumes", []))
        self.expected_mounts = layout(self.root, bootstrap)
        self.inspect()
        self.validate()
        self.current_broker = self.broker_plan()
        self.binding = {"project": arguments.project_name, "project_directory": str(directory), "configuration": digest(self.definition),
                        "setup_image": self.setup, "probe_image": self.probe_image, "state": str(self.root), "account": self.account}
        ids = {role: value["Id"] for role, value in self.roles.items()}
        if self.record:
            if set(self.record) != {"version", "operation", "binding", "containers", "broker", "review_sha256"} or self.record["version"] != 1 or self.record["operation"] != OPERATION:
                raise MaintenanceError("unsupported maintenance review journal")
            if self.record["binding"] != self.binding or set(self.record["containers"]) != ROLES:
                raise MaintenanceError("deployment inputs changed since the retained review")
            for role, container in self.record["containers"].items():
                if role == "broker" and "configuration-applied" in self.steps:
                    continue
                if ids.get(role) != container["id"]:
                    raise MaintenanceError("a reviewed service container was replaced outside this operation")
            sources = [self.record["broker"]["after_sha256"]] if "configuration-applied" in self.steps else [self.record["broker"]["before_sha256"], self.record["broker"]["after_sha256"]]
            if self.current_broker["before_sha256"] not in sources or self.current_broker["after_sha256"] != self.record["broker"]["after_sha256"]:
                raise MaintenanceError("broker configuration no longer matches the reviewed migration")
            if self.review_hash(self.record) != self.record["review_sha256"]:
                raise MaintenanceError("maintenance review digest is invalid")
        else:
            self.record = {"version": 1, "operation": OPERATION, "binding": self.binding,
                           "containers": {role: {"id": value["Id"], "running": value["State"]["Running"]} for role, value in self.roles.items()},
                           "broker": self.current_broker}
            self.record["review_sha256"] = self.review_hash(self.record)

    @staticmethod
    def review_hash(record):
        return digest({key: value for key, value in record.items() if key != "review_sha256"})

    def read_steps(self):
        present = []
        gap = False
        allowed = {"review.json", "compose.json", "lease"} | {str(index + 1) + "-" + name + ".json" for index, name in enumerate(STEPS)}
        if set(item.name for item in self.state.iterdir()) - allowed:
            raise MaintenanceError("maintenance state contains unexpected entries")
        for index, name in enumerate(STEPS):
            value = read_record(self.state / (str(index + 1) + "-" + name + ".json"))
            if value is None:
                gap = True
            elif gap or value != {"version": 1, "review_sha256": self.record["review_sha256"], "step": name}:
                raise MaintenanceError("maintenance step journal is incomplete or changed")
            else:
                present.append(name)
        return present

    def image(self, reference, entrypoint=None):
        values = self.docker.objects("local image inspection", "image", "inspect", reference)
        if len(values) != 1 or not re.fullmatch(r"sha256:[0-9a-f]{64}", values[0]["Id"]):
            raise MaintenanceError("an exact local image is required")
        if entrypoint and (values[0]["Config"].get("Entrypoint") != [entrypoint] or values[0]["Config"].get("User") != "65532:65532"):
            raise MaintenanceError("the setup or readiness image has an unexpected runtime boundary")
        return values[0]

    def inspect(self):
        ids = self.docker.run("project service inventory", "ps", "--all", "--quiet", "--filter", "label=com.docker.compose.project=" + self.args.project_name).split()
        if not ids:
            raise MaintenanceError("the existing reference project was not found")
        roles = {}
        for value in self.docker.objects("project runtime inspection", "inspect", *ids):
            labels = value["Config"].get("Labels") or {}
            role = labels.get("com.docker.compose.service")
            if labels.get("com.docker.compose.project") != self.args.project_name or role not in ROLES or role in roles or labels.get("com.docker.compose.oneoff", "False").lower() != "false":
                raise MaintenanceError("project service identities are ambiguous")
            roles[role] = value
        missing = ROLES - set(roles)
        if missing and not (missing == {"broker"} and "configuration-applied" in self.steps):
            raise MaintenanceError("a required reference service container is missing")
        self.roles = roles

    @staticmethod
    def environment(values):
        result = {}
        for item in values or []:
            name, separator, value = item.partition("=")
            if not separator or name in result:
                raise MaintenanceError("container environment is ambiguous")
            result[name] = value
        return result

    @staticmethod
    def invocation(service, image):
        # Compose renders inherited values as null; an empty list deliberately
        # clears them. An explicit entrypoint also suppresses the image CMD.
        entrypoint = service.get("entrypoint")
        command = service.get("command")
        if command is None:
            command = image.get("Cmd") if entrypoint is None else []
        if entrypoint is None:
            entrypoint = image.get("Entrypoint")
        return (entrypoint or [], command or [])

    def validate(self):
        if any(self.definition.get(name) for name in ("volumes", "secrets", "configs", "models")):
            raise MaintenanceError("reference maintenance cannot create additional project resources")
        networks = self.definition.get("networks", {})
        if set(networks) != {"data", "messaging", "console_backend", "broker_backend", "edge", "egress"}:
            raise MaintenanceError("reference network definitions changed")
        for name, network in networks.items():
            if network.get("name") != self.args.project_name + "_" + name or network.get("external") or name not in ("edge", "egress") and not network.get("internal"):
                raise MaintenanceError("backend networks must remain private and owned by this project")
        actual_networks = self.docker.objects("reference network inspection", "network", "inspect", *(item["name"] for item in networks.values()))
        for actual in actual_networks:
            logical = actual["Name"][len(self.args.project_name) + 1:]
            if actual["Name"] != networks[logical]["name"] or bool(actual["Internal"]) != bool(networks[logical].get("internal")) or (actual.get("Labels") or {}).get("com.docker.compose.project") != self.args.project_name:
                raise MaintenanceError("reference network ownership or isolation changed")
        for role, service in self.definition["services"].items():
            if service.get("user") != self.account or not service.get("read_only") or service.get("cap_drop") != ["ALL"] or "no-new-privileges:true" not in service.get("security_opt", []):
                raise MaintenanceError("reference service privilege policy changed")
            if any(service.get(name) for name in ("privileged", "cap_add", "devices", "device_cgroup_rules", "network_mode", "pid", "ipc", "volumes_from", "secrets", "configs", "build", "provider", "pre_start", "post_start", "pre_stop", "use_api_socket")):
                raise MaintenanceError("unsupported reference runtime override")
            if set(service.get("networks", {})) != NETWORKS[role] or service.get("pull_policy") != "never":
                raise MaintenanceError("service network or image policy changed")
            declared = {item["target"]: item for item in service.get("volumes", [])}
            if len(declared) != len(service.get("volumes", [])) or set(declared) != set(self.expected_mounts[role]):
                raise MaintenanceError("reference mount recipients changed")
            for target, (source, writable) in self.expected_mounts[role].items():
                item = declared[target]
                path = self.root
                for part in source.relative_to(self.root).parts:
                    path = path / part
                    if path.is_symlink():
                        raise MaintenanceError("state mounts cannot alias another input")
                info = source.lstat()
                private(source, stat.S_ISDIR(info.st_mode))
                if item.get("type") != "bind" or pathlib.Path(item.get("source", "")).resolve() != source or bool(item.get("read_only")) == writable or item.get("bind", {}).get("create_host_path"):
                    raise MaintenanceError("reference bind source or access mode changed")
            ports = service.get("ports", [])
            if ports and (role != "gateway" or len(ports) != 1 or ports[0].get("target") != 8443 or str(ports[0].get("published")) != "443" or ports[0].get("protocol") != "tcp"):
                raise MaintenanceError("reference maintenance cannot introduce exposed backend ports")
            if role not in self.roles:
                continue
            actual = self.roles[role]
            host, config = actual["HostConfig"], actual["Config"]
            if actual["Image"] != service["image"] or config.get("User") != self.account or not host.get("ReadonlyRootfs") or host.get("Privileged") or host.get("CapDrop") != ["ALL"] or "no-new-privileges:true" not in host.get("SecurityOpt", []):
                raise MaintenanceError("running service image or privilege boundary differs from the review")
            if host.get("CapAdd") or host.get("Devices") or host.get("DeviceRequests") or host.get("PidMode") or host.get("IpcMode") not in ("private", ""):
                raise MaintenanceError("running service has unsupported host access")
            image_config = self.images[role]["Config"]
            expected_environment = {**self.environment(image_config.get("Env")), **service.get("environment", {})}
            if self.environment(config.get("Env")) != expected_environment:
                raise MaintenanceError("running service environment differs from the reference definition")
            for forbidden in ("DATABASE_URL", "OPENUEM_AGENT_DATABASE_URL", "JWT_KEY", "ENCRYPTION_MASTER_KEY", "WINDOWS_MDM_MASTER_KEY"):
                if expected_environment.get(forbidden):
                    raise MaintenanceError("raw runtime credentials are not supported by reference maintenance")
            entrypoint, command = self.invocation(service, image_config)
            if (config.get("Cmd") or []) != command:
                raise MaintenanceError("running " + role + " arguments differ from the reference definition")
            if (config.get("Entrypoint") or []) != entrypoint:
                raise MaintenanceError("running " + role + " entrypoint differs from the reference definition")
            if set(actual["NetworkSettings"]["Networks"]) != {networks[name]["name"] for name in NETWORKS[role]}:
                raise MaintenanceError("running service network membership changed")
            mounts = {item["Destination"]: item for item in actual["Mounts"]}
            if len(mounts) != len(actual["Mounts"]) or set(mounts) != set(declared):
                raise MaintenanceError("running service mount recipients changed")
            for target, (source, writable) in self.expected_mounts[role].items():
                item = mounts[target]
                if item["Type"] != "bind" or pathlib.Path(item["Source"]).resolve() != source or bool(item["RW"]) != writable:
                    raise MaintenanceError("running service bind source or mode changed")
            bindings = host.get("PortBindings") or {}
            if not ports and bindings or ports and (set(bindings) != {"8443/tcp"} or any(item["HostPort"] != "443" for item in bindings["8443/tcp"])):
                raise MaintenanceError("running service port publication differs from the reference definition")
        if not self.roles["database"]["State"]["Running"] or self.roles["database"]["State"].get("Health", {}).get("Status") != "healthy":
            raise MaintenanceError("the retained reference database is not healthy")
        if self.definition["services"]["broker"].get("command") != ["--config", "/run/broker.json"] or self.images["broker"]["Config"].get("Entrypoint") != ["/nats-server"]:
            raise MaintenanceError("the broker is not the supported stock runtime")

    def job(self, stage, image, network, inputs, arguments):
        name = "openuem-maintenance-" + uuid.uuid4().hex[:16]
        try:
            return self.docker.run(stage, "run", "--rm", "--name", name, "--network", network,
                                   "--user", self.account, "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                                   "--pids-limit", "96", "--memory", "256m", *inputs, image, *arguments)
        finally:
            with contextlib.suppress(MaintenanceError):
                self.docker.run("owned maintenance job cleanup", "rm", "--force", name, check=False)

    def broker_plan(self):
        plan = decode(self.job("broker configuration preview", self.setup, "none", mount(self.root / "broker/state", "/broker"),
                               ["individual-broker-upgrade", "--directory", "/broker", "--check"]))
        if set(plan) != {"version", "before_sha256", "after_sha256", "change_required", "added_worker_requests"} or plan["version"] != 1 or not all(re.fullmatch(r"[0-9a-f]{64}", plan[name]) for name in ("before_sha256", "after_sha256")):
            raise MaintenanceError("unsupported broker upgrade preview")
        additions = ["hardware", "recovery", "rotation"] if plan["change_required"] else []
        if type(plan["change_required"]) is not bool or plan["added_worker_requests"] != additions:
            raise MaintenanceError("broker migration changes an unsupported permission boundary")
        return plan

    def public_plan(self):
        return {"operation": OPERATION, "project": self.args.project_name, "review_sha256": self.record["review_sha256"],
                "broker_before_sha256": self.record["broker"]["before_sha256"], "broker_after_sha256": self.record["broker"]["after_sha256"],
                "change_required": self.current_broker["change_required"], "completed_steps": self.steps,
                "maintenance_pending": self.record["broker"]["change_required"] and "complete" not in self.steps,
                "service_interruption": list(CLIENTS) + ["broker"], "database_retained": True}

    def marker(self, step):
        if step in self.steps:
            return
        if STEPS[len(self.steps)] != step:
            raise MaintenanceError("maintenance step order is invalid")
        self.check_lease()
        write_record(self.state / (str(len(self.steps) + 1) + "-" + step + ".json"),
                     {"version": 1, "review_sha256": self.record["review_sha256"], "step": step})
        self.steps.append(step)
        if self.after_step:
            self.after_step(step)

    def check_lease(self):
        root = private(self.root, True)
        if (root.st_dev, root.st_ino) != self.root_identity:
            raise MaintenanceError("the installation state directory was replaced")
        current = private(self.state, True)
        lease = private(self.state / "lease")
        held = os.fstat(self.lease)
        if (current.st_dev, current.st_ino) != self.state_identity or (lease.st_dev, lease.st_ino) != (held.st_dev, held.st_ino):
            raise MaintenanceError("maintenance state or lease identity changed")

    def stop(self, roles):
        if self.active:
            self.check_lease()
        self.inspect()
        for role in roles:
            if role not in self.roles:
                continue
            value = self.roles[role]
            was_running = value["State"]["Running"]
            if was_running:
                self.docker.run("service shutdown", "stop", "--time", "20", value["Id"])
            state = self.docker.objects("joined shutdown inspection", "inspect", value["Id"])[0]["State"]
            # A crash after docker stop but before the durable marker must not
            # turn an unsuccessful shutdown into an accepted stopped service.
            requires_clean_exit = was_running or (self.record["containers"][role]["running"] and "broker-started" not in self.steps)
            if state["Running"] or requires_clean_exit and state["ExitCode"] != 0:
                raise MaintenanceError("a reference service did not join a successful shutdown")

    def start(self, role):
        if self.active:
            self.check_lease()
        self.inspect()
        if not self.roles[role]["State"]["Running"]:
            self.docker.run("retained service startup", "start", self.roles[role]["Id"])

    def ready(self, network, inputs, arguments):
        result = decode(self.job("reference readiness", self.probe_image, network, inputs, [*arguments, "--timeout", "20s"]))
        if result != {"ready": True}:
            raise MaintenanceError("reference readiness was not positively established")

    def broker_ready(self):
        self.ready(self.args.project_name + "_messaging",
                   [*mount(self.root / "broker/state/worker-user.seed", "/worker.seed"), *mount(self.root / "pki/state/trust/backend-ca.pem", "/ca.pem")],
                   ["--mode", "broker", "--address", "tls://broker.internal:4222", "--trust-file", "/ca.pem", "--key-file", "/worker.seed"])

    def services_ready(self):
        self.inspect()
        for role, port in (("authorization", "1326"), ("commands", "1327")):
            self.ready("container:" + self.roles[role]["Id"], [], ["--mode", "http", "--address", "http://127.0.0.1:" + port + "/healthz"])
        worker = self.roles["worker"]
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            current = self.docker.objects("worker readiness inspection", "inspect", worker["Id"])[0]
            if not current["State"]["Running"]:
                raise MaintenanceError("the retained worker exited before readiness")
            # Driver logs stay private; only the fixed startup marker is examined.
            output = self.docker.run("worker subscription readiness", "logs", "--since", current["State"]["StartedAt"], "--tail", "50", worker["Id"])
            if "individual agent worker subscriptions established" in output:
                break
            time.sleep(0.1)
        else:
            raise MaintenanceError("worker subscriptions did not become ready")
        self.start("gateway")
        self.inspect()
        endpoint = self.roles["gateway"]["NetworkSettings"]["Networks"][self.args.project_name + "_edge"]["IPAddress"]
        origin = self.definition["services"]["console"]["environment"]["OPENUEM_PUBLIC_ORIGIN"]
        self.ready(self.args.project_name + "_edge", mount(self.root / "public/server.pem", "/gateway.pem"),
                   ["--mode", "gateway", "--address", endpoint + ":8443", "--origin", origin, "--trust-file", "/gateway.pem"])
        self.inspect()
        self.validate()
        if any(not value["State"]["Running"] for value in self.roles.values()):
            raise MaintenanceError("a reference service stopped before readiness completed")

    def apply(self, expected):
        if expected != self.record["review_sha256"]:
            raise MaintenanceError("the reviewed maintenance digest does not match this deployment")
        if "complete" in self.steps:
            return {"status": "already-complete", "review_sha256": expected}
        if not self.record["broker"]["change_required"]:
            return {"status": "unchanged", "review_sha256": expected}
        ensure_directory(self.root / "maintenance")
        info = ensure_directory(self.state)
        self.state_identity = (info.st_dev, info.st_ino)
        self.lease = os.open(self.state / "lease", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            self.check_lease()
            try:
                fcntl.flock(self.lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise MaintenanceError("another reference maintenance operation holds the lease") from None
            existing = read_record(self.state / "review.json")
            if existing is None:
                if set(item.name for item in self.state.iterdir()) != {"lease"}:
                    raise MaintenanceError("maintenance review is missing from existing operation state")
                write_record(self.state / "review.json", self.record)
            elif existing != self.record:
                raise MaintenanceError("maintenance review changed before the lease was acquired")
            self.steps = self.read_steps()
            snapshot = {"version": 1, "review_sha256": expected, "compose": self.definition}
            saved = read_record(self.state / "compose.json")
            if saved is None:
                if self.steps:
                    raise MaintenanceError("committed maintenance definition is missing")
                write_record(self.state / "compose.json", snapshot)
            elif saved != snapshot:
                raise MaintenanceError("retained maintenance definition changed")
            self.active = True
            # Never use mutable original files to recreate a service. Supply the
            # reviewed rendered model on stdin, escaping literal Compose dollars.
            self.stop(("gateway",))
            if "broker-started" not in self.steps:
                self.stop(("worker", "authorization", "commands", "console"))
                self.marker("clients-stopped")
                if "configuration-applied" not in self.steps:
                    self.stop(("broker",))
                    self.marker("broker-stopped")
                    completed = decode(self.job("reviewed broker configuration upgrade", self.setup, "none", mount(self.root / "broker/state", "/broker", True),
                                                ["individual-broker-upgrade", "--directory", "/broker", "--expected-sha256", self.record["broker"]["before_sha256"]]))
                    if completed.get("after_sha256") != self.record["broker"]["after_sha256"] or completed.get("change_required") is not False:
                        raise MaintenanceError("broker migration did not confirm the reviewed target")
                    self.marker("configuration-applied")
                self.inspect()
                original = self.record["containers"]["broker"]["id"]
                if "broker" not in self.roles or self.roles["broker"]["Id"] == original:
                    self.recreate_broker()
                self.start("broker")
                self.broker_ready()
                self.marker("broker-started")
            else:
                self.start("broker")
                self.broker_ready()
            for role in ("console", "authorization", "commands", "worker"):
                self.start(role)
            self.services_ready()
            self.marker("services-ready")
            self.marker("complete")
            self.done = True
            return {"status": "complete", "review_sha256": expected, "ready": True}
        finally:
            if self.active and not self.done:
                with contextlib.suppress(Exception):
                    self.stop(("gateway",))
            os.close(self.lease)

    def recreate_broker(self):
        self.check_lease()
        # stdin avoids a second mutable configuration file. The round trip must
        # reproduce the frozen model exactly before Compose is allowed to act.
        data = encoded(self.definition).decode().replace("$", "$$")
        invocation = ["docker", *self.base, "--env-file", "/dev/null", "--file", "-"]
        try:
            check = subprocess.run([*invocation, "config", "--format", "json"], input=data, text=True, capture_output=True, timeout=30, env=self.docker.environment)
            if check.returncode or decode(check.stdout) != self.definition:
                raise MaintenanceError("the frozen Compose model did not round-trip unchanged")
            self.check_lease()
            result = subprocess.run([*invocation, "up", "--detach", "--no-deps", "--force-recreate", "broker"], input=data, text=True, capture_output=True, timeout=45, env=self.docker.environment)
            if result.returncode:
                raise MaintenanceError("reviewed broker container recreation failed")
        except (OSError, subprocess.TimeoutExpired):
            raise MaintenanceError("broker container recreation did not complete; resume retained maintenance") from None
        self.inspect()
        self.validate()
        if self.roles["broker"]["Id"] == self.record["containers"]["broker"]["id"]:
            raise MaintenanceError("the reviewed broker container was not recreated")


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise MaintenanceError("reference maintenance arguments are invalid")


def arguments(values=None):
    parser = Parser(description=__doc__)
    parser.add_argument("--project-name", required=True)
    parser.add_argument("--project-directory", required=True)
    parser.add_argument("--file", action="append", required=True, help="Explicit absolute Compose file; repeat for overlays")
    parser.add_argument("--env-file", default="/dev/null", help="Explicit Compose environment file (default: /dev/null)")
    parser.add_argument("--setup-image", required=True, help="Locally available retained broker upgrade image")
    parser.add_argument("--probe-image", required=True, help="Locally available reference readiness image")
    parser.add_argument("--expected-review", help="Reviewed digest; required with --apply")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="Read-only public review of this existing project")
    mode.add_argument("--apply", action="store_true", help="Apply or resume the exact reviewed migration")
    result = parser.parse_args(values)
    if result.check and result.expected_review or result.apply and not result.expected_review or not pathlib.Path(result.env_file).is_absolute():
        raise MaintenanceError("reference maintenance requires an unambiguous review and explicit environment file")
    return result


def main(values=None):
    try:
        args = arguments(values)
        operation = Maintenance(args)
        result = operation.public_plan() if args.check else operation.apply(args.expected_review)
        print(json.dumps(result, sort_keys=True))
        return 0
    except MaintenanceError as error:
        print(str(error), file=sys.stderr)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        # Docker output, configuration, paths and driver errors remain private.
        print("reference maintenance failed; existing state was retained", file=sys.stderr)
    return 1


if __name__ == "__main__":
    def interrupted(_signal, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("reference maintenance interrupted; resume with the retained review", file=sys.stderr)
        sys.exit(130)

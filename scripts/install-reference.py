"""Review, initialize and resume a complete reference installation.

Uses explicit local images and protected inputs. Persistent state is retained;
the command never pulls images, deletes data or prints generated credentials.
"""

import argparse
import base64
import contextlib
import fcntl
import hashlib
import importlib.util
import ipaddress
import json
import os
import pathlib
import re
import signal
import ssl
import stat
import subprocess
import sys
import time
import urllib.parse


sys.dont_write_bytecode = True
REPOSITORY = pathlib.Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("reference_maintenance", REPOSITORY / "scripts/maintain-reference-broker.py")
maintenance = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(maintenance)
encoded, digest, decode = maintenance.encoded, maintenance.digest, maintenance.decode
private, read_record, write_record = maintenance.private, maintenance.read_record, maintenance.write_record
ensure_directory, mount = maintenance.ensure_directory, maintenance.mount


class InstallationError(Exception):
    pass


DATABASE_IMAGE = "postgres@sha256:051f7b7b3abdd564d5d1bd1e8c4b9c1b6e77087d1dd22020ede611c096a272e0"
EXECUTABLES = {
    "installation": "/openuem-installation-secrets", "protocol": "/openuem-protocol-keys",
    "credentials": "/openuem-database-credentials", "bootstrap": "/openuem-database-bootstrap",
    "pki": "/openuem-cert-manager", "probe": "/openuem-reference-probe",
    "console": "/openuem-console", "broker": "/nats-server", "authorization": "/openuem-agent-auth",
    "commands": "/openuem-agent-commands", "worker": "/openuem-worker", "gateway": "/openuem-gateway",
}
STEPS = ("inputs", "installation", "protocol", "credentials", "pki", "broker", "configuration",
         "database", "bootstrap", "runtime", "administrator", "bootstrap-stopped", "bootstrap-retired", "complete")
DIRECTORIES = ("installation", "protocol", "credentials", "pki", "broker", "journal", "database", "jetstream", "console-logs", "public", "releases")
PROJECT_LABEL = "io.openuem.setup.project"
REVIEW_LABEL = "io.openuem.setup.review"
JOB_LABEL = "io.openuem.setup.job"


def read_file(path, limit=1 << 20, secret=True, allow_empty=False):
    path = pathlib.Path(path)
    if not path.is_absolute() or str(path) != str(path.resolve(strict=True)):
        raise InstallationError("installation inputs must use canonical absolute paths")
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid not in (0, os.geteuid()) or before.st_mode & (0o077 if secret else 0o022):
        raise InstallationError("installation inputs require trusted ownership and protected regular files")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        actual = os.fstat(source.fileno())
        if (actual.st_dev, actual.st_ino) != (before.st_dev, before.st_ino) or actual.st_size > limit:
            raise InstallationError("installation input changed while opening or exceeded its limit")
        data = source.read(limit + 1)
    if not data and not allow_empty or len(data) > limit:
        raise InstallationError("installation input is empty or too large")
    return data


def public_tls(certificate, key, hostname):
    """Check a pinned local TLS pair using an in-memory handshake, without sockets."""
    if not hasattr(ssl, "VERIFY_X509_PARTIAL_CHAIN"):
        raise InstallationError("installation requires Python 3.10 or newer with partial-chain TLS verification")
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.minimum_version = ssl.TLSVersion.TLSv1_2
    server.load_cert_chain(certificate, key)
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.minimum_version = ssl.TLSVersion.TLSv1_2
    client.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    client.load_verify_locations(cafile=certificate)
    incoming, outgoing = [ssl.MemoryBIO(), ssl.MemoryBIO()], [ssl.MemoryBIO(), ssl.MemoryBIO()]
    peers = [client.wrap_bio(incoming[0], outgoing[0], server_hostname=hostname),
             server.wrap_bio(incoming[1], outgoing[1], server_side=True)]
    done = [False, False]
    for _ in range(16):
        for index, peer in enumerate(peers):
            if not done[index]:
                try:
                    peer.do_handshake()
                    done[index] = True
                except ssl.SSLWantReadError:
                    pass
            data = outgoing[index].read()
            if data:
                incoming[1 - index].write(data)
        if all(done):
            return hashlib.sha256(peers[0].getpeercert(binary_form=True)).hexdigest()
    raise InstallationError("public TLS inputs did not complete their local verification")


def release_keys(data):
    # RFC 8410 Ed25519 SubjectPublicKeyInfo has this exact DER prefix and a
    # 32-byte public key. Private keys, other algorithms and BER are rejected.
    prefix = bytes.fromhex("302a300506032b6570032100")
    pattern = re.compile(rb"\s*-----BEGIN PUBLIC KEY-----\r?\n([A-Za-z0-9+/=\r\n]+)-----END PUBLIC KEY-----\s*")
    remaining, keys = data, []
    while remaining:
        match = pattern.match(remaining)
        if match is None or len(keys) == 8:
            raise InstallationError("release trust must contain one to eight distinct Ed25519 public keys")
        value = base64.b64decode(re.sub(rb"[\r\n]", b"", match.group(1)), validate=True)
        if len(value) != 44 or value[:12] != prefix or value[12:] in keys:
            raise InstallationError("release trust contains an invalid or repeated public key")
        keys.append(value[12:])
        remaining = remaining[match.end():]
    if not keys:
        raise InstallationError("release public trust is empty")
    return [hashlib.sha256(key).hexdigest() for key in keys]


def profile(path):
    value = decode(read_file(path, 64 << 10))
    required = {"version", "project", "directory", "domain", "organization", "public_origin", "administrator", "administrator_networks", "access", "tls_certificate", "tls_key", "release_keys", "images"}
    if not isinstance(value, dict) or set(value) != required or type(value["version"]) is not int or value["version"] != 1:
        raise InstallationError("installation configuration must contain the exact version-one fields")
    if not all(isinstance(value[name], str) for name in required - {"version", "images", "administrator_networks"}):
        raise InstallationError("installation configuration contains an invalid field type")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,47}", value["project"]) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._@+\-]{0,127}", value["administrator"]):
        raise InstallationError("installation project or administrator name is invalid")
    dns = r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+"
    origin = urllib.parse.urlsplit(value["public_origin"])
    if not re.fullmatch(dns, value["domain"]) or origin.scheme != "https" or not re.fullmatch(dns, origin.hostname or "") or origin.username is not None or origin.path or origin.query or origin.fragment or value["public_origin"] != "https://" + origin.netloc or value["access"] not in ("public", "isolated"):
        raise InstallationError("installation requires an explicit HTTPS DNS origin and public or isolated access")
    expected_origin = "https://" + origin.hostname + (":8443" if value["access"] == "isolated" else "")
    if value["public_origin"] != expected_origin:
        raise InstallationError("public installation uses TCP 443; isolated acceptance uses origin port 8443")
    label = value["organization"]
    if not label or label != label.strip() or len(label.encode()) > 255 or any(ord(char) < 32 or ord(char) == 127 for char in label):
        raise InstallationError("installation organization label is invalid")
    networks = value["administrator_networks"]
    if not isinstance(networks, list) or not 1 <= len(networks) <= 32 or not all(isinstance(network, str) for network in networks) or len(set(networks)) != len(networks):
        raise InstallationError("administrator access requires an explicit bounded source-network list")
    for network in networks:
        parsed = ipaddress.ip_network(network, strict=True)
        if not isinstance(network, str) or str(parsed) != network or parsed.prefixlen == 0 or parsed.is_multicast or parsed.is_unspecified:
            raise InstallationError("administrator source networks must be canonical limited CIDRs")
    if not isinstance(value["images"], dict) or set(value["images"]) != set(EXECUTABLES) or any(not isinstance(image, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./:@-]{0,511}", image) for image in value["images"].values()):
        raise InstallationError("installation requires all explicit local setup and service images")
    root = pathlib.Path(value["directory"])
    if not root.is_absolute() or root == root.parent or str(root) != str(root.resolve(strict=True)) or "," in str(root):
        raise InstallationError("installation directory must be an existing canonical private absolute path")
    private(root, True)
    return value


class Docker(maintenance.Docker):
    def __init__(self):
        environment = {key: os.environ[key] for key in ("PATH", "HOME", "DOCKER_CONFIG", "DOCKER_CONTEXT", "DOCKER_HOST") if key in os.environ}
        super().__init__(environment)
        endpoint = environment.get("DOCKER_HOST")
        if not endpoint or environment.get("DOCKER_CONTEXT"):
            context = self.objects("local Docker context", "context", "inspect")[0]
            endpoint = context["Endpoints"]["docker"]["Host"]
        if not endpoint.startswith("unix://"):
            raise InstallationError("reference installation requires a local Unix-socket Docker context")
        self.identity = self.run("local Docker identity", "info", "--format", "{{.ID}}").strip()
        if not self.identity:
            raise InstallationError("local Docker identity is unavailable")

    def compose(self, base, definition, *arguments):
        content = encoded(definition).decode().replace("$", "$$")
        invocation = ["docker", *base, "--env-file", "/dev/null", "--file", "-"]
        result = subprocess.run([*invocation, "config", "--format", "json"], input=content, text=True, capture_output=True, timeout=30, env=self.environment)
        if result.returncode or maintenance.compose_model(decode(result.stdout)) != definition:
            raise InstallationError("retained Compose configuration did not round-trip unchanged")
        result = subprocess.run([*invocation, *arguments], input=content, text=True, capture_output=True, timeout=60, env=self.environment)
        if result.returncode:
            raise InstallationError("reference service operation failed; state was retained")
        return result.stdout


class Installation:
    def __init__(self, config, docker=None, after_step=None):
        if os.name != "posix" or os.geteuid() == 0 or os.getegid() == 0:
            raise InstallationError("reference installation requires a non-root POSIX account")
        self.config = config
        self.root = pathlib.Path(config["directory"])
        info = private(self.root, True)
        self.root_identity = (info.st_dev, info.st_ino)
        self.state = self.root / ".setup"
        self.project = config["project"]
        self.account = str(os.geteuid()) + ":" + str(os.getegid())
        self.docker = docker or Docker()
        self.after_step = after_step
        self.lease = None
        self.steps = []
        self.record = None
        self.images = {}
        self.image_configs = {}
        self.base = ["compose", "--project-name", self.project, "--project-directory", str(self.root)]
        if self.state.exists() or self.state.is_symlink():
            private(self.state, True)
            self.record = read_record(self.state / "review.json")
            self.steps = self.read_steps() if self.record else []
            if not self.record and set(path.name for path in self.state.iterdir()) - {"lease"}:
                raise InstallationError("retained installation review is missing")
        elif any(self.root.iterdir()):
            raise InstallationError("fresh installation requires an empty private directory")
        for role, reference in {**config["images"], "database": DATABASE_IMAGE}.items():
            image = self.docker.objects("local installation image", "image", "inspect", reference)[0]
            if image.get("Os") != "linux" or not re.fullmatch(r"sha256:[0-9a-f]{64}", image.get("Id", "")) or role != "database" and image["Config"].get("Entrypoint") != [EXECUTABLES[role]]:
                raise InstallationError("a local image does not match its selected reference role")
            self.images[role] = image["Id"]
            self.image_configs[role] = image["Config"]
        self.sources = {name: read_file(REPOSITORY / "deploy/reference" / name, secret=False) for name in ("compose.yaml", "compose.bootstrap.yaml")}
        binding = {"version": 1, "configuration": config, "account": self.account, "daemon": self.docker.identity,
                   "root_identity": list(self.root_identity), "images": self.images,
                   "templates": {name: hashlib.sha256(data).hexdigest() for name, data in self.sources.items()}}
        if self.record and "complete" in self.steps:
            if self.record["binding"] != binding:
                raise InstallationError("completed installation review does not match this configuration")
            self.review = self.record["review_sha256"]
            self.inputs = None
            return
        self.inputs = {"public/server.pem": read_file(config["tls_certificate"], 64 << 10, False),
                       "public/server.key": read_file(config["tls_key"], 64 << 10),
                       "release-keys.pem": read_file(config["release_keys"], 64 << 10, False)}
        if any(self.root == pathlib.Path(config[name]) or self.root in pathlib.Path(config[name]).parents for name in ("tls_certificate", "tls_key", "release_keys")):
            raise InstallationError("external installation inputs must remain outside the fresh state directory")
        tls_fingerprint = public_tls(config["tls_certificate"], config["tls_key"], urllib.parse.urlsplit(config["public_origin"]).hostname)
        if self.inputs != {"public/server.pem": read_file(config["tls_certificate"], 64 << 10, False),
                           "public/server.key": read_file(config["tls_key"], 64 << 10),
                           "release-keys.pem": read_file(config["release_keys"], 64 << 10, False)}:
            raise InstallationError("installation inputs changed during TLS verification")
        keys = release_keys(self.inputs["release-keys.pem"])
        input_hashes = {name: hashlib.sha256(data).hexdigest() for name, data in self.inputs.items()}
        self.review = digest({"binding": binding, "inputs": input_hashes})
        proposed = {"binding": binding, "inputs": input_hashes, "public_tls_sha256": tls_fingerprint, "release_keys": keys, "review_sha256": self.review}
        if self.record is not None and self.record != proposed:
            raise InstallationError("retained installation differs from the reviewed inputs or images")
        self.record = proposed
        if not self.state.exists():
            for label in ("com.docker.compose.project", PROJECT_LABEL):
                if self.docker.run("fresh project reservation", "ps", "--all", "--quiet", "--filter", "label=" + label + "=" + self.project).strip():
                    raise InstallationError("installation project already has containers")
            if self.docker.run("fresh network reservation", "network", "ls", "--quiet", "--filter", "label=com.docker.compose.project=" + self.project).strip():
                raise InstallationError("installation project already has networks")

    def public_plan(self):
        return {"status": "complete" if "complete" in self.steps else "awaiting-administrator" if "runtime" in self.steps else "ready-to-resume" if self.steps else "ready-to-initialize",
                "review_sha256": self.review, "project": self.project, "directory": str(self.root),
                "public_origin": self.config["public_origin"], "published_tcp_ports": [443] if self.config["access"] == "public" else [],
                "administrator_networks": self.config["administrator_networks"], "images": self.images,
                "public_tls_sha256": self.record["public_tls_sha256"], "release_keys": self.record["release_keys"], "steps": self.steps}

    def read_steps(self):
        result = []
        allowed = {"lease", "review.json", "source-compose.yaml", "source-compose.bootstrap.yaml",
                   "compose-bootstrap.json", "compose-bootstrap.wire.json", "compose-steady.json", "compose-steady.wire.json"}
        allowed |= {str(index) + "-" + step + ".json" for index, step in enumerate(STEPS, 1)}
        if set(path.name for path in self.state.iterdir()) - allowed:
            raise InstallationError("retained installation journal contains unexpected entries")
        def relative(value):
            return isinstance(value, str) and value not in ("", ".") and not pathlib.Path(value).is_absolute() and ".." not in pathlib.Path(value).parts and str(pathlib.Path(value)) == value
        for index, step in enumerate(STEPS, 1):
            path = self.state / (str(index) + "-" + step + ".json")
            value = read_record(path)
            if value is None:
                continue
            if not isinstance(value, dict) or set(value) != {"step", "review_sha256", "paths", "files", "metadata"} or len(result) != index - 1 or value.get("step") != step or value.get("review_sha256") != self.record["review_sha256"]:
                raise InstallationError("retained installation steps are incomplete or inconsistent")
            if not isinstance(value["paths"], list) or len(value["paths"]) > 64 or not all(relative(path) for path in value["paths"]) or not isinstance(value["files"], dict) or len(value["files"]) > 2048 or not all(relative(path) and isinstance(checksum, str) and re.fullmatch(r"[0-9a-f]{64}", checksum) for path, checksum in value["files"].items()):
                raise InstallationError("retained installation artifact inventory is invalid")
            metadata = value["metadata"]
            if step in ("installation", "administrator"):
                field, length = ("installation", 32) if step == "installation" else ("console", 64)
                if not isinstance(metadata, dict) or set(metadata) != {field} or not isinstance(metadata[field], str) or not re.fullmatch(r"[0-9a-f]{" + str(length) + "}", metadata[field]):
                    raise InstallationError("retained installation identity metadata is invalid")
            elif metadata is not None:
                raise InstallationError("retained installation step contains unexpected metadata")
            result.append(step)
        return result

    def check_lease(self):
        current = private(self.root, True)
        state = private(self.state, True)
        held, actual = os.fstat(self.lease), private(self.state / "lease")
        if (current.st_dev, current.st_ino) != self.root_identity or (state.st_dev, state.st_ino) != self.state_identity or (held.st_dev, held.st_ino) != (actual.st_dev, actual.st_ino):
            raise InstallationError("installation state or lease identity changed")

    def snapshot(self, paths):
        result = {}
        for relative in paths:
            path = self.root / relative
            if path.is_symlink():
                raise InstallationError("provisioning state cannot contain aliases")
            if path.is_dir():
                private(path, True)
                children = sorted(path.rglob("*"))
            else:
                children = [path]
            for child in children:
                if child.is_symlink():
                    raise InstallationError("provisioning state cannot contain aliases")
                if child.is_dir():
                    private(child, True)
                else:
                    result[str(child.relative_to(self.root))] = hashlib.sha256(read_file(child, 4 << 20, allow_empty=True)).hexdigest()
        return result

    def step(self, name, paths=(), metadata=None):
        self.check_lease()
        path = self.state / (str(STEPS.index(name) + 1) + "-" + name + ".json")
        if name in self.steps:
            value = read_record(path)
            if value["files"] != self.snapshot(value["paths"]):
                raise InstallationError("completed provisioning material was changed or removed")
            return value["metadata"]
        if STEPS[len(self.steps)] != name:
            raise InstallationError("installation attempted to skip a required step")
        write_record(path, {"step": name, "review_sha256": self.review, "paths": list(paths), "files": self.snapshot(paths), "metadata": metadata})
        self.steps.append(name)
        if self.after_step:
            self.after_step(name)
        return metadata

    def retain(self, path, data):
        self.check_lease()
        if path.exists() or path.is_symlink():
            if read_file(path, 4 << 20) != data:
                raise InstallationError("retained installation metadata differs from its reviewed value")
            return
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        maintenance.sync_directory(path.parent)

    def job(self, name, role, network, mounts, arguments, allow_failure=False):
        self.check_lease()
        container_name = self.project + "-setup-" + name
        specification = {"image": self.images[role], "network": network, "mounts": mounts, "arguments": arguments, "account": self.account}
        signature = digest(specification)
        identities = self.docker.run("retained setup job lookup", "ps", "--all", "--quiet", "--filter", "name=^/" + container_name + "$").split()
        if len(identities) > 1:
            raise InstallationError("setup job identity is ambiguous")
        if identities:
            current = self.docker.objects("retained setup job inspection", "inspect", identities[0])[0]
            labels = current["Config"].get("Labels") or {}
            if labels.get(PROJECT_LABEL) != self.project or labels.get(REVIEW_LABEL) != self.review or labels.get(JOB_LABEL) != signature or current["Image"] != self.images[role] or current["Config"].get("User") != self.account or current["Config"].get("Entrypoint") != [EXECUTABLES[role]] or current["Config"].get("Cmd") != arguments:
                raise InstallationError("retained setup job does not match the reviewed operation")
            policy = current["HostConfig"]
            expected_mounts = {item.split("destination=", 1)[1].split(",", 1)[0]: (item.split("source=", 1)[1].split(",", 1)[0], ",readonly" not in item) for item in mounts[1::2]}
            if maintenance.Maintenance.environment(current["Config"].get("Env")) != maintenance.Maintenance.environment(self.image_configs[role].get("Env")):
                raise InstallationError("retained setup job environment differs from its reviewed image")
            if not policy["ReadonlyRootfs"] or policy.get("Privileged") or policy.get("CapAdd") or policy.get("Devices") or policy.get("DeviceRequests") or policy.get("PidMode") or policy.get("IpcMode") not in ("private", "") or policy.get("PortBindings") or policy.get("CapDrop") != ["ALL"] or not set(policy.get("SecurityOpt", [])) & {"no-new-privileges", "no-new-privileges:true"} or policy.get("Memory") != 512 << 20 or policy.get("PidsLimit") != 128 or policy.get("Tmpfs") or policy.get("NetworkMode") != network or set(current["NetworkSettings"]["Networks"]) != {network} or any(item["Type"] != "bind" for item in current["Mounts"]) or {item["Destination"]: (item["Source"], item["RW"]) for item in current["Mounts"]} != expected_mounts:
                raise InstallationError("retained setup job isolation changed")
            identity = current["Id"]
            if not current["State"]["Running"] and current["State"]["Status"] != "created" and current["State"]["ExitCode"] != 0:
                # The former process is terminal. Only this exact owned failed
                # job is removed; its protected output/journal remains in place.
                self.docker.run("terminal setup job removal", "rm", identity)
                identity = None
        else:
            identity = None
        if identity is None:
            identity = self.docker.run("setup job creation", "create", "--name", container_name, "--network", network,
                "--label", PROJECT_LABEL + "=" + self.project, "--label", REVIEW_LABEL + "=" + self.review,
                "--label", JOB_LABEL + "=" + signature, "--user", self.account, "--read-only", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges", "--pids-limit", "128", "--memory", "512m", *mounts,
                self.images[role], *arguments).strip()
        current = self.docker.objects("setup process state", "inspect", identity)[0]
        if current["State"]["Status"] == "created":
            self.docker.run("setup process startup", "start", identity)
        # A controller interruption can leave its Docker job alive. Always join
        # that actual process; never infer completion from a journal or timeout.
        code = self.docker.run("setup process completion", "wait", identity, timeout=150).strip()
        output = self.docker.run("setup process result", "logs", identity)
        if code != "0":
            if allow_failure and output.strip() == "reference service did not become ready before the probe deadline":
                self.docker.run("completed readiness job removal", "rm", identity)
                return None
            raise InstallationError("setup job failed; its owned process and protected state were retained")
        self.docker.run("completed setup job removal", "rm", identity)
        # These PKI commands deliberately report readiness without a JSON
        # result. Their retained artifacts are checked by the following step.
        return None if role == "pki" else decode(output)

    def runtime_model(self, installation, bootstrap):
        environment = {**self.docker.environment, "OPENUEM_REFERENCE_STATE": str(self.root),
            "OPENUEM_RUNTIME_UID": str(os.geteuid()), "OPENUEM_RUNTIME_GID": str(os.getegid()),
            "OPENUEM_INSTALLATION_ID": installation, "OPENUEM_BOOTSTRAP_ADMIN": self.config["administrator"],
            "OPENUEM_DOMAIN": self.config["domain"], "OPENUEM_ORGANIZATION": self.config["organization"],
            "OPENUEM_PUBLIC_HOST": urllib.parse.urlsplit(self.config["public_origin"]).hostname,
            "OPENUEM_PUBLIC_ORIGIN": self.config["public_origin"], "OPENUEM_ADMIN_NETWORKS": ",".join(self.config["administrator_networks"])}
        for role in maintenance.CLIENTS + ("broker",):
            environment["OPENUEM_" + role.upper() + "_IMAGE"] = self.images[role]
        for name, data in self.sources.items():
            self.retain(self.state / ("source-" + name), data)
        files = ["--file", str(self.state / "source-compose.yaml")]
        if bootstrap:
            files += ["--file", str(self.state / "source-compose.bootstrap.yaml")]
        labels = {REVIEW_LABEL: self.review}
        override = {"services": {role: {"labels": labels} for role in maintenance.ROLES},
                    "networks": {name: {"labels": labels} for name in ("data", "messaging", "console_backend", "broker_backend", "edge", "egress")}}
        if self.config["access"] == "isolated":
            override["networks"]["edge"]["internal"] = True
            override["networks"]["egress"]["internal"] = True
        else:
            override["services"]["gateway"]["ports"] = [{"target": 8443, "published": "443", "protocol": "tcp"}]
        result = subprocess.run(["docker", *self.base, "--env-file", "/dev/null", *files, "--file", "-", "config", "--format", "json"], input=encoded(override).decode(), env=environment, capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise InstallationError("reviewed reference configuration could not be rendered")
        model = maintenance.compose_model(decode(result.stdout))
        model = {name: value for name, value in model.items() if not name.startswith("x-")}
        if set(model.get("services", {})) != maintenance.ROLES or model.get("name") != self.project:
            raise InstallationError("rendered reference services differ from the installation definition")
        for role, service in model["services"].items():
            service["image"] = self.images[role]
        return model

    def runtime(self, bootstrap):
        name = "compose-bootstrap" if bootstrap else "compose-steady"
        source = self.state / (name + ".wire.json")
        arguments = argparse.Namespace(project_name=self.project, project_directory=str(self.root), file=[str(source)], env_file="/dev/null",
                                       setup_image=self.images["pki"], probe_image=self.images["probe"])
        operation = maintenance.Maintenance(arguments, docker=self.docker)
        if operation.definition != read_record(self.state / (name + ".json")):
            raise InstallationError("actual reference runtime differs from its retained definition")
        for value in operation.roles.values():
            if (value["Config"].get("Labels") or {}).get(REVIEW_LABEL) != self.review:
                raise InstallationError("reference service does not belong to this installation review")
        return operation

    def validate_resources(self, model, incomplete=False):
        """Inspect existing owned resources before creating or starting anything."""
        identities = self.docker.run("existing installation containers", "ps", "--all", "--quiet", "--filter", "label=com.docker.compose.project=" + self.project).split()
        roles = {}
        values = self.docker.objects("existing installation boundaries", "inspect", *identities) if identities else []
        for actual in values:
            config, host = actual["Config"], actual["HostConfig"]
            labels = config.get("Labels") or {}
            role = labels.get("com.docker.compose.service")
            if role not in maintenance.ROLES or role in roles or labels.get(REVIEW_LABEL) != self.review or labels.get("com.docker.compose.oneoff", "false").lower() != "false":
                raise InstallationError("existing containers are not exclusive to this installation review")
            service, image = model["services"][role], self.image_configs[role]
            entrypoint, arguments = maintenance.Maintenance.invocation(service, image)
            environment = {**maintenance.Maintenance.environment(image.get("Env")), **service.get("environment", {})}
            if actual["Image"] != self.images[role] or config.get("User") != self.account or (config.get("Entrypoint") or []) != entrypoint or (config.get("Cmd") or []) != arguments or maintenance.Maintenance.environment(config.get("Env")) != environment:
                raise InstallationError("existing service configuration differs from the reviewed installation")
            if not host.get("ReadonlyRootfs") or host.get("Privileged") or host.get("CapAdd") or host.get("Devices") or host.get("DeviceRequests") or host.get("PidMode") or host.get("IpcMode") not in ("private", "") or host.get("CapDrop") != ["ALL"] or not set(host.get("SecurityOpt", [])) & {"no-new-privileges", "no-new-privileges:true"}:
                raise InstallationError("existing service privileges differ from the reviewed installation")
            expected = {item["target"]: (item["source"], not item.get("read_only", False)) for item in service.get("volumes", [])}
            observed = {item["Destination"]: (item["Source"], item["RW"]) for item in actual["Mounts"] if item["Type"] == "bind"}
            if len(observed) != len(actual["Mounts"]) or observed != expected or set(actual["NetworkSettings"]["Networks"]) != {self.project + "_" + name for name in service["networks"]}:
                raise InstallationError("existing service storage or network membership changed")
            ports = service.get("ports", [])
            bindings = host.get("PortBindings") or {}
            if not ports and bindings or ports and (set(bindings) != {"8443/tcp"} or any(item["HostPort"] != "443" for item in bindings["8443/tcp"])):
                raise InstallationError("existing service publication differs from the review")
            roles[role] = actual
        if not incomplete and set(roles) != maintenance.ROLES:
            raise InstallationError("a retained reference service container is missing")
        networks = self.docker.run("existing installation networks", "network", "ls", "--quiet", "--filter", "label=com.docker.compose.project=" + self.project).split()
        for network in self.docker.objects("existing network boundaries", "network", "inspect", *networks) if networks else []:
            logical = network["Name"][len(self.project) + 1:]
            if logical not in model["networks"] or network["Name"] != model["networks"][logical]["name"] or (network.get("Labels") or {}).get(REVIEW_LABEL) != self.review or bool(network["Internal"]) != bool(model["networks"][logical].get("internal")):
                raise InstallationError("existing network ownership or isolation differs from the review")
        for role, directory in (("database", "database"), ("broker", "jetstream"), ("console", "console-logs")):
            if role not in roles and any((self.root / directory).iterdir()) and not (role == "console" and "bootstrap-stopped" in self.steps):
                raise InstallationError("occupied runtime storage has no reviewed owning container")
        return roles

    def administrator_ready(self, installation):
        files = {"credentials/state/database.url": "/run/database.url", "pki/state/trust/backend-ca.pem": "/run/database-ca.pem",
                 "installation/state/initial-password": "/run/initial-password", "installation/state/jwt.key": "/run/jwt.key",
                 "installation/state/encryption.key": "/run/encryption.key"}
        inputs = [argument for source, target in files.items() for argument in mount(self.root / source, target)]
        result = self.job("administrator", "probe", self.project + "_data", inputs,
            ["--mode", "administrator", "--database-url-file", "/run/database.url", "--installation-id", installation,
             "--administrator", self.config["administrator"], "--initial-password-file", "/run/initial-password",
             "--jwt-file", "/run/jwt.key", "--master-file", "/run/encryption.key", "--timeout", "2s"], allow_failure=True)
        return result == {"ready": True}

    def gateway_ready(self, runtime):
        runtime.inspect()
        endpoint = runtime.roles["gateway"]["NetworkSettings"]["Networks"][self.project + "_edge"]["IPAddress"]
        if self.job("gateway", "probe", self.project + "_edge", mount(self.root / "public/server.pem", "/gateway.pem"),
            ["--mode", "gateway", "--address", endpoint + ":8443", "--origin", self.config["public_origin"], "--trust-file", "/gateway.pem", "--timeout", "1m"]) != {"ready": True}:
            raise InstallationError("gateway readiness was not established")

    def database_ready(self, model):
        identities = self.docker.compose(self.base, model, "ps", "--all", "--quiet", "database").split()
        if len(identities) != 1:
            raise InstallationError("reference database container is missing or ambiguous")
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            self.check_lease()
            current = self.docker.objects("database readiness", "inspect", identities[0])[0]
            if not current["State"]["Running"]:
                raise InstallationError("reference database exited before becoming ready")
            if current["State"].get("Health", {}).get("Status") == "healthy":
                return
            time.sleep(.1)
        raise InstallationError("reference database did not become healthy")

    def apply(self, expected):
        if expected != self.review:
            raise InstallationError("installation review does not match these inputs and local images")
        if "complete" in self.steps:
            return {"status": "already-complete", "review_sha256": self.review, "public_origin": self.config["public_origin"]}
        ensure_directory(self.state)
        state = private(self.state, True)
        self.state_identity = (state.st_dev, state.st_ino)
        descriptor = os.open(self.state / "lease", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        self.lease = descriptor
        awaiting = False
        active = False
        try:
            private(self.state / "lease")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise InstallationError("another installation controller is still active") from None
            self.check_lease()
            recorded = read_record(self.state / "review.json")
            if recorded is None:
                write_record(self.state / "review.json", self.record)
            elif recorded != self.record:
                raise InstallationError("installation review changed before the operation acquired its lease")
            active = True
            self.steps = self.read_steps()
            # Check every previously committed artifact before a setup command
            # is allowed to run again. Missing committed files are never repaired.
            for name in self.steps:
                self.step(name)
            for directory in DIRECTORIES:
                ensure_directory(self.root / directory)
            if "inputs" not in self.steps:
                for name, data in self.inputs.items():
                    self.retain(self.root / name, data)
                self.retain(self.root / "pg_hba.conf", b"local all all trust\nhostssl all all all scram-sha-256\nhostnossl all all all reject\n")
                self.step("inputs", ("public", "release-keys.pem", "pg_hba.conf"))
            if "installation" not in self.steps:
                public = self.job("installation", "installation", "none", mount(self.root / "installation", "/work", True), ["--directory", "/work/state"])
                if not isinstance(public, dict) or set(public) != {"installation"} or not re.fullmatch(r"[0-9a-f]{32}", public.get("installation", "")):
                    raise InstallationError("installation generator did not return its public identity")
                self.step("installation", ("installation/state",), public)
            installation = self.step("installation")["installation"]
            if "protocol" not in self.steps:
                public = self.job("protocol", "protocol", "none", [*mount(self.root / "protocol", "/work", True), *mount(self.root / "installation/state", "/installation")],
                                  ["--directory", "/work/state", "--installation", "/installation"])
                if public != {"installation": installation}:
                    raise InstallationError("protocol keys do not match the installation identity")
                self.step("protocol", ("protocol/state",))
            if "credentials" not in self.steps:
                metadata = {"version": 1, "installation": installation, "host": "database.internal", "port": 5432,
                            "database": "openuem", "user": "console", "trust_file": "/run/database-ca.pem"}
                self.retain(self.root / "database.json", encoded(metadata))
                self.job("credentials", "credentials", "none", [*mount(self.root / "credentials", "/work", True), *mount(self.root / "database.json", "/config.json")],
                         ["--config", "/config.json", "--directory", "/work/state"])
                self.step("credentials", ("credentials/state", "database.json"))
            if "pki" not in self.steps:
                self.job("pki", "pki", "none", mount(self.root / "pki", "/work", True),
                    ["private-pki", "--directory", "/work/state", "--name", self.project, "--console-dns", "console.internal",
                     "--broker-dns", "broker.internal", "--database-dns", "database.internal", "--administrator-authority"])
                self.step("pki", ("pki/state",))
            if "broker" not in self.steps:
                self.job("broker", "pki", "none", mount(self.root / "broker", "/work", True),
                    ["individual-broker", "--directory", "/work/state", "--name", self.project, "--listen", "0.0.0.0:4222",
                     "--websocket-listen", "0.0.0.0:9222", "--tls-cert", "/run/broker-tls/server.pem", "--tls-key", "/run/broker-tls/server.key",
                     "--gateway-ca", "/run/broker-tls/gateway-leaves.pem", "--store-directory", "/var/lib/openuem/jetstream"])
                self.step("broker", ("broker/state",))
            if "configuration" not in self.steps:
                for kind, bootstrap in (("bootstrap", True), ("steady", False)):
                    model = self.runtime_model(installation, bootstrap)
                    self.retain(self.state / ("compose-" + kind + ".json"), encoded(model))
                    self.retain(self.state / ("compose-" + kind + ".wire.json"), encoded(model).decode().replace("$", "$$").encode())
                self.step("configuration", (".setup/compose-bootstrap.json", ".setup/compose-steady.json",
                    ".setup/compose-bootstrap.wire.json", ".setup/compose-steady.wire.json", ".setup/source-compose.yaml", ".setup/source-compose.bootstrap.yaml"))
            bootstrap_model = read_record(self.state / "compose-bootstrap.json")
            steady_model = read_record(self.state / "compose-steady.json")
            if "database" not in self.steps:
                # All runtime containers are created with their explicit reviewed
                # image IDs before any listener starts. Compose cannot pull/build.
                self.validate_resources(bootstrap_model, incomplete=True)
                self.docker.compose(self.base, bootstrap_model, "create", "--no-build")
                self.validate_resources(bootstrap_model)
                self.docker.compose(self.base, bootstrap_model, "start", "database")
                self.database_ready(bootstrap_model)
                self.runtime(True)
                self.step("database")
            else:
                bootstrap = "bootstrap-retired" not in self.steps
                if bootstrap and "bootstrap-stopped" in self.steps:
                    original = self.step("administrator")["console"]
                    current = self.docker.compose(self.base, steady_model, "ps", "--all", "--quiet", "console").split()
                    bootstrap = current == [original]
                    if not current:
                        self.validate_resources(steady_model, incomplete=True)
                        self.docker.compose(self.base, steady_model, "up", "--detach", "--no-deps", "--force-recreate", "console")
                model = bootstrap_model if bootstrap else steady_model
                roles = self.validate_resources(model)
                if not roles["database"]["State"]["Running"]:
                    self.docker.run("retained database startup", "start", roles["database"]["Id"])
                self.database_ready(model)
            if "bootstrap" not in self.steps:
                self.job("bootstrap", "bootstrap", self.project + "_data", [*mount(self.root / "database.json", "/config.json"),
                    *mount(self.root / "credentials/state", "/credentials"), *mount(self.root / "pki/state/trust/backend-ca.pem", "/run/database-ca.pem"),
                    *mount(self.root / "journal", "/work", True)], ["--config", "/config.json", "--credentials", "/credentials", "--state", "/work/state"])
                self.step("bootstrap", ("journal/state",))
            if "bootstrap-stopped" not in self.steps:
                runtime = self.runtime(True)
                runtime.start("broker")
                runtime.broker_ready()
                runtime.start("console")
                runtime.start("gateway")
                self.gateway_ready(runtime)
                for role in ("authorization", "commands", "worker"):
                    runtime.start(role)
                runtime.services_ready()
                if "runtime" not in self.steps:
                    self.step("runtime")
            if "bootstrap-retired" not in self.steps:
                if not self.administrator_ready(installation):
                    awaiting = True
                    return {"status": "awaiting-administrator", "review_sha256": self.review, "public_origin": self.config["public_origin"],
                            "administrator": self.config["administrator"], "initial_password_file": str(self.root / "installation/state/initial-password")}
                if "administrator" not in self.steps:
                    runtime = self.runtime(True)
                    self.step("administrator", metadata={"console": runtime.roles["console"]["Id"]})
                if "bootstrap-stopped" not in self.steps:
                    runtime = self.runtime(True)
                    runtime.stop(("gateway", "console"))
                    self.step("bootstrap-stopped")
                original = self.step("administrator")["console"]
                identities = self.docker.compose(self.base, steady_model, "ps", "--all", "--quiet", "console").split()
                if identities == [original]:
                    self.docker.compose(self.base, steady_model, "up", "--detach", "--no-deps", "--force-recreate", "console")
                runtime = self.runtime(False)
                if runtime.roles["console"]["Id"] == original:
                    raise InstallationError("bootstrap console recreation did not retire the initial-password mount")
                self.step("bootstrap-retired")
            runtime = self.runtime(False)
            runtime.start("console")
            runtime.services_ready()
            self.step("complete")
            return {"status": "complete", "review_sha256": self.review, "public_origin": self.config["public_origin"], "ready": True}
        finally:
            if active and not awaiting and "complete" not in self.steps:
                # Keep the public entry point closed after an unexpected failure.
                # An interrupted setup job is retained for explicit process join.
                with contextlib.suppress(Exception):
                    identities = self.docker.run("owned gateway lookup", "ps", "--quiet", "--filter", "label=com.docker.compose.project=" + self.project,
                        "--filter", "label=com.docker.compose.service=gateway", "--filter", "label=" + REVIEW_LABEL + "=" + self.review).split()
                    for identity in identities:
                        self.docker.run("failed installation gateway shutdown", "stop", "--time", "20", identity)
            os.close(descriptor)
            self.lease = None


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise InstallationError("reference installation arguments are invalid")


def main(values=None):
    try:
        parser = Parser(description=__doc__)
        parser.add_argument("--config", required=True, help="Protected absolute installation configuration file")
        parser.add_argument("--expected-review", help="Exact digest from the read-only installation review")
        modes = parser.add_mutually_exclusive_group(required=True)
        modes.add_argument("--check", action="store_true", help="Read-only inspection of inputs, images and retained progress")
        modes.add_argument("--apply", action="store_true", help="Initialize or resume the exact reviewed installation")
        args = parser.parse_args(values)
        if args.check and args.expected_review or args.apply and not re.fullmatch(r"[0-9a-f]{64}", args.expected_review or ""):
            raise InstallationError("installation requires an unambiguous review or exact reviewed apply")
        operation = Installation(profile(args.config))
        result = operation.public_plan() if args.check else operation.apply(args.expected_review)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (InstallationError, maintenance.MaintenanceError) as error:
        print(str(error), file=sys.stderr)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        print("reference installation failed; existing protected state and owned jobs were retained", file=sys.stderr)
    return 1


if __name__ == "__main__":
    def interrupted(_signal, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("reference installation interrupted; resume the same reviewed configuration", file=sys.stderr)
        sys.exit(130)

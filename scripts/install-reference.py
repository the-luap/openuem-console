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
import uuid


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
ISSUER_EXECUTABLE = "/openuem-acme"


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
    if isinstance(value, dict) and type(value.get("version")) is int and value["version"] == 2:
        required = required - {"tls_certificate", "tls_key"} | {"public_tls"}
    if not isinstance(value, dict) or set(value) != required or type(value["version"]) is not int or value["version"] not in (1, 2):
        raise InstallationError("installation configuration must contain the exact fields for its supported version")
    if not all(isinstance(value[name], str) for name in required - {"version", "images", "administrator_networks", "public_tls"}):
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
    if value["version"] == 2:
        issuer = value["public_tls"]
        if not isinstance(issuer, dict) or set(issuer) != {"configuration", "image"} or not all(isinstance(item, str) for item in issuer.values()) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./:@-]{0,511}", issuer["image"]):
            raise InstallationError("automatic public TLS requires an explicit issuer image and protected configuration directory")
        directory = pathlib.Path(issuer["configuration"])
        if not directory.is_absolute() or directory == directory.parent or str(directory) != str(directory.resolve()) or "," in str(directory) or directory == root or root in directory.parents:
            raise InstallationError("issuer configuration must be a canonical private directory outside installation state")
    return value


def issuer_inputs(config):
    """Read only the exact provider inputs needed by the fixed issuer mounts."""
    directory = pathlib.Path(config["public_tls"]["configuration"])
    private(directory, True)
    issuer_data = read_file(directory / "issuer.json", 64 << 10)
    issuer = decode(issuer_data)
    origin = "https://" + urllib.parse.urlsplit(config["public_origin"]).hostname
    expected = {"public_origin": origin, "provider_environment_file": "/run/openuem-acme/provider.json",
                "state_directory": "/var/lib/openuem-acme", "publication_directory": "/var/lib/openuem-public-tls"}
    if not isinstance(issuer, dict) or any(issuer.get(name) != value for name, value in expected.items()):
        raise InstallationError("issuer configuration does not match the reviewed origin and fixed private mounts")
    provider_data = read_file(directory / "provider.json", 64 << 10)
    provider = decode(provider_data)
    if not isinstance(provider, dict) or not 1 <= len(provider) <= 128 or not all(isinstance(value, str) for value in provider.values()):
        raise InstallationError("issuer provider inputs must be a bounded explicit environment")
    files = {"issuer.json": issuer_data, "provider.json": provider_data}

    def referenced(path, public=False):
        prefix = "/run/openuem-acme/"
        name = path.removeprefix(prefix) if isinstance(path, str) else ""
        if not isinstance(path, str) or path != prefix + name or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", name) or name in ("issuer.json", "provider.json"):
            raise InstallationError("issuer file inputs must name separate files within the protected configuration mount")
        data = read_file(directory / name, 1 << 20 if public else 64 << 10, secret=not public)
        if name in files and files[name] != data:
            raise InstallationError("issuer file inputs changed while reading")
        files[name] = data

    for name, value in provider.items():
        if name.endswith("_FILE"):
            referenced(value)
    if issuer.get("acme_roots_file"):
        referenced(issuer["acme_roots_file"], public=True)
    if set(path.name for path in directory.iterdir()) != set(files):
        raise InstallationError("issuer configuration directory contains unreferenced files or directories")
    return {"acme/config/" + name: data for name, data in files.items()}, issuer


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
    sequence = STEPS

    def __init__(self, config, docker=None, after_step=None):
        if os.name != "posix" or os.geteuid() == 0 or os.getegid() == 0:
            raise InstallationError("reference installation requires a non-root POSIX account")
        self.config = config
        self.acme = config["version"] == 2
        self.sequence = ("inputs", "public-tls", *STEPS[1:]) if self.acme else STEPS
        self.issuer_config = None
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
        self.issuer_project = self.project + "-public-tls"
        self.issuer_base = ["compose", "--project-name", self.issuer_project, "--project-directory", str(self.root)]
        if self.state.exists() or self.state.is_symlink():
            private(self.state, True)
            self.record = read_record(self.state / "review.json")
            self.steps = self.read_steps() if self.record else []
            if not self.record and set(path.name for path in self.state.iterdir()) - {"lease"}:
                raise InstallationError("retained installation review is missing")
        elif any(self.root.iterdir()):
            raise InstallationError("fresh installation requires an empty private directory")
        references = {**config["images"], "database": DATABASE_IMAGE}
        if self.acme:
            references["acme"] = config["public_tls"]["image"]
        for role, reference in references.items():
            image = self.docker.objects("local installation image", "image", "inspect", reference)[0]
            executable = ISSUER_EXECUTABLE if role == "acme" else EXECUTABLES.get(role)
            if image.get("Os") != "linux" or not re.fullmatch(r"sha256:[0-9a-f]{64}", image.get("Id", "")) or role != "database" and image["Config"].get("Entrypoint") != [executable]:
                raise InstallationError("a local image does not match its selected reference role")
            self.images[role] = image["Id"]
            self.image_configs[role] = image["Config"]
        sources = ("compose.yaml", "compose.bootstrap.yaml", "compose.acme.yaml", "compose.issuer.yaml") if self.acme else ("compose.yaml", "compose.bootstrap.yaml")
        self.sources = {name: read_file(REPOSITORY / "deploy/reference" / name, secret=False) for name in sources}
        binding = {"version": 1, "configuration": config, "account": self.account, "daemon": self.docker.identity,
                   "root_identity": list(self.root_identity), "images": self.images,
                   "templates": {name: hashlib.sha256(data).hexdigest() for name, data in self.sources.items()}}
        if self.record and "complete" in self.steps:
            if self.record["binding"] != binding:
                raise InstallationError("completed installation review does not match this configuration")
            self.review = self.record["review_sha256"]
            self.inputs = None
            return
        self.inputs = {"release-keys.pem": read_file(config["release_keys"], 64 << 10, False)}
        names = ("release_keys",) if self.acme else ("tls_certificate", "tls_key", "release_keys")
        if any(self.root == pathlib.Path(config[name]) or self.root in pathlib.Path(config[name]).parents for name in names):
            raise InstallationError("external installation inputs must remain outside the fresh state directory")
        if self.acme:
            inputs, self.issuer_config = issuer_inputs(config)
            self.inputs.update(inputs)
            self.check_issuer_inputs()
            repeated, repeated_config = issuer_inputs(config)
            if repeated != inputs or repeated_config != self.issuer_config or self.inputs["release-keys.pem"] != read_file(config["release_keys"], 64 << 10, False):
                raise InstallationError("issuer inputs changed during read-only verification")
            tls_fingerprint = None
        else:
            self.inputs.update({"public/server.pem": read_file(config["tls_certificate"], 64 << 10, False),
                                "public/server.key": read_file(config["tls_key"], 64 << 10)})
            tls_fingerprint = public_tls(config["tls_certificate"], config["tls_key"], urllib.parse.urlsplit(config["public_origin"]).hostname)
            if self.inputs != {"public/server.pem": read_file(config["tls_certificate"], 64 << 10, False),
                               "public/server.key": read_file(config["tls_key"], 64 << 10),
                               "release-keys.pem": read_file(config["release_keys"], 64 << 10, False)}:
                raise InstallationError("installation inputs changed during TLS verification")
        keys = release_keys(self.inputs["release-keys.pem"])
        input_hashes = {name: hashlib.sha256(data).hexdigest() for name, data in self.inputs.items()}
        self.review = digest({"binding": binding, "inputs": input_hashes})
        proposed = {"binding": binding, "inputs": input_hashes, "public_tls_sha256": tls_fingerprint, "release_keys": keys, "review_sha256": self.review}
        if self.acme:
            proposed["public_tls"] = {"mode": "dns-01", "acme_directory_url": self.issuer_config["acme_directory_url"], "dns_provider": self.issuer_config["dns_provider"]}
        if self.record is not None and self.record != proposed:
            raise InstallationError("retained installation differs from the reviewed inputs or images")
        self.record = proposed
        if not self.state.exists():
            for project in (self.project, self.issuer_project) if self.acme else (self.project,):
                for label in ("com.docker.compose.project", PROJECT_LABEL):
                    if self.docker.run("fresh project reservation", "ps", "--all", "--quiet", "--filter", "label=" + label + "=" + project).strip():
                        raise InstallationError("installation project already has containers")
                if self.docker.run("fresh network reservation", "network", "ls", "--quiet", "--filter", "label=com.docker.compose.project=" + project).strip():
                    raise InstallationError("installation project already has networks")

    def check_issuer_inputs(self):
        name = "openuem-issuer-inputs-" + uuid.uuid4().hex[:16]
        try:
            output = self.docker.run("read-only issuer input verification", "run", "--rm", "--name", name, "--network", "none",
                "--user", self.account, "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--pids-limit", "32", "--memory", "128m", *mount(self.config["public_tls"]["configuration"], "/run/openuem-acme"),
                self.images["acme"], "--config", "/run/openuem-acme/issuer.json", "--check")
            if decode(output) != {"inputs_valid": True}:
                raise InstallationError("issuer image did not positively verify the protected inputs")
        finally:
            # This bounded checker has no writable mounts or network. It is
            # separate from retained provisioning jobs, which must be joined.
            with contextlib.suppress(Exception):
                self.docker.run("owned read-only input checker cleanup", "rm", "--force", name, check=False)

    def public_plan(self):
        result = {"status": "complete" if "complete" in self.steps else "awaiting-administrator" if "runtime" in self.steps else "ready-to-resume" if self.steps else "ready-to-initialize",
                "review_sha256": self.review, "project": self.project, "directory": str(self.root),
                "public_origin": self.config["public_origin"], "published_tcp_ports": [443] if self.config["access"] == "public" else [],
                "administrator_networks": self.config["administrator_networks"], "images": self.images,
                "public_tls_sha256": self.record["public_tls_sha256"], "release_keys": self.record["release_keys"], "steps": self.steps}
        if self.acme:
            result["public_tls"] = self.record["public_tls"]
            if "public-tls" in self.steps:
                result["public_tls_sha256"] = read_record(self.state / "2-public-tls.json")["metadata"]["certificate_sha256"]
        return result

    def read_steps(self):
        result = []
        allowed = {"lease", "review.json", "source-compose.yaml", "source-compose.bootstrap.yaml",
                   "compose-bootstrap.json", "compose-bootstrap.wire.json", "compose-steady.json", "compose-steady.wire.json"}
        if getattr(self, "acme", False):
            allowed |= {"source-compose.acme.yaml", "source-compose.issuer.yaml", "compose-issuer.json", "compose-issuer.wire.json"}
        allowed |= {str(index) + "-" + step + ".json" for index, step in enumerate(self.sequence, 1)}
        if set(path.name for path in self.state.iterdir()) - allowed:
            raise InstallationError("retained installation journal contains unexpected entries")
        def relative(value):
            return isinstance(value, str) and value not in ("", ".") and not pathlib.Path(value).is_absolute() and ".." not in pathlib.Path(value).parts and str(pathlib.Path(value)) == value
        for index, step in enumerate(self.sequence, 1):
            path = self.state / (str(index) + "-" + step + ".json")
            value = read_record(path)
            if value is None:
                continue
            if not isinstance(value, dict) or set(value) != {"step", "review_sha256", "paths", "files", "metadata"} or len(result) != index - 1 or value.get("step") != step or value.get("review_sha256") != self.record["review_sha256"]:
                raise InstallationError("retained installation steps are incomplete or inconsistent")
            if not isinstance(value["paths"], list) or len(value["paths"]) > 64 or not all(relative(path) for path in value["paths"]) or not isinstance(value["files"], dict) or len(value["files"]) > 2048 or not all(relative(path) and isinstance(checksum, str) and re.fullmatch(r"[0-9a-f]{64}", checksum) for path, checksum in value["files"].items()):
                raise InstallationError("retained installation artifact inventory is invalid")
            metadata = value["metadata"]
            identities = {"installation": ("installation", 32), "administrator": ("console", 64), "public-tls": ("certificate_sha256", 64)}
            if step in identities:
                field, length = identities[step]
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
        path = self.state / (str(self.sequence.index(name) + 1) + "-" + name + ".json")
        if name in self.steps:
            value = read_record(path)
            if value["files"] != self.snapshot(value["paths"]):
                raise InstallationError("completed provisioning material was changed or removed")
            return value["metadata"]
        if self.sequence[len(self.steps)] != name:
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
        issuer = role == "acme"
        tmpfs = "/tmp:rw,nosuid,nodev,noexec,size=16m,mode=0700,uid=" + str(os.geteuid()) + ",gid=" + str(os.getegid())
        if issuer:
            specification.update({"init": True, "tmpfs": tmpfs})
        executable = ISSUER_EXECUTABLE if issuer else EXECUTABLES[role]
        signature = digest(specification)
        identities = self.docker.run("retained setup job lookup", "ps", "--all", "--quiet", "--filter", "name=^/" + container_name + "$").split()
        if len(identities) > 1:
            raise InstallationError("setup job identity is ambiguous")
        if identities:
            current = self.docker.objects("retained setup job inspection", "inspect", identities[0])[0]
            labels = current["Config"].get("Labels") or {}
            if labels.get(PROJECT_LABEL) != self.project or labels.get(REVIEW_LABEL) != self.review or labels.get(JOB_LABEL) != signature or current["Image"] != self.images[role] or current["Config"].get("User") != self.account or current["Config"].get("Entrypoint") != [executable] or current["Config"].get("Cmd") != arguments:
                raise InstallationError("retained setup job does not match the reviewed operation")
            policy = current["HostConfig"]
            expected_mounts = {item.split("destination=", 1)[1].split(",", 1)[0]: (item.split("source=", 1)[1].split(",", 1)[0], ",readonly" not in item) for item in mounts[1::2]}
            if maintenance.Maintenance.environment(current["Config"].get("Env")) != maintenance.Maintenance.environment(self.image_configs[role].get("Env")):
                raise InstallationError("retained setup job environment differs from its reviewed image")
            expected_tmpfs = {"/tmp": tmpfs.partition(":")[2]} if issuer else {}
            if not policy["ReadonlyRootfs"] or policy.get("Privileged") or policy.get("CapAdd") or policy.get("Devices") or policy.get("DeviceRequests") or policy.get("PidMode") or policy.get("IpcMode") not in ("private", "") or policy.get("PortBindings") or policy.get("CapDrop") != ["ALL"] or not set(policy.get("SecurityOpt", [])) & {"no-new-privileges", "no-new-privileges:true"} or policy.get("Memory") != 512 << 20 or policy.get("PidsLimit") != 128 or bool(policy.get("Init")) != issuer or (policy.get("Tmpfs") or {}) != expected_tmpfs or policy.get("NetworkMode") != network or set(current["NetworkSettings"]["Networks"]) != {network} or any(item["Type"] != "bind" for item in current["Mounts"]) or {item["Destination"]: (item["Source"], item["RW"]) for item in current["Mounts"]} != expected_mounts:
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
                "--security-opt", "no-new-privileges", "--pids-limit", "128", "--memory", "512m", *(["--init", "--tmpfs", tmpfs] if issuer else []), *mounts,
                self.images[role], *arguments).strip()
        current = self.docker.objects("setup process state", "inspect", identity)[0]
        if current["State"]["Status"] == "created":
            self.docker.run("setup process startup", "start", identity)
        # A controller interruption can leave its Docker job alive. Always join
        # that actual process; never infer completion from a journal or timeout.
        code = self.docker.run("setup process completion", "wait", identity, timeout=1900 if issuer else 150).strip()
        output = self.docker.run("setup process result", "logs", identity)
        if code != "0":
            if allow_failure and output.strip() == "reference service did not become ready before the probe deadline":
                self.docker.run("completed readiness job removal", "rm", identity)
                return None
            raise InstallationError("setup job failed; its owned process and protected state were retained")
        self.docker.run("completed setup job removal", "rm", identity)
        # These PKI commands deliberately report readiness without a JSON
        # result. Their retained artifacts are checked by the following step.
        return None if role in ("pki", "acme") else decode(output)

    def issuer_definition(self):
        self.retain(self.state / "source-compose.issuer.yaml", self.sources["compose.issuer.yaml"])
        environment = {**self.docker.environment, "OPENUEM_REFERENCE_STATE": str(self.root),
                       "OPENUEM_RUNTIME_UID": str(os.geteuid()), "OPENUEM_RUNTIME_GID": str(os.getegid()), "OPENUEM_ACME_IMAGE": self.images["acme"]}
        labels = {REVIEW_LABEL: self.review, PROJECT_LABEL: self.project}
        override = {"services": {"acme": {"labels": labels}},
                    "networks": {"public_tls": {"labels": labels, "internal": self.config["access"] == "isolated"}}}
        result = subprocess.run(["docker", *self.issuer_base, "--env-file", "/dev/null", "--file", str(self.state / "source-compose.issuer.yaml"),
                                 "--file", "-", "config", "--format", "json"], input=encoded(override).decode(), env=environment,
                                text=True, capture_output=True, timeout=30)
        if result.returncode:
            raise InstallationError("reviewed issuer configuration could not be rendered")
        model = maintenance.compose_model(decode(result.stdout))
        model = {name: value for name, value in model.items() if not name.startswith("x-")}
        if model.get("name") != self.issuer_project or set(model.get("services", {})) != {"acme"} or set(model.get("networks", {})) != {"public_tls"}:
            raise InstallationError("issuer composition must contain only its dedicated service and network")
        service, network = model["services"]["acme"], model["networks"]["public_tls"]
        forbidden = ("privileged", "cap_add", "devices", "device_cgroup_rules", "network_mode", "pid", "ipc", "volumes_from", "secrets", "configs", "build", "provider", "pre_start", "post_start", "pre_stop", "use_api_socket", "ports")
        expected = {"/run/openuem-acme": (str(self.root / "acme/config"), True),
                    "/var/lib/openuem-acme": (str(self.root / "acme/state"), False), "/var/lib/openuem-public-tls": (str(self.root / "public"), False)}
        mounts = service.get("volumes", [])
        if any(service.get(name) for name in forbidden) or service.get("image") != self.images["acme"] or service.get("user") != self.account or not service.get("read_only") or not service.get("init") or service.get("cap_drop") != ["ALL"] or "no-new-privileges:true" not in service.get("security_opt", []) or service.get("pull_policy") != "never" or set(service.get("networks", {})) != {"public_tls"}:
            raise InstallationError("issuer service does not retain its reviewed privilege and network boundaries")
        if service.get("command") != ["--config", "/run/openuem-acme/issuer.json"] or service.get("entrypoint") is not None or service.get("environment") or str(service.get("mem_limit")) != str(128 << 20) or service.get("pids_limit") != 64 or service.get("restart") != "unless-stopped" or service.get("stop_grace_period") != "15s":
            raise InstallationError("issuer command, environment or resource limits changed")
        if len(mounts) != 3 or any(item.get("type") != "bind" or item.get("bind", {}).get("create_host_path") for item in mounts) or {item["target"]: (item["source"], bool(item.get("read_only"))) for item in mounts} != expected:
            raise InstallationError("issuer account, provider and publication mounts changed")
        if network.get("name") != self.issuer_project + "_public_tls" or network.get("external") or network.get("driver", "bridge") != "bridge" or bool(network.get("internal")) != (self.config["access"] == "isolated"):
            raise InstallationError("issuer network ownership or isolation changed")
        if any(model.get(name) for name in ("volumes", "secrets", "configs", "models")):
            raise InstallationError("issuer composition cannot create additional resources")
        self.retain(self.state / "compose-issuer.json", encoded(model))
        self.retain(self.state / "compose-issuer.wire.json", encoded(model).decode().replace("$", "$$").encode())
        return model

    def issuer_resources(self, model):
        self.check_lease()
        service = model["services"]["acme"]
        network = model["networks"]["public_tls"]
        identities = self.docker.run("retained issuer containers", "ps", "--all", "--quiet", "--filter", "label=com.docker.compose.project=" + self.issuer_project).split()
        if len(identities) > 1:
            raise InstallationError("issuer service identity is ambiguous")
        current = None
        if identities:
            current = self.docker.objects("retained issuer boundaries", "inspect", identities[0])[0]
            config, host = current["Config"], current["HostConfig"]
            labels = config.get("Labels") or {}
            if labels.get("com.docker.compose.service") != "acme" or labels.get("com.docker.compose.oneoff", "false").lower() != "false" or labels.get(REVIEW_LABEL) != self.review or labels.get(PROJECT_LABEL) != self.project:
                raise InstallationError("existing issuer does not belong to this installation review")
            entrypoint, arguments = maintenance.Maintenance.invocation(service, self.image_configs["acme"])
            if current["Image"] != self.images["acme"] or config.get("User") != self.account or (config.get("Entrypoint") or []) != entrypoint or (config.get("Cmd") or []) != arguments or maintenance.Maintenance.environment(config.get("Env")) != maintenance.Maintenance.environment(self.image_configs["acme"].get("Env")):
                raise InstallationError("existing issuer image, command or environment differs from the review")
            if not host.get("ReadonlyRootfs") or not host.get("Init") or host.get("Privileged") or host.get("CapAdd") or host.get("Devices") or host.get("DeviceRequests") or host.get("PidMode") or host.get("UTSMode") or host.get("UsernsMode") or host.get("IpcMode") not in ("private", "") or host.get("CapDrop") != ["ALL"] or not set(host.get("SecurityOpt", [])) & {"no-new-privileges", "no-new-privileges:true"} or host.get("Memory") != 128 << 20 or host.get("PidsLimit") != 64 or host.get("PortBindings") or host.get("RestartPolicy") != {"Name": "unless-stopped", "MaximumRetryCount": 0} or config.get("StopTimeout") != 15:
                raise InstallationError("existing issuer privileges or resource limits changed")
            expected = {item["target"]: (item["source"], not item.get("read_only", False)) for item in service["volumes"]}
            if len(current["Mounts"]) != len(expected) or any(item["Type"] != "bind" for item in current["Mounts"]) or {item["Destination"]: (item["Source"], item["RW"]) for item in current["Mounts"]} != expected or host.get("NetworkMode") != network["name"] or set(current["NetworkSettings"]["Networks"]) != {network["name"]}:
                raise InstallationError("existing issuer storage or network membership changed")
            expected_tmpfs = {item.partition(":")[0]: item.partition(":")[2] for item in service.get("tmpfs", [])}
            if (host.get("Tmpfs") or {}) != expected_tmpfs:
                raise InstallationError("existing issuer temporary storage changed")
        elif "public-tls" not in self.steps and (any((self.root / "acme/state").iterdir()) or any((self.root / "public").iterdir())):
            raise InstallationError("occupied issuer state has no reviewed owning service")
        found = self.docker.run("issuer network lookup", "network", "ls", "--quiet", "--filter", "name=^" + network["name"] + "$").split()
        if len(found) > 1:
            raise InstallationError("issuer network identity is ambiguous")
        owned = self.docker.run("owned issuer network lookup", "network", "ls", "--quiet", "--filter", "label=com.docker.compose.project=" + self.issuer_project).split()
        if set(owned) != set(found):
            raise InstallationError("issuer project has unexpected or foreign networks")
        if found:
            actual = self.docker.objects("issuer network inspection", "network", "inspect", found[0])[0]
            labels = actual.get("Labels") or {}
            if actual.get("Name") != network["name"] or actual.get("Driver") != "bridge" or labels.get(REVIEW_LABEL) != self.review or labels.get(PROJECT_LABEL) != self.project or labels.get("com.docker.compose.project") != self.issuer_project or labels.get("com.docker.compose.network") != "public_tls" or bool(actual.get("Internal")) != bool(network.get("internal")):
                raise InstallationError("issuer network isolation or review identity changed")
            for expected in network.get("ipam", {}).get("config", []):
                if not any(item.get("Subnet") == expected.get("subnet") for item in actual.get("IPAM", {}).get("Config", [])):
                    raise InstallationError("issuer network address allocation differs from its reviewed definition")
        return current

    def issuer_anchors(self):
        account = decode(read_file(self.root / "acme/state/account-key.json", 8192))
        directory = urllib.parse.urlsplit(self.issuer_config["acme_directory_url"]).netloc
        key_path = "lego/accounts/" + directory.replace(":", "_").replace("/", "_").replace("\\", "_") + "/" + self.issuer_config["email"] + "/" + self.issuer_config["email"] + ".key"
        if not isinstance(account, dict) or set(account) != {"version", "key_path", "sha256"} or type(account["version"]) is not int or account["version"] != 1 or account["key_path"] != key_path or not isinstance(account["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", account["sha256"]):
            raise InstallationError("issuer did not retain the expected original account key binding")
        key = self.root / "acme/state" / key_path
        if hashlib.sha256(read_file(key, 64 << 10)).hexdigest() != account["sha256"]:
            raise InstallationError("issuer original account key changed or is unavailable")
        state = decode(read_file(self.root / "acme/state/installation.json", 8192))
        public = decode(read_file(self.root / "public/installation.json", 8192))
        if not isinstance(state, dict) or state != public or set(state) != {"version", "installation", "origin", "directory", "email", "provider"} or type(state["version"]) is not int or state["version"] != 1:
            raise InstallationError("issuer account and publication are not a retained matching pair")
        installation = uuid.UUID(state["installation"])
        if installation.int == 0 or str(installation) != state["installation"] or state["origin"] != self.issuer_config["public_origin"] or state["directory"] != self.issuer_config["acme_directory_url"] or state["email"] != self.issuer_config["email"] or state["provider"] != self.issuer_config["dns_provider"]:
            raise InstallationError("issuer installation identity does not match the reviewed configuration")
        return ("acme/state/account-key.json", "acme/state/installation.json", "public/installation.json", "acme/state/" + key_path)

    def initialize_public_tls(self):
        model = self.issuer_definition()
        current = self.issuer_resources(model)
        if current is None:
            self.docker.compose(self.issuer_base, model, "create", "--no-build")
            current = self.issuer_resources(model)
        if current is None:
            raise InstallationError("reviewed issuer service was not created")
        if "public-tls" not in self.steps:
            if current["State"]["Running"]:
                self.docker.run("initial issuer shutdown", "stop", "--time", "20", current["Id"])
                stopped = self.docker.objects("initial issuer joined shutdown", "inspect", current["Id"])[0]["State"]
                if stopped["Running"] or stopped["ExitCode"] != 0:
                    raise InstallationError("issuer did not join a successful shutdown before initial issuance")
            self.job("public-tls", "acme", self.issuer_project + "_public_tls",
                [*mount(self.root / "acme/config", "/run/openuem-acme"), *mount(self.root / "acme/state", "/var/lib/openuem-acme", True),
                 *mount(self.root / "public", "/var/lib/openuem-public-tls", True)], ["--config", "/run/openuem-acme/issuer.json", "--once"])
            anchors = self.issuer_anchors()
            certificate = maintenance.gateway_trust(self.root, {"command": ["--tls-cert", "/run/public/current/fullchain.pem", "--tls-key", "/run/public/current/private.pem"]})
            key = certificate.parent / "private.pem"
            read_file(key, 64 << 10)
            fingerprint = public_tls(str(certificate), str(key), urllib.parse.urlsplit(self.config["public_origin"]).hostname)
            self.step("public-tls", (*anchors, ".setup/source-compose.issuer.yaml", ".setup/compose-issuer.json", ".setup/compose-issuer.wire.json"), {"certificate_sha256": fingerprint})
        else:
            self.issuer_anchors()
        current = self.issuer_resources(model)
        if not current["State"]["Running"]:
            self.docker.run("retained issuer startup", "start", current["Id"])
        if not self.docker.objects("issuer startup state", "inspect", current["Id"])[0]["State"]["Running"]:
            raise InstallationError("retained issuer exited before its renewal service started")

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
        if self.acme:
            files += ["--file", str(self.state / "source-compose.acme.yaml")]
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
        certificate = maintenance.gateway_trust(self.root, runtime.definition["services"]["gateway"])
        if self.job("gateway", "probe", self.project + "_edge", mount(certificate, "/gateway.pem"),
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
            if self.acme:
                for directory in ("acme", "acme/config", "acme/state"):
                    ensure_directory(self.root / directory)
            if "inputs" not in self.steps:
                for name, data in self.inputs.items():
                    self.retain(self.root / name, data)
                self.retain(self.root / "pg_hba.conf", b"local all all trust\nhostssl all all all scram-sha-256\nhostnossl all all all reject\n")
                self.step("inputs", ("acme/config" if self.acme else "public", "release-keys.pem", "pg_hba.conf"))
            if self.acme:
                self.initialize_public_tls()
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
                    ".setup/compose-bootstrap.wire.json", ".setup/compose-steady.wire.json", ".setup/source-compose.yaml", ".setup/source-compose.bootstrap.yaml",
                    *((".setup/source-compose.acme.yaml",) if self.acme else ())))
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

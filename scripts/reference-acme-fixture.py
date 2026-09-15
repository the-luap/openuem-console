"""Owned local ACME/DNS server for the production installer acceptance test."""

import ipaddress
import json
import os
import pathlib
import shutil
import time
import uuid


class ACMEFixture:
    def __init__(self, root, repository, project, image, command, cleanup):
        self.command, self.project = command, project
        self.server = project + "-acme-fixture"
        self.network = project + "-acme-fixture"
        self.issuer_network = project + "-public-tls_public_tls"
        self.attached = False
        self.output = root / "acme-fixture"
        self.output.mkdir(mode=0o700)
        self.inputs = root / "issuer-inputs"
        self.inputs.mkdir(mode=0o700)
        self.repository = root / "source"
        (self.repository / "scripts").mkdir(parents=True)
        (self.repository / "deploy/reference").mkdir(parents=True)
        for name in ("install-reference.py", "maintain-reference-broker.py"):
            shutil.copyfile(repository / "scripts" / name, self.repository / "scripts" / name)
        for name in ("compose.yaml", "compose.bootstrap.yaml", "compose.acme.yaml", "compose.issuer.yaml"):
            shutil.copyfile(repository / "deploy/reference" / name, self.repository / "deploy/reference" / name)
        networks = command("docker", "network", "ls", "--quiet").stdout.split()
        existing = json.loads(command("docker", "network", "inspect", *networks).stdout)
        used = [ipaddress.ip_network(item["Subnet"]) for network in existing for item in (network.get("IPAM", {}).get("Config") or []) if item.get("Subnet")]
        # Explicit test-only allocation avoids consuming Docker's default pool.
        # The copied template and its allocation enter the real review digest.
        start = int(uuid.uuid4()) % 4096
        selected = []
        base = int(ipaddress.ip_address("10.240.0.0"))
        for index in range(4096):
            candidate = ipaddress.ip_network((base + ((start + index) % 4096) * 256, 24))
            if not any(candidate.overlaps(value) for value in used if value.version == 4):
                selected.append(candidate)
                if len(selected) == 2:
                    break
        if len(selected) != 2:
            raise RuntimeError("owned ACME fixture address ranges are unavailable")
        boot, issuer = selected
        self.address = str(issuer.network_address + 10)
        source = self.repository / "deploy/reference/compose.issuer.yaml"
        original = source.read_text()
        assert original.count("  public_tls: {}") == 1
        source.write_text(original.replace("  public_tls: {}", "  public_tls:\n    ipam:\n      config:\n        - subnet: " + str(issuer)))
        command("docker", "network", "create", "--internal", "--subnet", str(boot),
                "--label", "io.openuem.reference.fixture=" + project, self.network)
        cleanup.callback(self.remove)
        account = str(os.geteuid()) + ":" + str(os.getegid())
        command("docker", "run", "--detach", "--pull", "never", "--name", self.server, "--network", self.network,
                "--user", account, "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--pids-limit", "128", "--memory", "256m", "--env", "OPENUEM_ACME_REFERENCE_FIXTURE=1",
                "--env", "OPENUEM_ACME_REFERENCE_ADDRESS=" + self.address,
                "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=32m,mode=0700,uid=" + str(os.geteuid()) + ",gid=" + str(os.getegid()),
                "--label", "io.openuem.reference.fixture=" + project,
                "--mount", "type=bind,source=" + str(self.output) + ",destination=/fixture", image,
                "-test.v", "-test.run=^TestACMEReferenceServer$", "-test.timeout=20m")
        self.control_address = json.loads(command("docker", "inspect", self.server).stdout)[0]["NetworkSettings"]["Networks"][self.network]["IPAddress"]
        deadline = time.monotonic() + 30
        while not (self.output / "ready.json").exists() and time.monotonic() < deadline:
            assert json.loads(command("docker", "inspect", self.server).stdout)[0]["State"]["Running"]
            time.sleep(.1)
        assert json.loads((self.output / "ready.json").read_text()) == {"ready": True}
        configuration = {"version": 1, "public_origin": "https://uem.example.test", "acme_directory_url": "https://acme.example.test:14000/dir",
                         "email": "operator@example.test", "accept_terms": True, "dns_provider": "httpreq",
                         "provider_environment_file": "/run/openuem-acme/provider.json", "state_directory": "/var/lib/openuem-acme",
                         "publication_directory": "/var/lib/openuem-public-tls", "acme_roots_file": "/run/openuem-acme/acme-roots.pem",
                         "dns_resolvers": [self.address + ":53"], "attempt_timeout": "1m", "check_interval": "1m"}
        provider = {"HTTPREQ_ENDPOINT": "http://acme.example.test:18080", "HTTPREQ_USERNAME": "fixture",
                    "HTTPREQ_PASSWORD_FILE": "/run/openuem-acme/provider-secret", "HTTPREQ_PROPAGATION_TIMEOUT": "10",
                    "HTTPREQ_POLLING_INTERVAL": "1", "HTTPREQ_HTTP_TIMEOUT": "50"}
        for name, data in (("issuer.json", json.dumps(configuration).encode()), ("provider.json", json.dumps(provider).encode()),
                           ("provider-secret", b"synthetic-dns-secret"), ("acme-roots.pem", (self.output / "acme-roots.pem").read_bytes())):
            descriptor = os.open(self.inputs / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                output.write(data)

    def attach(self, process):
        if self.attached:
            return
        deadline = time.monotonic() + 60
        while process.poll() is None and time.monotonic() < deadline:
            if self.command("docker", "network", "ls", "--quiet", "--filter", "name=^" + self.issuer_network + "$").stdout.strip():
                self.command("docker", "network", "connect", "--ip", self.address, "--alias", "acme.example.test",
                             "--alias", "ns.example.test", self.issuer_network, self.server)
                self.attached = True
                return
            time.sleep(.05)
        raise RuntimeError("installer did not create its reviewed issuer network")

    def control(self, action):
        # The test binary is already in this owned fixture container. Its
        # private fixture address allows control before the issuer network exists.
        result = self.command("docker", "exec", "--env", "OPENUEM_ACME_REFERENCE_ADDRESS=" + self.control_address,
                              "--env", "OPENUEM_ACME_REFERENCE_ACTION=" + action, self.server,
                              "/issuer.test", "-test.v", "-test.run=^TestACMEReferenceControl$", "-test.timeout=5s")
        assert "--- PASS: TestACMEReferenceControl " in result.stdout
        if action == "status":
            return json.loads(next(line for line in result.stdout.splitlines() if line.startswith("{")))

    def stop(self):
        self.command("docker", "stop", "--time", "15", self.server)
        current = json.loads(self.command("docker", "inspect", self.server).stdout)[0]
        assert not current["State"]["Running"] and current["State"]["ExitCode"] == 0
        assert "--- PASS: TestACMEReferenceServer " in self.command("docker", "logs", self.server).stdout

    def remove(self):
        self.command("docker", "rm", "--force", "--volumes", self.server, check=False)
        self.command("docker", "network", "rm", self.network)

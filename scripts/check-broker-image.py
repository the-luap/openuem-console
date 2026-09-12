"""Audit the stock broker executable, license and offline runtime boundary."""

import hashlib
import json
import pathlib
import re
import subprocess
import sys
import tarfile
import tempfile


def call(*args):
    return subprocess.check_output(args, text=True, timeout=60).strip()


image = sys.argv[1]
version = re.search(r"github.com/nats-io/nats-server/v2 v(\S+)", pathlib.Path("go.mod").read_text()).group(1)
config = json.loads(call("docker", "image", "inspect", "--format", "{{json .Config}}", image))
assert config["User"] == "65532:65532"
assert config["Entrypoint"] == ["/nats-server"] and config["Cmd"] == ["--help"]
assert config["StopSignal"] == "SIGTERM"
assert not config.get("ExposedPorts") and not config.get("Healthcheck")
run = ["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
       "--security-opt", "no-new-privileges", "--pids-limit", "64", "--memory", "128m", image]
assert "Usage: nats-server" in call(*run)
assert call(*run, "--version") == "nats-server: v" + version
missing = subprocess.run(run + ["--config", "/run/openuem/broker.json"], text=True,
                         capture_output=True, timeout=15)
assert missing.returncode != 0 and "no such file or directory" in missing.stderr
container = call("docker", "create", image)
try:
    with tempfile.TemporaryDirectory() as directory:
        archive = str(pathlib.Path(directory) / "runtime.tar")
        subprocess.run(["docker", "export", "-o", archive, container], check=True, timeout=60)
        with tarfile.open(archive) as stream:
            entries = {entry.name.removeprefix("./").lstrip("/"): entry for entry in stream if not entry.isdir()}
            generated = {".dockerenv", "dev/console", "etc/hostname", "etc/hosts", "etc/resolv.conf", "etc/mtab"}
            if "etc/mtab" in entries:
                assert entries["etc/mtab"].issym() and entries["etc/mtab"].linkname == "/proc/mounts"
            assert set(entries) - generated == {"nats-server", "licenses/nats-server.LICENSE"}
            assert entries["nats-server"].isfile() and entries["nats-server"].mode & 0o111
            license_entry = entries["licenses/nats-server.LICENSE"]
            assert license_entry.isfile()
            assert hashlib.sha256(stream.extractfile(license_entry).read()).hexdigest() == "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4"
finally:
    subprocess.run(["docker", "rm", "-f", container], check=True, stdout=subprocess.DEVNULL)
print("broker image: pinned stock executable, license and unprivileged startup verified")

"""Audit the console image's pinned base, application files and offline startup."""

import hashlib
import json
import pathlib
import subprocess
import sys
import tarfile
import tempfile


BASE = "gcr.io/distroless/base-debian13:nonroot@sha256:d199d20fb09c898d8822ae5cbd5cf3c6d424e9b5e1fc2eb9a719a7752cd9d861"
GENERATED = {"etc/hostname", "etc/hosts", "etc/resolv.conf", "dev/console", ".dockerenv"}


def call(*args):
    return subprocess.check_output(args, text=True, timeout=60).strip()


def files(image):
    container = call("docker", "create", "--entrypoint", "/openuem-console", image, "--help")
    try:
        with tempfile.TemporaryDirectory() as directory:
            archive = str(pathlib.Path(directory) / "runtime.tar")
            subprocess.run(["docker", "export", "-o", archive, container], check=True, timeout=60)
            result = {}
            with tarfile.open(archive) as stream:
                for entry in stream:
                    name = entry.name.removeprefix("./").lstrip("/")
                    if entry.isdir() or name in GENERATED:
                        continue
                    digest = b""
                    if entry.isfile():
                        digest = hashlib.sha256(stream.extractfile(entry).read()).digest()
                    result[name] = (entry.type, entry.linkname, entry.mode, entry.uid, entry.gid, digest)
            return result
    finally:
        subprocess.run(["docker", "rm", "-f", container], check=True, stdout=subprocess.DEVNULL)


image = sys.argv[1]
config = json.loads(call("docker", "image", "inspect", "--format", "{{json .Config}}", image))
assert config["User"] == "65532:65532"
assert config["WorkingDir"] == "/tmp"
assert config["Entrypoint"] == ["/openuem-console"] and config["Cmd"] == ["--help"]
assert config["StopSignal"] == "SIGTERM"
assert "OPENUEM_INDIVIDUAL_AGENT_MODE=true" in config["Env"]
assert not config.get("ExposedPorts") and not config.get("Healthcheck")
runtime, base = files(image), files(BASE)
for name, record in base.items():
    assert runtime.get(name) == record, "console changed a pinned base file"
assets = call("git", "ls-files", "assets").splitlines()
assert assets
expected = {"openuem-console", "licenses/openuem-console.LICENSE", *assets}
assert set(runtime) - set(base) == expected, "unexpected application files in console image"
for path in assets:
    assert runtime[path][0] == tarfile.REGTYPE
    assert runtime[path][-1] == hashlib.sha256(pathlib.Path(path).read_bytes()).digest()
assert runtime["licenses/openuem-console.LICENSE"][-1] == hashlib.sha256(pathlib.Path("LICENSE").read_bytes()).digest()
assert "etc/ssl/certs/ca-certificates.crt" in runtime
assert not {"bin/sh", "bin/bash", "usr/bin/apt-get", "usr/bin/python3"} & set(runtime)

run = ["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
       "--security-opt", "no-new-privileges", "--pids-limit", "64", "--memory", "256m",
       "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=32m,uid=65532,gid=65532,mode=0700",
       "--tmpfs", "/var/log/openuem-server:rw,nosuid,nodev,noexec,size=8m,uid=65532,gid=65532,mode=0700", image]
assert "openuem-console" in call(*run)
missing = subprocess.run(run + ["start", "--domain", "example.test", "--org-name", "Fixture"],
                         text=True, capture_output=True, timeout=15)
assert missing.returncode != 0 and "individual console requires explicit TLS broker URLs" in missing.stderr
print("console image: pinned base, exact assets and unprivileged startup verified")

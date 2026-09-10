"""Audit the two private service images with offline, unprivileged commands."""

import json
import pathlib
import subprocess
import sys
import tarfile
import tempfile


def call(*args):
    return subprocess.check_output(args, text=True, timeout=60).strip()


for image, executable in zip(sys.argv[1:], ("openuem-agent-auth", "openuem-agent-commands"), strict=True):
    config = json.loads(call("docker", "image", "inspect", "--format", "{{json .Config}}", image))
    assert config["User"] == "65532:65532"
    assert config["Entrypoint"] == ["/" + executable]
    assert config["Cmd"] == ["--help"]
    assert config["StopSignal"] == "SIGTERM"
    assert not config.get("ExposedPorts")
    assert not config.get("Healthcheck")
    run = ["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
           "--security-opt", "no-new-privileges", "--pids-limit", "64", "--memory", "128m", image]
    help_result = subprocess.run(run, text=True, capture_output=True, timeout=15)
    assert help_result.returncode == 0 and "Usage of /" + executable in help_result.stderr
    missing = subprocess.run(run + ["--health-listen", "127.0.0.1:1326"], text=True,
                             capture_output=True, timeout=15)
    expected_error = ("database and credential-free private TLS broker URLs are required"
                      if executable == "openuem-agent-auth" else
                      "command service requires a database URL and explicit private TLS broker origins")
    assert missing.returncode != 0 and expected_error in missing.stderr
    container = call("docker", "create", image)
    try:
        with tempfile.TemporaryDirectory() as directory:
            archive = str(pathlib.Path(directory) / "runtime.tar")
            subprocess.run(["docker", "export", "-o", archive, container], check=True)
            with tarfile.open(archive) as stream:
                names = {entry.name.removeprefix("./").lstrip("/") for entry in stream if entry.isfile()}
            assert {executable, "licenses/openuem-console.LICENSE"} <= names
            allowed = {executable, "licenses/openuem-console.LICENSE", ".dockerenv",
                       "dev/console", "etc/hostname", "etc/hosts", "etc/resolv.conf"}
            assert names <= allowed
    finally:
        subprocess.run(["docker", "rm", "-f", container], check=True, stdout=subprocess.DEVNULL)
    print(executable + ": private runtime boundary verified")

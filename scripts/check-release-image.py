"""Audit the separate release admission runtime without database or network access."""

import json
import pathlib
import subprocess
import sys
import tarfile
import tempfile


def call(*args):
    return subprocess.check_output(args, text=True, timeout=60).strip()


if len(sys.argv) != 2:
    raise SystemExit("provide exactly one local release admission image")
image = sys.argv[1]
executable = "openuem-agent-releases"
config = json.loads(call("docker", "image", "inspect", "--format", "{{json .Config}}", image))
assert config["User"] == "65532:65532"
assert config["Entrypoint"] == ["/" + executable] and config["Cmd"] == ["--help"]
assert config["StopSignal"] == "SIGTERM" and not config.get("ExposedPorts") and not config.get("Healthcheck")
run = ["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
       "--security-opt", "no-new-privileges", "--pids-limit", "64", "--memory", "128m", image]
help_result = subprocess.run(run, text=True, capture_output=True, timeout=15)
assert help_result.returncode == 0 and "Usage: openuem-agent-releases" in help_result.stdout
assert "-dburl-file" in help_result.stdout and not help_result.stderr
for arguments, expected in ((["--action", "show"], "configure one protected private agent database connection"),
                            (["--unknown=synthetic-secret"], "release command arguments are invalid")):
    failed = subprocess.run(run + arguments, text=True, capture_output=True, timeout=15)
    assert failed.returncode != 0 and not failed.stdout and expected in failed.stderr
    assert "synthetic-secret" not in failed.stderr
container = call("docker", "create", image)
try:
    with tempfile.TemporaryDirectory(prefix="openuem-release-audit-") as directory:
        archive = str(pathlib.Path(directory) / "runtime.tar")
        subprocess.run(["docker", "export", "-o", archive, container], check=True)
        with tarfile.open(archive) as stream:
            names = {entry.name.removeprefix("./").lstrip("/") for entry in stream if entry.isfile()}
        assert {executable, "licenses/openuem-console.LICENSE"} <= names
        assert names <= {executable, "licenses/openuem-console.LICENSE", ".dockerenv",
                         "dev/console", "etc/hostname", "etc/hosts", "etc/resolv.conf"}
finally:
    subprocess.run(["docker", "rm", "-f", container], check=True, stdout=subprocess.DEVNULL)
print("release admission: private runtime boundary verified")

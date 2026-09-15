"""Exercise real DNS-01 across separate owned issuer and test-provider containers."""

import argparse
import ipaddress
import json
import os
import pathlib
import re
import subprocess
import tempfile
import time
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture_image")
    args = parser.parse_args()
    if os.name != "posix" or os.geteuid() == 0 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./:@-]{0,511}", args.fixture_image):
        raise RuntimeError("reference ACME acceptance requires a non-root account and an explicit local fixture image")
    environment = {name: os.environ[name] for name in ("PATH", "HOME", "DOCKER_CONFIG", "DOCKER_CONTEXT", "DOCKER_HOST") if name in os.environ}

    def command(*arguments, check=True, timeout=60):
        result = subprocess.run(arguments, env=environment, text=True, capture_output=True, timeout=timeout)
        if check and result.returncode:
            failures = re.findall(r"reference_linux_test.go:\d+: ([^\n]+)", result.stdout)
            raise RuntimeError("owned reference ACME operation failed" + (": " + "; ".join(failures[:3]) if failures else ""))
        return result

    image = json.loads(command("docker", "image", "inspect", args.fixture_image).stdout)[0]
    assert image["Os"] == "linux" and image["Config"]["Entrypoint"] == ["/issuer.test"]
    project = "openuem-acme-reference-" + uuid.uuid4().hex[:12]
    network, server, client = project + "-network", project + "-server", project + "-client"
    account = str(os.geteuid()) + ":" + str(os.getegid())
    with tempfile.TemporaryDirectory(prefix=project + "-") as temporary:
        root = pathlib.Path(temporary).resolve()
        command("docker", "network", "create", "--internal", "--label", "io.openuem.reference.fixture=" + project, network)
        try:
            selected = json.loads(command("docker", "network", "inspect", network).stdout)[0]
            assert selected["Internal"] and selected["Driver"] == "bridge"
            policy = ["--network", network, "--user", account, "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                      "--pids-limit", "128", "--memory", "256m", "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=32m,uid=" + str(os.geteuid()) + ",gid=" + str(os.getegid()) + ",mode=0700",
                      "--label", "io.openuem.reference.fixture=" + project, "--env", "OPENUEM_ACME_REFERENCE_FIXTURE=1"]
            command("docker", "run", "--detach", "--name", server, *policy,
                    "--network-alias", "acme.example.test", "--network-alias", "ns.example.test",
                    "--mount", "type=bind,src=" + str(root) + ",dst=/fixture", image["Id"],
                    "-test.v", "-test.run=^TestACMEReferenceServer$", "-test.timeout=15m")
            server_state = json.loads(command("docker", "inspect", server).stdout)[0]
            address = server_state["NetworkSettings"]["Networks"][network]["IPAddress"]
            assert ipaddress.ip_address(address).version == 4 and ipaddress.ip_address(address).is_private
            deadline = time.monotonic() + 30
            ready = root / "ready.json"
            while not ready.exists() and time.monotonic() < deadline:
                current = json.loads(command("docker", "inspect", server).stdout)[0]
                if not current["State"]["Running"]:
                    raise RuntimeError("reference ACME server exited before readiness")
                time.sleep(.1)
            assert ready.is_file() and json.loads(ready.read_text()) == {"ready": True}
            result = command("docker", "run", "--rm", "--name", client, *policy,
                             "--env", "OPENUEM_ACME_REFERENCE_ADDRESS=" + address,
                             "--mount", "type=bind,src=" + str(root) + ",dst=/fixture,readonly", image["Id"],
                             "-test.v", "-test.run=^TestACMEReferenceClient$", "-test.timeout=90s", timeout=100)
            if "--- PASS: TestACMEReferenceClient " not in result.stdout:
                raise RuntimeError("reference issuer did not positively establish separate-container DNS-01 acceptance")
            command("docker", "stop", "--time", "15", server)
            stopped = json.loads(command("docker", "inspect", server).stdout)[0]
            logs = command("docker", "logs", server)
            assert not stopped["State"]["Running"] and stopped["State"]["ExitCode"] == 0
            assert "--- PASS: TestACMEReferenceServer " in logs.stdout
        finally:
            command("docker", "rm", "--force", "--volumes", client, server, check=False)
            command("docker", "network", "rm", network)
    print("reference ACME: separate containers, real DNS-01, retained account after provider failure, pinned chain and clean shutdown passed")


if __name__ == "__main__":
    main()

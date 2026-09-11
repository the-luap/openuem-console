"""Exercise the production reference installer using owned isolated containers."""

import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time
import uuid


REPOSITORY = pathlib.Path(__file__).resolve().parent.parent
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("reference_installation", REPOSITORY / "scripts/install-reference.py")
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


def command(*arguments, check=True, timeout=180):
    result = subprocess.run(arguments, text=True, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError("reference installation fixture command failed: " + result.stderr[-1000:])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for role in installer.EXECUTABLES:
        parser.add_argument(role + "_image")
    parser.add_argument("test_binary", type=pathlib.Path)
    parser.add_argument("--interrupt", action="store_true")
    args = parser.parse_args()
    if os.geteuid() == 0 or not args.test_binary.is_file():
        raise RuntimeError("installer fixture requires a non-root account and its Linux reference probe")
    project = "openuem-install-" + uuid.uuid4().hex[:12]
    account = str(os.geteuid()) + ":" + str(os.getegid())
    policy = ["--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", account, "--pids-limit", "128", "--memory", "512m"]
    with tempfile.TemporaryDirectory(prefix=project + "-") as temporary, contextlib.ExitStack() as cleanup:
        root = pathlib.Path(temporary).resolve()
        inputs, state = root / "inputs", root / "state"
        for directory in (inputs, state, inputs / "public", inputs / "releases"):
            directory.mkdir(mode=0o700)

        def remove_owned():
            for label in ("com.docker.compose.project", installer.PROJECT_LABEL):
                identities = command("docker", "ps", "--all", "--quiet", "--filter", "label=" + label + "=" + project).stdout.split()
                if identities:
                    command("docker", "rm", "--force", "--volumes", *identities)
            networks = command("docker", "network", "ls", "--quiet", "--filter", "label=com.docker.compose.project=" + project).stdout.split()
            if networks:
                command("docker", "network", "rm", *networks)
        cleanup.callback(remove_owned)
        probe = [*policy, "--env", "OPENUEM_REFERENCE_FIXTURE=1", *installer.mount(args.test_binary.resolve(), "/reference.test")]
        command("docker", "run", "--rm", "--network", "none", *probe, *installer.mount(inputs, "/state", True),
                "--entrypoint", "/reference.test", args.broker_image, "-test.v", "-test.run=^TestReferencePrepare$", "-test.timeout=30s")
        config = {"version": 1, "project": project, "directory": str(state), "domain": "example.test", "organization": "Reference $Literal",
                  "public_origin": "https://uem.example.test:8443", "administrator": "first-admin", "access": "isolated",
                  "administrator_networks": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
                  "tls_certificate": str(inputs / "public/server.pem"), "tls_key": str(inputs / "public/server.key"),
                  "release_keys": str(inputs / "release-keys.pem"), "images": {role: getattr(args, role + "_image") for role in installer.EXECUTABLES}}
        path = root / "installation.json"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as output:
            json.dump(config, output)
        invocation = ["python3", str(REPOSITORY / "scripts/install-reference.py"), "--config", str(path)]
        review = json.loads(command(*invocation, "--check").stdout)
        assert review["status"] == "ready-to-initialize" and review["published_tcp_ports"] == [] and not list(state.iterdir())
        denied = command(*invocation, "--apply", "--expected-review", "0" * 64, check=False)
        assert denied.returncode == 1 and not list(state.iterdir())
        apply = [*invocation, "--apply", "--expected-review", review["review_sha256"]]
        if args.interrupt:
            process = subprocess.Popen(apply, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic() + 90
                marker = state / ".setup/5-pki.json"
                while process.poll() is None and not marker.exists() and time.monotonic() < deadline:
                    time.sleep(.05)
                if process.poll() is not None or not marker.exists():
                    raise RuntimeError("installer did not reach a live retained interruption point")
                process.send_signal(signal.SIGTERM)
                process.communicate(timeout=45)
                assert process.returncode == 130
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()
            preserved = {str(file.relative_to(state)): hashlib.sha256(file.read_bytes()).hexdigest()
                         for parent in ("installation", "protocol", "credentials", "pki") for file in (state / parent).rglob("*") if file.is_file()}
            resumed = json.loads(command(*invocation, "--check").stdout)
            assert resumed["review_sha256"] == review["review_sha256"] and resumed["status"] == "ready-to-resume"
        result = json.loads(command(*apply).stdout)
        assert result["status"] == "awaiting-administrator"
        if args.interrupt:
            assert all(hashlib.sha256((state / path).read_bytes()).hexdigest() == value for path, value in preserved.items())
        print("reference installer: reviewed setup and retained first-administrator readiness passed", flush=True)

        def administrator(restart=False):
            result = command("docker", "run", "--rm", "--network", project + "_edge", *probe,
                "--env", "OPENUEM_REFERENCE_RESTART=" + ("1" if restart else "0"),
                *installer.mount(inputs / "public-ca.pem", "/trust.pem"), *installer.mount(state / "installation/state/initial-password", "/initial-password"),
                "--entrypoint", "/reference.test", args.broker_image, "-test.v", "-test.run=^TestReferenceAdministrator$", "-test.timeout=45s")
            assert "--- PASS: TestReferenceAdministrator " in result.stdout
        administrator()
        if args.interrupt:
            database = command("docker", "ps", "--all", "--quiet", "--filter", "label=com.docker.compose.project=" + project,
                               "--filter", "label=com.docker.compose.service=database").stdout.strip()
            command("docker", "stop", "--time", "20", database)
            class Interrupted(Exception):
                pass
            def after_stop(phase):
                if phase == "bootstrap-stopped":
                    raise Interrupted()
            operation = installer.Installation(installer.profile(path), after_step=after_stop)
            try:
                operation.apply(review["review_sha256"])
            except Interrupted:
                pass
            else:
                raise RuntimeError("installer did not stop at the retained bootstrap transition")
            assert (state / ".setup/12-bootstrap-stopped.json").is_file()
            assert not (state / ".setup/13-bootstrap-retired.json").exists()
            replacement = None
            for _ in range(2):
                # Interrupt immediately before the retirement marker. The first
                # attempt leaves the new console present; the second must accept
                # that exact replacement without recreating it again.
                operation = installer.Installation(installer.profile(path))
                original_step = operation.step
                def before_retired(name, *arguments, **options):
                    if name == "bootstrap-retired":
                        raise Interrupted()
                    return original_step(name, *arguments, **options)
                operation.step = before_retired
                try:
                    operation.apply(review["review_sha256"])
                except Interrupted:
                    pass
                else:
                    raise RuntimeError("installer did not retain the pre-marker replacement state")
                current = command("docker", "ps", "--all", "--quiet", "--filter", "label=com.docker.compose.project=" + project,
                                  "--filter", "label=com.docker.compose.service=console").stdout.strip()
                assert current and (replacement is None or current == replacement)
                replacement = current
            # Simulate the other interrupted recreate outcome: removal completed
            # but its replacement is absent. Only this owned console is removed.
            command("docker", "stop", "--time", "20", replacement)
            command("docker", "rm", replacement)
            assert not (state / ".setup/13-bootstrap-retired.json").exists()
            print("reference installer: stopped database, retained replacement and interrupted console recreation recovery passed", flush=True)
        result = json.loads(command(*apply).stdout)
        assert result["status"] == "complete" and result["ready"] is True
        administrator(True)
        identities = command("docker", "ps", "--all", "--quiet", "--filter", "label=com.docker.compose.project=" + project).stdout.split()
        values = json.loads(command("docker", "inspect", *identities).stdout)
        assert len(values) == 7 and all(value["State"]["Running"] and not value["HostConfig"]["PortBindings"] for value in values)
        console = next(value for value in values if value["Config"]["Labels"]["com.docker.compose.service"] == "console")
        assert not any(item["Destination"] == "/run/initial-password" for item in console["Mounts"])
        assert not any(item.startswith("OPENUEM_BOOTSTRAP_PASSWORD_FILE=") for item in console["Config"]["Env"])
        before = {value["Id"]: value["State"]["StartedAt"] for value in values}
        assert json.loads(command(*apply).stdout)["status"] == "already-complete"
        assert json.loads(command(*invocation, "--check").stdout)["status"] == "complete"
        values = json.loads(command("docker", "inspect", *identities).stdout)
        assert {value["Id"]: value["State"]["StartedAt"] for value in values} == before
        print("reference installer: verified password replacement, retired bootstrap mount and unchanged completed retry passed", flush=True)


if __name__ == "__main__":
    main()

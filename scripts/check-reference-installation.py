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
    parser.add_argument("--acme-image")
    parser.add_argument("--acme-fixture-image")
    args = parser.parse_args()
    if bool(args.acme_image) != bool(args.acme_fixture_image):
        parser.error("automatic TLS acceptance requires both explicit ACME images")
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
            for owned in (project, project + "-public-tls") if args.acme_image else (project,):
                for label in ("com.docker.compose.project", installer.PROJECT_LABEL):
                    identities = command("docker", "ps", "--all", "--quiet", "--filter", "label=" + label + "=" + owned).stdout.split()
                    if identities:
                        command("docker", "rm", "--force", "--volumes", *identities)
                networks = command("docker", "network", "ls", "--quiet", "--filter", "label=com.docker.compose.project=" + owned).stdout.split()
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
        acme = None
        repository = REPOSITORY
        trust = inputs / "public-ca.pem"
        if args.acme_image:
            fixture_spec = importlib.util.spec_from_file_location("installer_acme_fixture", REPOSITORY / "scripts/reference-acme-fixture.py")
            fixture = importlib.util.module_from_spec(fixture_spec)
            fixture_spec.loader.exec_module(fixture)
            acme = fixture.ACMEFixture(root, REPOSITORY, project, args.acme_fixture_image, command, cleanup)
            repository = installer.REPOSITORY = acme.repository
            trust = acme.output / "gateway-roots.pem"
            config.pop("tls_certificate")
            config.pop("tls_key")
            config.update({"version": 2, "public_tls": {"image": args.acme_image, "configuration": str(acme.inputs)}})
        path = root / "installation.json"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as output:
            json.dump(config, output)
        invocation = ["python3", str(repository / "scripts/install-reference.py"), "--config", str(path)]
        review = json.loads(command(*invocation, "--check").stdout)
        assert review["status"] == "ready-to-initialize" and review["published_tcp_ports"] == [] and not list(state.iterdir())
        denied = command(*invocation, "--apply", "--expected-review", "0" * 64, check=False)
        assert denied.returncode == 1 and not list(state.iterdir())
        apply = [*invocation, "--apply", "--expected-review", review["review_sha256"]]
        sequence = ("inputs", "public-tls", *installer.STEPS[1:]) if acme else installer.STEPS
        def marker(name):
            return state / ".setup" / (str(sequence.index(name) + 1) + "-" + name + ".json")
        def launch():
            process = subprocess.Popen(apply, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            def stop_controller():
                if process.poll() is None:
                    process.send_signal(signal.SIGTERM)
                    try:
                        process.communicate(timeout=45)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.communicate()
            cleanup.callback(stop_controller)
            if acme:
                try:
                    acme.attach(process)
                except RuntimeError:
                    if process.poll() is not None:
                        _, errors = process.communicate()
                        raise RuntimeError("installer exited before issuer attachment: " + errors[-1000:]) from None
                    raise
            return process
        def finish(process, expected=0):
            output, errors = process.communicate(timeout=180)
            if process.returncode != expected:
                raise RuntimeError("installer acceptance exited unexpectedly: " + errors[-1000:])
            return json.loads(output) if output.strip() else None
        if acme and args.interrupt:
            acme.control("fail")
            failed = launch()
            finish(failed, 1)
            assert not marker("public-tls").exists() and not (state / "public/current").is_symlink()
            binding = json.loads((state / "acme/state/account-key.json").read_text())
            key = state / "acme/state" / binding["key_path"]
            original_key = key.read_bytes()
            assert hashlib.sha256(original_key).hexdigest() == binding["sha256"]
            key.unlink()
            denied = command(*apply, check=False)
            assert denied.returncode == 1 and not key.exists() and not marker("public-tls").exists()
            descriptor = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                output.write(original_key)
            acme.control("hold")
            process = launch()
            try:
                deadline = time.monotonic() + 30
                while process.poll() is None and not acme.control("status")["held"] and time.monotonic() < deadline:
                    time.sleep(.1)
                assert process.poll() is None and acme.control("status")["held"] > 0
                job = project + "-setup-public-tls"
                previous = json.loads(command("docker", "inspect", job).stdout)[0]
                assert previous["State"]["Running"]
                process.send_signal(signal.SIGTERM)
                finish(process, 130)
                retained = json.loads(command("docker", "inspect", job).stdout)[0]
                assert retained["Id"] == previous["Id"] and retained["State"]["Running"]
                process = launch()
                time.sleep(.2)
                retained = json.loads(command("docker", "inspect", job).stdout)[0]
                assert retained["Id"] == previous["Id"] and retained["State"]["Running"]
                acme.control("allow")
                result = finish(process)
                assert result["status"] == "awaiting-administrator" and key.read_bytes() == original_key
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()
            print("reference installer: DNS provider failure, missing original key rejection and actual retained ACME process join passed", flush=True)
        if args.interrupt and not acme:
            process = launch()
            try:
                deadline = time.monotonic() + 90
                target = marker("pki")
                while process.poll() is None and not target.exists() and time.monotonic() < deadline:
                    time.sleep(.05)
                if process.poll() is not None or not target.exists():
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
            assert resumed["review_sha256"] == review["review_sha256"] and resumed["status"] in ("ready-to-resume", "awaiting-administrator")
        result = finish(launch())
        assert result["status"] == "awaiting-administrator"
        if acme:
            reviewed = json.loads(command(*invocation, "--check").stdout)
            certificate = installer.maintenance.gateway_trust(state, {"command": ["--tls-cert", "/run/public/current/fullchain.pem", "--tls-key", "/run/public/current/private.pem"]})
            expected = installer.public_tls(str(certificate), str(certificate.parent / "private.pem"), "uem.example.test")
            assert reviewed["public_tls_sha256"] == expected and reviewed["review_sha256"] == review["review_sha256"]
        if args.interrupt and not acme:
            assert all(hashlib.sha256((state / path).read_bytes()).hexdigest() == value for path, value in preserved.items())
        print("reference installer: reviewed setup and retained first-administrator readiness passed", flush=True)

        def administrator(restart=False):
            result = command("docker", "run", "--rm", "--network", project + "_edge", *probe,
                "--env", "OPENUEM_REFERENCE_RESTART=" + ("1" if restart else "0"),
                *installer.mount(trust, "/trust.pem"), *installer.mount(state / "installation/state/initial-password", "/initial-password"),
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
            assert marker("bootstrap-stopped").is_file()
            assert not marker("bootstrap-retired").exists()
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
            assert not marker("bootstrap-retired").exists()
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
        if acme:
            issuer = command("docker", "ps", "--all", "--quiet", "--filter", "label=com.docker.compose.project=" + project + "-public-tls").stdout.split()
            assert len(issuer) == 1
            identities.extend(issuer)
            current = json.loads(command("docker", "inspect", issuer[0]).stdout)[0]
            assert current["State"]["Running"] and not current["HostConfig"]["PortBindings"]
            before[current["Id"]] = current["State"]["StartedAt"]
            counts = acme.control("status")
            assert all(counts[name] > 0 for name in ("present", "cleanup", "txt")) and counts["records"] == counts["held"] == 0
            # Completed receipts no longer need external provider inputs.
            for source in acme.inputs.iterdir():
                source.unlink()
            acme.inputs.rmdir()
        assert json.loads(command(*apply).stdout)["status"] == "already-complete"
        assert json.loads(command(*invocation, "--check").stdout)["status"] == "complete"
        values = json.loads(command("docker", "inspect", *identities).stdout)
        assert {value["Id"]: value["State"]["StartedAt"] for value in values} == before
        if acme:
            acme.stop()
            print("reference installer: real DNS-01, pinned public chain and retained renewal service passed", flush=True)
        print("reference installer: verified password replacement, retired bootstrap mount and unchanged completed retry passed", flush=True)


if __name__ == "__main__":
    main()

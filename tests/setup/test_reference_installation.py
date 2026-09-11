"""Protected review, leases and retained-process tests for the reference installer."""

import base64
import copy
import fcntl
import importlib.util
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
SOURCE = pathlib.Path(__file__).resolve().parents[2] / "scripts/install-reference.py"
spec = importlib.util.spec_from_file_location("reference_installer_test", SOURCE)
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class QuietDocker:
    def __init__(self):
        self.calls = []

    def run(self, stage, *arguments, **options):
        self.calls.append((stage, arguments))
        return ""


class ProtectedInstallation(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="openuem-installer-unit-")
        self.addCleanup(temporary.cleanup)
        self.root = pathlib.Path(temporary.name).resolve()

    def operation(self, state=True):
        operation = installer.Installation.__new__(installer.Installation)
        operation.root = self.root
        info = installer.private(self.root, True)
        operation.root_identity = (info.st_dev, info.st_ino)
        operation.state = self.root / ".setup"
        operation.project = "reference-unit"
        operation.review = "a" * 64
        operation.record = {"review_sha256": operation.review}
        operation.steps = []
        operation.after_step = None
        operation.lease = None
        operation.docker = QuietDocker()
        operation.config = {"public_origin": "https://uem.example.test"}
        if state:
            info = installer.ensure_directory(operation.state)
            operation.state_identity = (info.st_dev, info.st_ino)
            operation.lease = os.open(operation.state / "lease", os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
            self.addCleanup(os.close, operation.lease)
        return operation

    def test_wrong_review_has_no_state_or_docker_mutation(self):
        operation = self.operation(False)
        with self.assertRaises(installer.InstallationError):
            operation.apply("b" * 64)
        self.assertEqual(list(self.root.iterdir()), [])
        self.assertEqual(operation.docker.calls, [])

    def test_busy_lease_cannot_stop_another_installers_gateway(self):
        operation = self.operation()
        held = operation.lease
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with self.assertRaisesRegex(installer.InstallationError, "still active"):
            operation.apply(operation.review)
        self.assertEqual(operation.docker.calls, [])
        self.assertEqual({path.name for path in operation.state.iterdir()}, {"lease"})

    def test_state_directory_replacement_does_not_reuse_a_moved_lease(self):
        operation = self.operation()
        old = self.root / "old-setup"
        operation.state.rename(old)
        operation.state.mkdir(mode=0o700)
        (old / "lease").rename(operation.state / "lease")
        with self.assertRaises(installer.InstallationError):
            operation.check_lease()

    def test_completed_artifacts_are_not_repaired_or_replaced(self):
        operation = self.operation()
        source = self.root / "input.pem"
        operation.retain(source, b"protected input")
        operation.step("inputs", ("input.pem",))
        source.unlink()
        with self.assertRaises(FileNotFoundError):
            operation.step("inputs")
        self.assertFalse(source.exists())

    def test_step_holes_and_foreign_review_are_rejected(self):
        operation = self.operation()
        for index, step in ((1, "inputs"), (2, "installation")):
            installer.write_record(operation.state / (str(index) + "-" + step + ".json"),
                {"step": step, "review_sha256": operation.review, "paths": [], "files": {}, "metadata": {"installation": "d" * 32} if step == "installation" else None})
        self.assertEqual(operation.read_steps(), ["inputs", "installation"])
        first = operation.state / "1-inputs.json"
        saved = first.read_bytes()
        first.write_bytes(saved.replace(operation.review.encode(), b"b" * 64))
        with self.assertRaises(installer.InstallationError):
            operation.read_steps()
        first.write_bytes(saved)
        (operation.state / "1-inputs.json").unlink()
        with self.assertRaises(installer.InstallationError):
            operation.read_steps()

    def test_journal_cannot_add_paths_outside_the_installation(self):
        operation = self.operation()
        installer.write_record(operation.state / "1-inputs.json", {"step": "inputs", "review_sha256": operation.review,
            "paths": ["../unrelated"], "files": {}, "metadata": None})
        with self.assertRaises(installer.InstallationError):
            operation.read_steps()

    def test_empty_retained_lock_files_have_a_stable_snapshot(self):
        operation = self.operation()
        path = self.root / "retained.lock"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
        self.assertEqual(operation.snapshot(("retained.lock",)), {"retained.lock": installer.hashlib.sha256(b"").hexdigest()})

    def test_release_trust_accepts_only_bounded_distinct_public_ed25519_keys(self):
        def public(key):
            return b"-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(bytes.fromhex("302a300506032b6570032100") + key) + b"\n-----END PUBLIC KEY-----\n"
        key = public(bytes(range(32)))
        self.assertEqual(len(installer.release_keys(key)), 1)
        for invalid in (b"", key + key, key.replace(b"PUBLIC KEY", b"PRIVATE KEY"), key + b"trailing", public(b"short"), b"".join(public(bytes([index]) * 32) for index in range(9))):
            with self.assertRaises((installer.InstallationError, ValueError)):
                installer.release_keys(invalid)

    def test_profile_rejects_ambiguous_origin_networks_and_image_arguments(self):
        value = {"version": 1, "project": "reference-unit", "directory": str(self.root),
                 "domain": "example.test", "organization": "Reference $Literal", "public_origin": "https://uem.example.test",
                 "administrator": "first-admin", "administrator_networks": ["10.42.0.0/24"], "access": "public",
                 "tls_certificate": "/inputs/server.pem", "tls_key": "/inputs/server.key", "release_keys": "/inputs/release-keys.pem",
                 "images": {role: "local/" + role + ":check" for role in installer.EXECUTABLES}}
        source = self.root / "profile.json"
        installer.write_record(source, value)
        self.assertEqual(installer.profile(source), value)
        for field, invalid in (("version", True), ("project", "--project"), ("public_origin", "https://uem.example.test:443"),
                               ("public_origin", "https://user@uem.example.test"), ("public_origin", "https://uem.example.test/"),
                               ("administrator_networks", ["0.0.0.0/0"]), ("administrator_networks", ["10.42.0.1/24"]),
                               ("administrator_networks", ["10.42.0.0/24"] * 2), ("administrator_networks", ["::/0"]),
                               ("organization", "Reference\nInjected"), ("images", {**value["images"], "pki": "--privileged"})):
            with self.subTest(field=field, value=invalid):
                source.write_bytes(installer.encoded({**value, field: invalid}))
                with self.assertRaises((installer.InstallationError, ValueError)):
                    installer.profile(source)

    def retained_job(self):
        operation = self.operation()
        operation.account = str(os.geteuid()) + ":" + str(os.getegid())
        operation.images = {"installation": "sha256:" + "b" * 64}
        operation.image_configs = {"installation": {"Env": ["PATH=/usr/bin"]}}
        arguments = ["--directory", "/work/state"]
        mounts = installer.mount(self.root, "/work", True)
        signature = installer.digest({"image": operation.images["installation"], "network": "none", "mounts": mounts, "arguments": arguments, "account": operation.account})
        state = {"Id": "c" * 64, "Image": operation.images["installation"],
                 "Config": {"User": operation.account, "Entrypoint": ["/openuem-installation-secrets"], "Cmd": arguments, "Env": ["PATH=/usr/bin"],
                            "Labels": {installer.PROJECT_LABEL: operation.project, installer.REVIEW_LABEL: operation.review, installer.JOB_LABEL: signature}},
                 "HostConfig": {"ReadonlyRootfs": True, "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges"], "NetworkMode": "none", "IpcMode": "private", "Memory": 512 << 20, "PidsLimit": 128},
                 "NetworkSettings": {"Networks": {"none": {}}}, "Mounts": [{"Type": "bind", "Destination": "/work", "Source": str(self.root), "RW": True}],
                 "State": {"Running": True, "Status": "running", "ExitCode": 0}}

        class RetainedDocker(QuietDocker):
            observing = True

            def objects(self, stage, *arguments):
                return [copy.deepcopy(state)]

            def run(self, stage, *arguments, **options):
                self.calls.append((stage, arguments))
                if arguments[0] == "ps":
                    return state["Id"]
                if arguments[0] == "wait":
                    if not self.observing:
                        raise subprocess.TimeoutExpired("docker wait", 1)
                    return "0"
                if arguments[0] == "logs":
                    return '{"installation":"' + "d" * 32 + '"}'
                if arguments[0] == "rm":
                    return ""
                raise AssertionError("retained live job must not be recreated or restarted")
        operation.docker = RetainedDocker()
        return operation, mounts, arguments, state

    def test_live_setup_job_is_joined_after_an_observation_timeout(self):
        operation, mounts, arguments, _ = self.retained_job()
        operation.docker.observing = False
        with self.assertRaises(subprocess.TimeoutExpired):
            operation.job("installation", "installation", "none", mounts, arguments)
        self.assertFalse(any(args[0] == "rm" for _, args in operation.docker.calls))
        operation.docker.observing = True
        self.assertEqual(operation.job("installation", "installation", "none", mounts, arguments), {"installation": "d" * 32})
        self.assertFalse(any(args[0] in ("create", "start") for _, args in operation.docker.calls))

    def test_retained_job_mount_or_review_substitution_is_rejected(self):
        operation, mounts, arguments, state = self.retained_job()
        for target, key, value in ((state["Mounts"][0], "Source", "/different"),
                                   (state["Config"]["Labels"], installer.REVIEW_LABEL, "b" * 64),
                                   (state["Config"], "Env", ["PATH=/usr/bin", "PGHOST=unreviewed"]),
                                   (state["HostConfig"], "IpcMode", "host"),
                                   (state["HostConfig"], "Memory", 0),
                                   (state["HostConfig"], "PidsLimit", 0),
                                   (state["Mounts"][0], "Type", "volume")):
            with self.subTest(field=key):
                original = target[key]
                target[key] = value
                operation.docker.calls.clear()
                with self.assertRaises(installer.InstallationError):
                    operation.job("installation", "installation", "none", mounts, arguments)
                self.assertEqual([args[0] for _, args in operation.docker.calls], ["ps"])
                target[key] = original


if __name__ == "__main__":
    unittest.main()

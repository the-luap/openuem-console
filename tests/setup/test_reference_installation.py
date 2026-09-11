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

    def issuer_configuration(self):
        directory = self.root / "issuer-config"
        directory.mkdir(mode=0o700)
        config = {"public_origin": "https://uem.example.test:8443", "public_tls": {"configuration": str(directory), "image": "issuer:check"}}
        issuer = {"version": 1, "public_origin": "https://uem.example.test", "acme_directory_url": "https://acme.example.test/dir",
                  "email": "operator@example.test", "accept_terms": True, "dns_provider": "httpreq",
                  "provider_environment_file": "/run/openuem-acme/provider.json", "state_directory": "/var/lib/openuem-acme",
                  "publication_directory": "/var/lib/openuem-public-tls", "acme_roots_file": "/run/openuem-acme/roots.pem"}
        provider = {"HTTPREQ_ENDPOINT": "http://acme.example.test:18080", "HTTPREQ_PASSWORD_FILE": "/run/openuem-acme/secret"}
        for name, value in (("issuer.json", issuer), ("provider.json", provider), ("secret", {"synthetic": "secret"}), ("roots.pem", {"synthetic": "public trust"})):
            installer.write_record(directory / name, value)
        (directory / "roots.pem").chmod(0o644)
        return config, directory, issuer, provider

    def test_automatic_tls_profile_cannot_mix_modes_or_embed_provider_inputs_in_state(self):
        value = {"version": 2, "project": "reference-unit", "directory": str(self.root), "domain": "example.test",
                 "organization": "Reference", "public_origin": "https://uem.example.test", "administrator": "first-admin",
                 "administrator_networks": ["10.42.0.0/24"], "access": "public", "release_keys": "/inputs/release-keys.pem",
                 "public_tls": {"configuration": str(self.root.parent / "external-issuer-inputs"), "image": "issuer:local"},
                 "images": {role: "local/" + role + ":check" for role in installer.EXECUTABLES}}
        source = self.root / "profile.json"
        installer.write_record(source, value)
        # Completed receipts permit removed external inputs; opening them is
        # required only by the unfinished installation's actual input check.
        self.assertEqual(installer.profile(source), value)
        for changed in ({**value, "tls_key": "/inputs/server.key"}, {**value, "version": 1},
                        {**value, "public_tls": {**value["public_tls"], "configuration": str(self.root / "issuer")}},
                        {**value, "public_tls": {**value["public_tls"], "image": "--privileged"}}):
            source.write_bytes(installer.encoded(changed))
            with self.assertRaises(installer.InstallationError):
                installer.profile(source)

    def test_issuer_inputs_bind_only_explicit_files_without_writing_state(self):
        config, directory, expected, _ = self.issuer_configuration()
        before = {path.name: path.read_bytes() for path in directory.iterdir()}
        files, issuer = installer.issuer_inputs(config)
        self.assertEqual(issuer, expected)
        self.assertEqual(files, {"acme/config/" + name: data for name, data in before.items()})
        self.assertEqual({path.name for path in self.root.iterdir()}, {"issuer-config"})
        self.assertEqual(before, {path.name: path.read_bytes() for path in directory.iterdir()})

    def test_issuer_inputs_reject_file_escapes_aliases_and_unreferenced_material(self):
        config, directory, issuer, provider = self.issuer_configuration()
        for path in ("/outside/secret", "/run/openuem-acme/../secret", "/run/openuem-acme/provider.json", "/run/openuem-acme/issuer.json"):
            (directory / "provider.json").write_bytes(installer.encoded({**provider, "HTTPREQ_PASSWORD_FILE": path}))
            with self.assertRaises(installer.InstallationError):
                installer.issuer_inputs(config)
        (directory / "provider.json").write_bytes(installer.encoded(provider))
        installer.write_record(directory / "unreferenced.key", {"synthetic": "unreferenced"})
        with self.assertRaises(installer.InstallationError):
            installer.issuer_inputs(config)
        (directory / "unreferenced.key").unlink()
        secret = directory / "secret"
        secret.unlink()
        secret.symlink_to("roots.pem")
        with self.assertRaises(installer.InstallationError):
            installer.issuer_inputs(config)
        secret.unlink()
        installer.write_record(secret, {"synthetic": "secret"})
        (directory / "issuer.json").write_bytes(installer.encoded({**issuer, "public_origin": "https://different.example.test"}))
        with self.assertRaises(installer.InstallationError):
            installer.issuer_inputs(config)

    def test_automatic_tls_journal_requires_issuance_before_private_provisioning(self):
        operation = self.operation()
        operation.acme = True
        operation.sequence = ("inputs", "public-tls", *installer.STEPS[1:])
        operation.step("inputs")
        with self.assertRaises(installer.InstallationError):
            operation.step("installation", metadata={"installation": "d" * 32})
        operation.step("public-tls", metadata={"certificate_sha256": "e" * 64})
        operation.step("installation", metadata={"installation": "d" * 32})
        self.assertEqual(operation.read_steps(), ["inputs", "public-tls", "installation"])
        (operation.state / "2-public-tls.json").unlink()
        with self.assertRaises(installer.InstallationError):
            operation.read_steps()

    def test_issuer_anchors_require_the_original_account_and_matching_publication(self):
        operation = self.operation()
        operation.issuer_config = {"acme_directory_url": "https://acme.example.test:14000/dir", "email": "operator@example.test",
                                   "public_origin": "https://uem.example.test", "dns_provider": "httpreq"}
        key_path = "lego/accounts/acme.example.test_14000/operator@example.test/operator@example.test.key"
        key = self.root / "acme/state" / key_path
        key.parent.mkdir(mode=0o700, parents=True)
        (self.root / "public").mkdir(mode=0o700)
        operation.retain(key, b"original synthetic account key")
        binding = {"version": 1, "installation": str(installer.uuid.uuid4()), "origin": "https://uem.example.test",
                   "directory": "https://acme.example.test:14000/dir", "email": "operator@example.test", "provider": "httpreq"}
        for relative in ("acme/state/installation.json", "public/installation.json"):
            # Go's field order is valid; it is deliberately not maintenance's
            # canonical JSON encoding used for Python journal records.
            operation.retain(self.root / relative, installer.json.dumps(binding).encode())
        operation.retain(self.root / "acme/state/account-key.json", installer.json.dumps(
            {"version": 1, "key_path": key_path, "sha256": installer.hashlib.sha256(key.read_bytes()).hexdigest()}).encode())
        self.assertIn("acme/state/" + key_path, operation.issuer_anchors())
        key.unlink()
        with self.assertRaises(FileNotFoundError):
            operation.issuer_anchors()
        self.assertFalse(key.exists())
        operation.retain(key, b"replacement synthetic account key")
        with self.assertRaises(installer.InstallationError):
            operation.issuer_anchors()
        key.unlink()
        operation.retain(key, b"original synthetic account key")
        (self.root / "public/installation.json").write_bytes(installer.encoded({**binding, "installation": str(installer.uuid.uuid4())}))
        with self.assertRaises(installer.InstallationError):
            operation.issuer_anchors()

    def retained_job(self, issuer=False):
        operation = self.operation()
        role = "acme" if issuer else "installation"
        operation.account = str(os.geteuid()) + ":" + str(os.getegid())
        operation.images = {role: "sha256:" + "b" * 64}
        operation.image_configs = {role: {"Env": ["PATH=/usr/bin"]}}
        arguments = ["--directory", "/work/state"]
        mounts = installer.mount(self.root, "/work", True)
        specification = {"image": operation.images[role], "network": "none", "mounts": mounts, "arguments": arguments, "account": operation.account}
        temporary = "rw,nosuid,nodev,noexec,size=16m,mode=0700,uid=" + str(os.geteuid()) + ",gid=" + str(os.getegid())
        if issuer:
            specification.update({"init": True, "tmpfs": "/tmp:" + temporary})
        signature = installer.digest(specification)
        state = {"Id": "c" * 64, "Image": operation.images[role],
                 "Config": {"User": operation.account, "Entrypoint": ["/openuem-acme" if issuer else "/openuem-installation-secrets"], "Cmd": arguments, "Env": ["PATH=/usr/bin"],
                            "Labels": {installer.PROJECT_LABEL: operation.project, installer.REVIEW_LABEL: operation.review, installer.JOB_LABEL: signature}},
                 "HostConfig": {"ReadonlyRootfs": True, "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges"], "NetworkMode": "none", "IpcMode": "private", "Memory": 512 << 20, "PidsLimit": 128},
                 "NetworkSettings": {"Networks": {"none": {}}}, "Mounts": [{"Type": "bind", "Destination": "/work", "Source": str(self.root), "RW": True}],
                 "State": {"Running": True, "Status": "running", "ExitCode": 0}}
        if issuer:
            state["HostConfig"].update({"Init": True, "Tmpfs": {"/tmp": temporary}})

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
                    return "" if issuer else '{"installation":"' + "d" * 32 + '"}'
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

    def test_live_issuer_job_requires_init_and_bounded_private_temporary_storage(self):
        operation, mounts, arguments, state = self.retained_job(True)
        for field, value in (("Init", False), ("Tmpfs", {"/tmp": "rw"}), ("Tmpfs", {"/tmp": "rw", "/extra": "rw"})):
            original = state["HostConfig"][field]
            state["HostConfig"][field] = value
            with self.assertRaises(installer.InstallationError):
                operation.job("public-tls", "acme", "none", mounts, arguments)
            state["HostConfig"][field] = original
        operation.docker.observing = False
        with self.assertRaises(subprocess.TimeoutExpired):
            operation.job("public-tls", "acme", "none", mounts, arguments)
        self.assertFalse(any(args[0] == "rm" for _, args in operation.docker.calls))
        operation.docker.observing = True
        self.assertIsNone(operation.job("public-tls", "acme", "none", mounts, arguments))
        self.assertFalse(any(args[0] in ("create", "start") for _, args in operation.docker.calls))

    def test_renewal_service_rejects_foreign_identity_mounts_and_networks(self):
        operation, _, arguments, current = self.retained_job(True)
        operation.issuer_project = operation.project + "-public-tls"
        network_name = operation.issuer_project + "_public_tls"
        operation.image_configs["acme"]["Entrypoint"] = ["/openuem-acme"]
        current["Config"]["Labels"].update({"com.docker.compose.project": operation.issuer_project,
                                          "com.docker.compose.service": "acme", "com.docker.compose.oneoff": "False"})
        current["HostConfig"].update({"Memory": 128 << 20, "PidsLimit": 64, "NetworkMode": network_name})
        current["HostConfig"]["RestartPolicy"] = {"Name": "unless-stopped", "MaximumRetryCount": 0}
        current["Config"]["StopTimeout"] = 15
        current["NetworkSettings"]["Networks"] = {network_name: {}}
        paths = (("acme/config", "/run/openuem-acme", True), ("acme/state", "/var/lib/openuem-acme", False),
                 ("public", "/var/lib/openuem-public-tls", False))
        volumes = [{"source": str(self.root / source), "target": target, "read_only": readonly} for source, target, readonly in paths]
        current["Mounts"] = [{"Type": "bind", "Source": item["source"], "Destination": item["target"], "RW": not item["read_only"]} for item in volumes]
        network = {"Name": network_name, "Driver": "bridge", "Internal": True,
                   "Labels": {installer.REVIEW_LABEL: operation.review, installer.PROJECT_LABEL: operation.project,
                              "com.docker.compose.project": operation.issuer_project, "com.docker.compose.network": "public_tls"}}
        model = {"services": {"acme": {"command": arguments, "volumes": volumes,
                   "tmpfs": ["/tmp:" + current["HostConfig"]["Tmpfs"]["/tmp"]]}}, "networks": {"public_tls": {"name": network_name, "internal": True}}}

        class IssuerDocker(QuietDocker):
            def run(self, stage, *arguments, **options):
                self.calls.append((stage, arguments))
                if arguments[0] == "ps":
                    return current["Id"]
                if arguments[:2] == ("network", "ls"):
                    return "f" * 12
                raise AssertionError("issuer inspection must not mutate its resources")

            def objects(self, stage, *arguments):
                return [copy.deepcopy(network if arguments[0] == "network" else current)]

        operation.docker = IssuerDocker()
        self.assertEqual(operation.issuer_resources(model)["Id"], current["Id"])
        for target, field, value in ((current["Config"]["Labels"], installer.REVIEW_LABEL, "b" * 64),
                                    (current["Mounts"][0], "RW", True), (current["Mounts"][0], "Source", "/different"),
                                    (current["HostConfig"], "NetworkMode", "host"), (current["HostConfig"], "Memory", 0),
                                    (current["HostConfig"], "RestartPolicy", {"Name": "no", "MaximumRetryCount": 0}),
                                    (current["NetworkSettings"], "Networks", {network_name: {}, "private-backend": {}}),
                                    (network, "Internal", False), (network["Labels"], installer.PROJECT_LABEL, "different")):
            with self.subTest(field=field):
                original = target[field]
                target[field] = value
                with self.assertRaises(installer.InstallationError):
                    operation.issuer_resources(model)
                target[field] = original

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

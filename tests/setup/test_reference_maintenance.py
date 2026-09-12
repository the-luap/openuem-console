"""Recovery and protected metadata tests for reference maintenance."""

import json
import os
import pathlib
import tempfile
import types
import unittest

SOURCE = pathlib.Path(__file__).resolve().parents[2] / "scripts/maintain-reference-broker.py"
maintenance = types.ModuleType("reference_maintenance_test")
exec(compile(SOURCE.read_text(), str(SOURCE), "exec"), maintenance.__dict__)


class ProtectedMetadata(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="openuem-maintenance-unit-")
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)

    def test_broker_preview_accepts_only_reviewed_software_migrations(self):
        operation = self.operation()
        operation.setup = "synthetic-private-pki"
        plan = {"version": 2, "before_sha256": "a" * 64, "after_sha256": "b" * 64,
                "change_required": True, "added_worker_requests": ["software"]}
        operation.job = lambda *args: json.dumps(plan)
        for additions in (["software"], ["hardware", "recovery", "rotation", "software"]):
            plan["added_worker_requests"] = additions
            self.assertEqual(operation.broker_plan(), plan)
        plan.update(after_sha256="a" * 64, change_required=False, added_worker_requests=[])
        self.assertEqual(operation.broker_plan(), plan)
        baseline = dict(plan)
        for mutation in ({"version": 1}, {"version": 2.0}, {"version": True}, {"change_required": 0},
                         {"before_sha256": None}, {"after_sha256": "B" * 64},
                         {"after_sha256": "b" * 64}, {"extra": "field"},
                         {"change_required": True, "added_worker_requests": ["software"]},
                         {"change_required": True, "after_sha256": "b" * 64, "added_worker_requests": ["hardware", "recovery", "rotation"]},
                         {"change_required": True, "after_sha256": "b" * 64, "added_worker_requests": ["software", ">"]},
                         {"change_required": True, "after_sha256": "b" * 64, "added_worker_requests": ["software", "hardware", "recovery", "rotation"]}):
            with self.subTest(mutation=mutation):
                plan = baseline | mutation
                with self.assertRaises(maintenance.MaintenanceError):
                    operation.broker_plan()

    def test_software_migration_retains_completed_preceding_maintenance(self):
        operation = self.operation()
        operation.args = types.SimpleNamespace(project_name="synthetic-project")
        operation.check_preceding_maintenance()
        state = self.root / "maintenance" / maintenance.PRECEDING_OPERATION
        state.mkdir(parents=True, mode=0o700)
        state.parent.chmod(0o700)
        definition = {"synthetic": "previous frozen definition"}
        record = {"version": 1, "operation": maintenance.PRECEDING_OPERATION,
                  "binding": {"state": str(self.root), "project": "synthetic-project", "configuration": maintenance.digest(definition)},
                  "containers": {}, "broker": {}}
        record["review_sha256"] = maintenance.Maintenance.review_hash(record)
        maintenance.write_record(state / "review.json", record)
        maintenance.write_record(state / "compose.json", {"version": 1, "review_sha256": record["review_sha256"], "compose": definition})
        (state / "lease").touch(mode=0o600)
        for index, name in enumerate(maintenance.STEPS):
            with self.assertRaises(maintenance.MaintenanceError):
                operation.check_preceding_maintenance()
            maintenance.write_record(state / (str(index + 1) + "-" + name + ".json"),
                                     {"version": 1, "review_sha256": record["review_sha256"], "step": name})
        before = {path.name: path.read_bytes() for path in state.iterdir()}
        operation.check_preceding_maintenance()
        self.assertEqual({path.name: path.read_bytes() for path in state.iterdir()}, before)
        self.assertNotEqual(maintenance.OPERATION, maintenance.PRECEDING_OPERATION)
        for name in before:
            if name == "lease":
                continue
            with self.subTest(name=name):
                path = state / name
                path.write_bytes(b'{}')
                with self.assertRaises(maintenance.MaintenanceError):
                    operation.check_preceding_maintenance()
                self.assertEqual(path.read_bytes(), b'{}')
                path.write_bytes(before[name])

    def test_rendered_compose_values_preserve_literal_dollars_and_mapping_keys(self):
        rendered = {"command": ["Reference $$Literal $$$$Budget $${HOME}"],
                    "environment": {"UNCHANGED$$KEY": "$$VALUE"}, "read_only": True, "entrypoint": None}
        expected = {"command": ["Reference $Literal $$Budget ${HOME}"],
                    "environment": {"UNCHANGED$$KEY": "$VALUE"}, "read_only": True, "entrypoint": None}
        self.assertEqual(maintenance.compose_model(rendered), expected)
        self.assertEqual(rendered["command"], ["Reference $$Literal $$$$Budget $${HOME}"])

    def test_gateway_probe_selects_only_public_files_in_the_active_generation(self):
        public = self.root / "public"
        public.mkdir(mode=0o700)
        name = "generation-11111111-1111-4111-8111-111111111111"
        generation = public / name
        generation.mkdir(mode=0o700)
        certificate = generation / "fullchain.pem"
        maintenance.write_record(certificate, {"fixture": "public certificate only"})
        current = public / "current"
        current.symlink_to(name)
        service = {"command": ["--tls-cert", "/run/public/current/fullchain.pem", "--tls-key", "/run/public/current/private.pem"]}
        self.assertEqual(maintenance.gateway_trust(self.root, service), certificate)
        certificate.chmod(0o644)
        self.assertEqual(maintenance.gateway_trust(self.root, service), certificate)
        for invalid in ("../unrelated", str(generation), name + "/nested"):
            current.unlink()
            current.symlink_to(invalid)
            with self.assertRaises(maintenance.MaintenanceError):
                maintenance.gateway_trust(self.root, service)
        current.unlink()
        current.symlink_to(name)
        original = generation / "original.pem"
        certificate.rename(original)
        certificate.symlink_to(original.name)
        with self.assertRaises(maintenance.MaintenanceError):
            maintenance.gateway_trust(self.root, service)
        for arguments in (["--tls-cert", "/run/public/server.pem", "--tls-key", "/run/public/current/private.pem"],
                          service["command"] + ["--tls-cert", "/run/public/server.pem"]):
            with self.assertRaises(maintenance.MaintenanceError):
                maintenance.gateway_trust(self.root, {"command": arguments})

    def test_exact_private_creation_and_no_overwrite(self):
        path = self.root / "review.json"
        expected = {"version": 1, "hash": "a" * 64}
        maintenance.write_record(path, expected)
        before = path.read_bytes()
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(maintenance.read_record(path), expected)
        with self.assertRaises(FileExistsError):
            maintenance.write_record(path, {"version": 2})
        self.assertEqual(path.read_bytes(), before)

    def test_missing_is_distinct_from_partial_or_noncanonical_state(self):
        path = self.root / "review.json"
        self.assertIsNone(maintenance.read_record(path))
        for data in (b"", b'{"version":', b'{"version":1,"version":1}', b'{ "version":1}', b'{"value":NaN}'):
            with self.subTest(data=data):
                path.write_bytes(data)
                path.chmod(0o600)
                with self.assertRaises((maintenance.MaintenanceError, ValueError)):
                    maintenance.read_record(path)
                self.assertEqual(path.read_bytes(), data)

    def test_aliases_and_public_permissions_are_rejected(self):
        original = self.root / "original.json"
        maintenance.write_record(original, {"version": 1})
        alias = self.root / "alias.json"
        alias.symlink_to(original)
        with self.assertRaises(maintenance.MaintenanceError):
            maintenance.read_record(alias)
        alias.unlink()
        os.link(original, alias)
        with self.assertRaises(maintenance.MaintenanceError):
            maintenance.read_record(original)
        alias.unlink()
        original.chmod(0o644)
        with self.assertRaises(maintenance.MaintenanceError):
            maintenance.read_record(original)
        self.assertEqual(json.loads(original.read_text()), {"version": 1})

    def operation(self):
        operation = maintenance.Maintenance.__new__(maintenance.Maintenance)
        operation.root = self.root
        info = self.root.stat()
        operation.root_identity = (info.st_dev, info.st_ino)
        operation.state = self.root / "operation"
        info = maintenance.ensure_directory(operation.state)
        operation.state_identity = (info.st_dev, info.st_ino)
        operation.record = {"review_sha256": "a" * 64}
        operation.steps = []
        operation.after_step = None
        operation.lease = os.open(operation.state / "lease", os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        self.addCleanup(os.close, operation.lease)
        return operation

    def test_completed_marker_survives_interruption_and_a_hole_is_rejected(self):
        operation = self.operation()
        class Interrupted(Exception):
            pass
        def interrupt(_):
            raise Interrupted()
        operation.after_step = interrupt
        with self.assertRaises(Interrupted):
            operation.marker("clients-stopped")
        self.assertEqual(operation.read_steps(), ["clients-stopped"])
        operation.after_step = None
        operation.marker("broker-stopped")
        second = operation.state / "2-broker-stopped.json"
        before = second.read_bytes()
        (operation.state / "1-clients-stopped.json").unlink()
        with self.assertRaises(maintenance.MaintenanceError):
            operation.read_steps()
        self.assertEqual(second.read_bytes(), before)

    def test_changed_lease_inode_cannot_publish_a_step(self):
        operation = self.operation()
        lease = operation.state / "lease"
        lease.rename(operation.state / "original-lease")
        lease.touch(mode=0o600)
        with self.assertRaises(maintenance.MaintenanceError):
            operation.marker("clients-stopped")
        self.assertFalse((operation.state / "1-clients-stopped.json").exists())

    def test_invalid_arguments_are_not_echoed(self):
        for arguments in (["--unknown=synthetic-secret"], ["--apply"], ["--check", "--expected-review", "synthetic-secret"]):
            with self.subTest(arguments=arguments):
                with self.assertRaises(maintenance.MaintenanceError) as error:
                    maintenance.arguments(arguments)
                self.assertNotIn("synthetic-secret", str(error.exception))

    def test_compose_null_inherits_but_empty_values_clear_image_defaults(self):
        image = {"Entrypoint": ["/service"], "Cmd": ["--help"]}
        for service, expected in (
            ({}, (["/service"], ["--help"])),
            ({"entrypoint": None, "command": ["--start"]}, (["/service"], ["--start"])),
            ({"entrypoint": None, "command": None}, (["/service"], ["--help"])),
            ({"entrypoint": [], "command": None}, ([], [])),
            ({"entrypoint": ["/replacement"], "command": None}, (["/replacement"], [])),
            ({"command": []}, (["/service"], [])),
        ):
            with self.subTest(service=service):
                self.assertEqual(maintenance.Maintenance.invocation(service, image), expected)

    def test_interrupted_stop_does_not_accept_a_failed_prior_shutdown(self):
        operation = self.operation()
        operation.active = False
        operation.record = {"containers": {"broker": {"running": True}, "worker": {"running": False}}}
        operation.roles = {role: {"Id": role, "State": {"Running": False}} for role in ("broker", "worker")}
        operation.inspect = lambda: None
        class FailedShutdown:
            def objects(self, *_arguments):
                return [{"State": {"Running": False, "ExitCode": 137}}]
        operation.docker = FailedShutdown()
        with self.assertRaises(maintenance.MaintenanceError):
            operation.stop(("broker",))
        # The incompatible worker may already have failed before maintenance;
        # that does not weaken the clean stop required for the retained broker.
        operation.stop(("worker",))


if __name__ == "__main__":
    unittest.main()

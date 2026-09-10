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

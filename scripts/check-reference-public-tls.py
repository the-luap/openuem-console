"""Check the separate reference issuer component with owned offline inputs."""

import argparse
import json
import os
import pathlib
import re
import subprocess
import tempfile
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image")
    args = parser.parse_args()
    if os.name != "posix" or os.geteuid() == 0 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./:@-]{0,511}", args.image):
        raise RuntimeError("issuer component acceptance requires a non-root account and an explicit local image")
    environment = {key: os.environ[key] for key in ("PATH", "HOME", "DOCKER_CONFIG", "DOCKER_CONTEXT", "DOCKER_HOST") if key in os.environ}

    def command(*arguments):
        result = subprocess.run(arguments, env=environment, text=True, capture_output=True, timeout=60)
        if result.returncode:
            raise RuntimeError("owned reference issuer component operation failed")
        return result.stdout

    selected = json.loads(command("docker", "image", "inspect", args.image))[0]
    assert selected["Os"] == "linux" and selected["Config"]["Entrypoint"] == ["/openuem-acme"]
    project = "openuem-issuer-" + uuid.uuid4().hex[:12]
    repository = pathlib.Path(__file__).resolve().parent.parent
    account = str(os.geteuid()) + ":" + str(os.getegid())
    with tempfile.TemporaryDirectory(prefix=project + "-") as temporary:
        root = pathlib.Path(temporary).resolve()
        for relative in ("acme", "acme/config", "acme/state", "public"):
            (root / relative).mkdir(mode=0o700)

        def write(relative, value):
            descriptor = os.open(root / relative, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w") as stream:
                json.dump(value, stream)

        write("acme/config/issuer.json", {"version": 1, "public_origin": "https://uem.example.test",
              "acme_directory_url": "https://127.0.0.1:14000/dir", "email": "operator@example.test", "accept_terms": True,
              "dns_provider": "httpreq", "provider_environment_file": "/run/openuem-acme/provider.json",
              "state_directory": "/var/lib/openuem-acme", "publication_directory": "/var/lib/openuem-public-tls"})
        write("acme/config/provider.json", {"HTTPREQ_ENDPOINT": "http://127.0.0.1:1", "HTTPREQ_PASSWORD": "synthetic-component-fixture"})
        write("offline.json", {"networks": {"public_tls": {"internal": True}}})
        environment.update({"OPENUEM_REFERENCE_STATE": str(root), "OPENUEM_RUNTIME_UID": str(os.geteuid()),
                            "OPENUEM_RUNTIME_GID": str(os.getegid()), "OPENUEM_ACME_IMAGE": selected["Id"]})
        compose = ["docker", "compose", "--project-name", project, "--project-directory", str(root), "--env-file", "/dev/null",
                   "--file", str(repository / "deploy/reference/compose.issuer.yaml"), "--file", str(root / "offline.json")]
        model = json.loads(command(*compose, "config", "--format", "json"))
        assert set(model["services"]) == {"acme"} and set(model["networks"]) == {"public_tls"}
        service = model["services"]["acme"]
        assert service["image"] == selected["Id"] and service["pull_policy"] == "never" and not service.get("ports")
        assert service["user"] == account and service["init"] and service["read_only"] and service["cap_drop"] == ["ALL"]
        before = {path.name: path.read_bytes() for path in (root / "acme/config").iterdir()}
        try:
            command(*compose, "create", "--no-build")
            identity = command(*compose, "ps", "--all", "--quiet", "acme").strip()
            actual = json.loads(command("docker", "inspect", identity))[0]
            config, host = actual["Config"], actual["HostConfig"]
            assert not actual["State"]["Running"] and config["User"] == account and actual["Image"] == selected["Id"]
            assert config["Cmd"] == ["--config", "/run/openuem-acme/issuer.json"]
            assert host["Init"] and host["ReadonlyRootfs"] and not host["Privileged"] and host["CapDrop"] == ["ALL"]
            assert host["PidsLimit"] == 64 and host["Memory"] == 128 << 20 and not host.get("PortBindings")
            assert "no-new-privileges:true" in host["SecurityOpt"]
            assert {item["Destination"]: (item["Source"], item["RW"]) for item in actual["Mounts"]} == {
                "/run/openuem-acme": (str(root / "acme/config"), False),
                "/var/lib/openuem-acme": (str(root / "acme/state"), True),
                "/var/lib/openuem-public-tls": (str(root / "public"), True)}
            assert set(actual["NetworkSettings"]["Networks"]) == {project + "_public_tls"}
            network = json.loads(command("docker", "network", "inspect", project + "_public_tls"))[0]
            assert network["Internal"]
            result = command(*compose, "run", "--rm", "--no-deps", "acme", "--config", "/run/openuem-acme/issuer.json", "--check")
            assert json.loads(result) == {"inputs_valid": True}
            assert not list((root / "acme/state").iterdir()) and not list((root / "public").iterdir())
            assert before == {path.name: path.read_bytes() for path in (root / "acme/config").iterdir()}
            assert json.loads(command("docker", "inspect", identity))[0]["State"]["Status"] == "created"
        finally:
            command(*compose, "down", "--volumes", "--remove-orphans")
    print("reference issuer: isolated network, private account/configuration boundaries and actual read-only preflight passed")


if __name__ == "__main__":
    main()

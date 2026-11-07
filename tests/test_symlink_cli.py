"""Setup commands must stay offline and preserve unrelated launcher files."""
import os
from pathlib import Path

import pytest

import smtp_recipient_probe as cli


@pytest.fixture
def launcher_environment(tmp_path, monkeypatch):
    scripts = tmp_path / "environment" / "bin"
    scripts.mkdir(parents=True)
    name = "smtp-recipient-probe.exe" if os.name == "nt" else "smtp-recipient-probe"
    entrypoint = scripts / name
    entrypoint.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    entrypoint.chmod(0o755)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(cli.sysconfig, "get_path", lambda key: str(scripts))
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.setattr(cli, "run_probe", lambda *_: pytest.fail("Setup attempted a probe"))
    monkeypatch.setattr(cli, "validate_settings", lambda *_: pytest.fail("Setup attempted recipient validation"))
    return entrypoint, home / "bin" / name


def test_standalone_setup_and_repeat_through_symlink(launcher_environment, monkeypatch):
    entrypoint, destination = launcher_environment
    assert cli.main(["--symlink-cli"]) == 0
    assert destination.is_symlink()
    assert destination.resolve() == entrypoint
    monkeypatch.setattr(cli.sys, "argv", [str(destination), "--symlink-cli"])
    monkeypatch.setenv("PATH", str(destination.parent))
    assert cli.main() == 0
    assert destination.readlink() == entrypoint


@pytest.mark.parametrize("kind", ["file", "directory"])
def test_setup_preserves_unrelated_destination(launcher_environment, kind):
    _, destination = launcher_environment
    destination.parent.mkdir()
    if kind == "file":
        destination.write_text("keep this launcher", encoding="utf-8")
    else:
        destination.mkdir()
    assert cli.main(["--symlink-cli"]) == 3
    if kind == "file":
        assert destination.read_text(encoding="utf-8") == "keep this launcher"
    else:
        assert destination.is_dir()


def test_setup_repairs_stale_link_and_preserves_it_on_failure(launcher_environment, monkeypatch):
    entrypoint, destination = launcher_environment
    destination.parent.mkdir()
    old_target = destination.parent / "missing-old-environment"
    destination.symlink_to(old_target)
    original = Path.symlink_to

    def denied(*args, **kwargs):
        raise PermissionError("Simulated symlink denial")

    monkeypatch.setattr(Path, "symlink_to", denied)
    assert cli.main(["--symlink-cli"]) == 3
    assert destination.readlink() == old_target
    monkeypatch.setattr(Path, "symlink_to", original)
    assert cli.main(["--symlink-cli"]) == 0
    assert destination.resolve() == entrypoint


def test_setup_requires_installed_entrypoint(launcher_environment):
    entrypoint, destination = launcher_environment
    entrypoint.unlink()
    assert cli.main(["--symlink-cli"]) == 3
    assert not destination.exists()


@pytest.mark.parametrize("extra", [["--dry-run"], ["--target", "person@example.com"], ["--json", "report.json"]])
def test_setup_cannot_be_mixed_with_probe_options(launcher_environment, extra):
    _, destination = launcher_environment
    assert cli.main(["--symlink-cli", *extra]) == 2
    assert not destination.exists()

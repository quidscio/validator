"""Offline tests for persisted identity defaults, precedence, and validation."""
import json
from pathlib import Path
import socket

import dns.resolver
import pytest

import smtp_recipient_probe as cli


CONFIG_NAME = "smtp-recipient-probe.toml"
original_config_candidates = cli.config_candidates
BASE_ARGS = ["--target", "recipient@example.com", "--dry-run"]


def forbidden(*args, **kwargs):
    pytest.fail("Configuration handling attempted unmocked networking")


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(dns.resolver.Resolver, "resolve", forbidden)


def write_config(path, text='[smtp]\nmail_from = "config@example.net"\nhelo = "config.example.net"\n'):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def dry_report(tmp_path, extra=()):
    output = tmp_path / "report.json"
    assert cli.main([*BASE_ARGS, *extra, "--json", str(output)]) == 0
    return json.loads(output.read_text(encoding="utf-8"))


def test_default_config_supplies_both_identity_fields(tmp_path):
    write_config(tmp_path / CONFIG_NAME)
    report = dry_report(tmp_path)
    assert report["sender"] == "config@example.net"
    assert report["helo"] == "config.example.net"
    assert report["status"] == "dry_run"
    assert report["hosts"] == []


def test_environment_only_requires_no_config(tmp_path, monkeypatch):
    monkeypatch.setenv("SMTP_PROBE_MAIL_FROM", "environment@example.net")
    monkeypatch.setenv("SMTP_PROBE_HELO", "environment.example.net")
    report = dry_report(tmp_path)
    assert report["sender"] == "environment@example.net"
    assert report["helo"] == "environment.example.net"


@pytest.mark.parametrize("cli_flags,expected_sender,expected_helo", [
    ([], "environment@example.net", "environment.example.net"),
    (["--mail-from", "command@example.net"], "command@example.net", "environment.example.net"),
    (["--helo", "command.example.net"], "environment@example.net", "command.example.net"),
    (["--mail-from", "command@example.net", "--helo", "command.example.net"], "command@example.net", "command.example.net"),
])
def test_cli_overrides_environment_overrides_file_per_field(tmp_path, monkeypatch, cli_flags, expected_sender, expected_helo):
    write_config(tmp_path / CONFIG_NAME)
    monkeypatch.setenv("SMTP_PROBE_MAIL_FROM", "environment@example.net")
    monkeypatch.setenv("SMTP_PROBE_HELO", "environment.example.net")
    report = dry_report(tmp_path, cli_flags)
    assert report["sender"] == expected_sender
    assert report["helo"] == expected_helo


def test_partial_file_combines_with_environment_and_cli(tmp_path, monkeypatch):
    write_config(tmp_path / CONFIG_NAME, '[smtp]\nhelo = "config.example.net"\n')
    monkeypatch.setenv("SMTP_PROBE_MAIL_FROM", "environment@example.net")
    report = dry_report(tmp_path)
    assert report["sender"] == "environment@example.net"
    assert report["helo"] == "config.example.net"
    report = dry_report(tmp_path, ["--helo", "command.example.net"])
    assert report["helo"] == "command.example.net"


def test_explicit_config_selects_only_that_file(tmp_path):
    write_config(tmp_path / CONFIG_NAME)
    alternate = write_config(tmp_path / "other" / "custom.toml", '[smtp]\nmail_from = "other@example.net"\nhelo = "other.example.net"\n')
    report = dry_report(tmp_path, ["--config", str(alternate)])
    assert report["sender"] == "other@example.net"
    assert report["helo"] == "other.example.net"


def test_missing_explicit_config_does_not_fall_back(tmp_path, monkeypatch):
    write_config(tmp_path / CONFIG_NAME)
    monkeypatch.setattr(cli, "run_probe", forbidden)
    assert cli.main([*BASE_ARGS, "--config", str(tmp_path / "absent.toml")]) == 2


@pytest.mark.parametrize("text", [
    '[smtp\nhelo = "client.example.net"\n',
    'smtp = "not a table"\n',
    'mail_from = "misplaced@example.net"\n',
    '[smtp]\nmail_form = "typo@example.net"\n',
    '[smtp]\nmail_from = ["list@example.net"]\n',
    '[smtp]\nhelo = false\n',
])
def test_invalid_config_fails_before_probe(tmp_path, monkeypatch, text):
    write_config(tmp_path / CONFIG_NAME, text)
    monkeypatch.setattr(cli, "run_probe", forbidden)
    assert cli.main(BASE_ARGS) == 2


@pytest.mark.parametrize("key,bad_value", [
    ("mail_from", "sender@example.net\\r\\nDATA"),
    ("helo", "client.example.net\\r\\nDATA"),
])
def test_config_injection_rejected_before_probe(tmp_path, monkeypatch, key, bad_value):
    values = {"mail_from": "sender@example.net", "helo": "client.example.net"}
    values[key] = bad_value
    text = '[smtp]\n' + ''.join(f'{name} = "{value}"\n' for name, value in values.items())
    write_config(tmp_path / CONFIG_NAME, text)
    monkeypatch.setattr(cli, "run_probe", forbidden)
    assert cli.main(BASE_ARGS) == 2


@pytest.mark.parametrize("variable", ["SMTP_PROBE_MAIL_FROM", "SMTP_PROBE_HELO"])
def test_environment_injection_rejected_before_probe(tmp_path, monkeypatch, variable):
    write_config(tmp_path / CONFIG_NAME)
    monkeypatch.setenv(variable, "bad\r\nDATA")
    monkeypatch.setattr(cli, "run_probe", forbidden)
    assert cli.main(BASE_ARGS) == 2


def test_config_does_not_supply_target(tmp_path, monkeypatch):
    write_config(tmp_path / CONFIG_NAME)
    monkeypatch.setattr(cli, "run_probe", forbidden)
    assert cli.main(["--dry-run"]) == 2


def test_help_and_setup_bypass_config_loading(tmp_path, monkeypatch):
    write_config(tmp_path / CONFIG_NAME, "deliberately invalid TOML")
    monkeypatch.setattr(cli, "load_config", forbidden)
    assert cli.main(["--help"]) == 0
    target = tmp_path / "entrypoint"
    target.write_text("local launcher", encoding="utf-8")
    launcher = tmp_path / "launcher"
    launcher.symlink_to(target)
    monkeypatch.setattr(cli, "symlink_cli", lambda: launcher)
    assert cli.main(["--symlink-cli"]) == 0


def test_config_discovery_follows_launcher_symlink_and_ignores_cwd(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    module = project / "smtp_recipient_probe.py"
    module.write_text("# module", encoding="utf-8")
    script = project / ".venv" / "bin" / "smtp-recipient-probe"
    script.parent.mkdir(parents=True)
    script.write_text("# launcher", encoding="utf-8")
    shortcut = tmp_path / "bin" / "smtp-recipient-probe"
    shortcut.parent.mkdir()
    shortcut.symlink_to(script)
    unrelated = tmp_path / "working"
    unrelated.mkdir()
    write_config(unrelated / CONFIG_NAME, '[smtp]\nmail_from = "wrong@example.net"\nhelo = "wrong.example.net"\n')
    monkeypatch.chdir(unrelated)
    monkeypatch.setattr(cli, "__file__", str(module))
    monkeypatch.setattr(cli.sys, "argv", [str(shortcut)])
    monkeypatch.setattr(cli, "config_candidates", original_config_candidates)
    assert cli.config_candidates() == [script.parent / CONFIG_NAME, project / CONFIG_NAME]
    write_config(project / CONFIG_NAME)
    assert cli.load_config()["mail_from"] == "config@example.net"
    write_config(script.parent / CONFIG_NAME, '[smtp]\nmail_from = "launcher@example.net"\nhelo = "launcher.example.net"\n')
    assert cli.load_config()["mail_from"] == "launcher@example.net"


def test_direct_script_discovery_deduplicates_same_folder(tmp_path, monkeypatch):
    script = tmp_path / "smtp_recipient_probe.py"
    script.write_text("# module", encoding="utf-8")
    monkeypatch.setattr(cli, "__file__", str(script))
    monkeypatch.setattr(cli.sys, "argv", [str(script)])
    assert original_config_candidates() == [tmp_path / CONFIG_NAME]

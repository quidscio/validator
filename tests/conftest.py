"""Keep local defaults and shell identities out of every automated test."""
import pytest

import smtp_recipient_probe as cli


@pytest.fixture(autouse=True)
def isolate_operator_config(tmp_path, monkeypatch):
    monkeypatch.delenv("SMTP_PROBE_MAIL_FROM", raising=False)
    monkeypatch.delenv("SMTP_PROBE_HELO", raising=False)
    monkeypatch.setattr(cli, "config_candidates", lambda: [tmp_path / "smtp-recipient-probe.toml"])

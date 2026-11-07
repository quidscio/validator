"""Offline argument, DNS-routing, report, and conservative classification tests."""
from __future__ import annotations

import json
import re
import socket
from types import SimpleNamespace

import dns.exception
import dns.name
import dns.resolver
import pytest

import probe_common as common
from probe_common import Deadline
import probe_dns
from probe_dns import DNSFailure, DNSResolver
import smtp_recipient_probe as cli


def forbidden(*args, **kwargs):
    raise AssertionError("A local test attempted unmocked networking")


@pytest.fixture(autouse=True)
def no_public_network(monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(dns.resolver.Resolver, "resolve", forbidden)


def mx(preference, exchange):
    return SimpleNamespace(preference=preference, exchange=dns.name.from_text(exchange))


def address(ip):
    return SimpleNamespace(address=ip)


class FakeResolver:
    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def resolve(self, host, kind, *, lifetime, search):
        host = str(host).rstrip(".")
        self.calls.append((host, kind, lifetime, search))
        assert 0 < lifetime <= 5
        assert search is False
        result = self.answers.get((host, kind), dns.resolver.NoAnswer())
        if isinstance(result, BaseException):
            raise result
        return result


def resolver_for(answers):
    raw = FakeResolver(answers)
    return DNSResolver(Deadline(20, 5), resolver=raw), raw


def base_settings(**changes):
    result = {
        "target": "Target@example.com", "sender": "sender@example.net",
        "helo": "client.example.net", "control": "control@example.com",
        "control_mode": "auto", "max_mx": 2, "timeout": 5.0,
        "deadline": 20.0, "tls": "auto", "dry_run": False,
    }
    result.update(changes)
    return result


BASE_ARGS = ["--target", "Target@example.com", "--mail-from", "sender@example.net", "--helo", "client.example.net"]


def invoke(args):
    try:
        return cli.main(args)
    except SystemExit as exc:
        return exc.code


@pytest.mark.parametrize("field", ["--target", "--mail-from", "--control", "--helo"])
@pytest.mark.parametrize("injection", ["\r\nDATA", "\x00", "\t", "\x1b"])
def test_cli_control_characters_rejected_before_network(field, injection, capsys):
    args = list(BASE_ARGS)
    if field in args:
        args[args.index(field) + 1] += injection
    else:
        args.extend([field, "control@example.com" + injection])
    assert invoke(args) == 2
    output = capsys.readouterr()
    assert "invalid_input" in output.out + output.err


@pytest.mark.parametrize("bad", [
    "a@example.com,b@example.com", "Name<a@example.com>", '"quoted"@example.com',
    "tést@example.com", "test@éxample.com", ".leading@example.com",
    "trailing.@example.com", "double..dot@example.com", "a@-bad.example",
    "a@bad-.example", "a" * 65 + "@example.com",
])
def test_cli_unsupported_target_rejected_before_network(bad):
    args = list(BASE_ARGS)
    args[1] = bad
    assert invoke(args) == 2


@pytest.mark.parametrize("option,value", [
    ("--max-mx", "0"), ("--max-mx", "4"), ("--max-mx", "1.5"),
    ("--timeout", "0"), ("--timeout", "-1"), ("--timeout", "nan"),
    ("--deadline", "inf"), ("--deadline", "-2"), ("--tls", "never"),
])
def test_invalid_numeric_or_enum_options(option, value):
    assert invoke(BASE_ARGS + [option, value]) == 2


@pytest.mark.parametrize("args", [[], ["--target", "a@example.com"], BASE_ARGS + ["--target", "b@example.com", "c@example.com"]])
def test_missing_or_extra_arguments(args):
    assert invoke(args) == 2


@pytest.mark.parametrize("option,value", [
    ("--target", "second@example.com"),
    ("--mail-from", "second@example.net"),
    ("--helo", "second.example.net"),
])
def test_duplicate_required_identity_options_are_rejected(option, value):
    assert invoke(BASE_ARGS + [option, value]) == 2


def test_duplicate_control_options_are_rejected():
    assert invoke(BASE_ARGS + ["--control", "auto", "--control", "none"]) == 2


def test_output_directory_or_missing_parent_rejected_before_network(tmp_path):
    assert invoke(BASE_ARGS + ["--json", str(tmp_path)]) == 2
    assert invoke(BASE_ARGS + ["--json", str(tmp_path / "missing" / "report.json")]) == 3


def test_output_permission_failure_returns_three_before_probing(tmp_path, monkeypatch):
    def permission_denied(path):
        raise PermissionError("Simulated report path permission denial")

    monkeypatch.setattr(cli, "prepare_output", permission_denied)
    monkeypatch.setattr(cli, "run_probe", forbidden)
    assert invoke(BASE_ARGS + ["--json", str(tmp_path / "report.json")]) == 3


def test_dry_run_zero_dns_and_connections_and_json(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(probe_dns, "DNSResolver", forbidden)
    path = tmp_path / "dry.json"
    assert invoke(BASE_ARGS + ["--dry-run", "--json", str(path)]) == 0
    report = json.loads(path.read_text(encoding="utf-8"))
    assert report["target"] == "Target@example.com"
    assert report["message_submitted"] is False
    assert report["ownership_verified"] is False
    assert not report["hosts"]
    assert "dry" in capsys.readouterr().out.lower()


def test_address_normalization_and_supported_helo():
    assert common.email_address("Case.Tag+foo@EXAMPLE.COM") == "Case.Tag+foo@example.com"
    assert common.helo_name("[192.0.2.1]") == "[192.0.2.1]"
    assert common.helo_name("[IPv6:2001:db8::1]") == "[IPv6:2001:db8::1]"
    assert common.helo_name("CLIENT.EXAMPLE.NET") == "client.example.net"


@pytest.mark.parametrize("bad", ["localhost", "[bad]", "[2001:db8::1]", "[IPv6:192.0.2.1]", "2001:db8::1%eth0"])
def test_invalid_helo(bad):
    with pytest.raises(ValueError):
        common.helo_name(bad)


def test_control_random_distinct_same_domain():
    controls = {common.make_control("auto", "Target@example.com") for _ in range(10)}
    assert len(controls) == 10
    assert all(re.fullmatch(r"probe-nonexistent-[0-9a-f]{32}@example\.com", item) for item in controls)
    assert "Target@example.com" not in controls
    assert common.make_control("none", "Target@example.com") is None
    with pytest.raises(ValueError):
        common.make_control("Target@example.com", "Target@example.com")
    with pytest.raises(ValueError):
        common.make_control("control@elsewhere.example", "Target@example.com")


def test_auto_control_requires_room_for_prefix_and_128_bits():
    domain = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 29])
    target = common.email_address("a@" + domain)
    assert 254 - len(domain) - 1 == 32
    with pytest.raises(ValueError, match="128-bit control"):
        common.make_control("auto", target)
    assert common.make_control("none", target) is None
    assert common.make_control("b@" + domain, target) == "b@" + domain
    shorter_target = common.email_address("a@" + domain[:-1])
    control = common.make_control("auto", shorter_target)
    assert len(control) == 254
    assert re.fullmatch(r"p[0-9a-f]{32}", control.split("@", 1)[0])


@pytest.mark.parametrize("code,reply,expected", [
    (250, "2.1.5 Accepted", "accepted"),
    (251, "2.1.5 Forwarding to <elsewhere@example.net>", "accepted_forwarding"),
    (550, "5.1.1 Unavailable", "recipient_unavailable"),
    (550, "User unknown", "rejected_other"),
    (550, "5.7.1 Refused", "policy_rejected"),
    (554, "Policy rejection", "policy_rejected"),
    (551, "5.1.6 Try <elsewhere@example.net>", "rejected_other"),
    (553, "5.1.3 Bad address", "rejected_other"),
    (552, "5.2.2 Mailbox full", "rejected_other"),
    (450, "4.2.0 Later", "temporary_failure"),
    (421, "Closing", "temporary_failure"),
    (252, "Cannot verify", "unexpected_response"),
])
def test_individual_classification_preserves_evidence(code, reply, expected):
    result = common.classify_reply(code, reply)
    assert result["observation"] == expected
    assert result["code"] == code
    assert result["reply"] == reply


@pytest.mark.parametrize("target,control,status", [
    ((250, "Accepted"), (550, "5.1.1 Unknown"), "accepted_selectively"),
    ((251, "Forwarding"), (550, "5.1.1 Unknown"), "accepted_selectively"),
    ((250, "Accepted"), (250, "Accepted"), "accepted_unverified"),
    ((250, "Accepted"), (450, "4.1.0 Later"), "accepted_unverified"),
    ((550, "5.1.1 Unknown"), (550, "5.1.1 Unknown"), "recipient_unavailable"),
    ((550, "User unknown"), (550, "5.1.1 Unknown"), "inconclusive"),
    ((550, "5.7.1 Policy"), (550, "5.1.1 Unknown"), "inconclusive"),
])
def test_host_classification(target, control, status):
    actual, explanation = common.derive_host_result(common.classify_reply(*target), common.classify_reply(*control))
    assert actual == status
    if status == "recipient_unavailable":
        assert "blocked" in explanation and "not" in explanation
    if target[0] == control[0] == 250:
        assert "not proven" in explanation


def test_accepted_with_disabled_control_unverified():
    assert common.derive_host_result(common.classify_reply(250, "OK"), {"observation": "disabled"})[0] == "accepted_unverified"


@pytest.mark.parametrize("records,status", [
    ([mx(0, ".")], "domain_no_mail"),
    ([mx(5, ".")], "dns_configuration_error"),
    ([mx(0, "."), mx(10, "mx.example.com")], "dns_configuration_error"),
])
def test_null_mx(records, status):
    resolver, raw = resolver_for({("example.com", "MX"): records})
    result = resolver.resolve_mx("example.com", 2)
    assert result["status"] == status
    assert result["selected"] == []
    assert len(result["records"]) == len(records)
    assert [(host, kind) for host, kind, *_ in raw.calls] == [("example.com", "MX")]


@pytest.mark.parametrize("error,status", [
    (dns.resolver.NXDOMAIN(), "domain_not_found"),
    (dns.exception.Timeout(), "inconclusive"),
    (dns.resolver.NoNameservers(), "inconclusive"),
])
def test_dns_errors_never_fall_back(error, status):
    resolver, raw = resolver_for({("example.com", "MX"): error})
    result = resolver.resolve_mx("example.com", 2)
    assert result["status"] == status
    assert result["selected"] == []
    assert [(host, kind) for host, kind, *_ in raw.calls] == [("example.com", "MX")]


def test_no_mx_uses_implicit_domain_and_resolves_a_aaaa():
    resolver, raw = resolver_for({
        ("example.com", "MX"): dns.resolver.NoAnswer(),
        ("example.com", "A"): [address("192.0.2.1")],
        ("example.com", "AAAA"): [address("2001:db8::1")],
    })
    result = resolver.resolve_mx("example.com", 2)
    assert result["status"] == "ready"
    assert result["selected"] == [{"host": "example.com", "preference": 0, "implicit": True}]
    addresses = resolver.resolve_addresses("example.com")
    assert {item["ip"] for item in addresses} == {"192.0.2.1", "2001:db8::1"}
    assert {item["family"] for item in addresses} == {"IPv4", "IPv6"}


def test_mx_sorted_deduplicated_before_limit_and_preserved():
    records = [mx(30, "third.example.com"), mx(10, "first.example.com"), mx(20, "second.example.com"), mx(10, "FIRST.EXAMPLE.COM")]
    resolver, _ = resolver_for({("example.com", "MX"): records})
    result = resolver.resolve_mx("example.com", 2)
    assert [item["host"] for item in result["selected"]] == ["first.example.com", "second.example.com"]
    assert len(result["records"]) == 4
    assert [item["host"] for item in result["skipped"]] == ["third.example.com"]


def test_equal_preference_order_is_randomized_and_then_recorded(monkeypatch):
    shuffled = []

    class ReverseRandom:
        def shuffle(self, values):
            shuffled.append(True)
            values.reverse()

    monkeypatch.setattr(probe_dns.secrets, "SystemRandom", ReverseRandom)
    resolver, _ = resolver_for({("example.com", "MX"): [
        mx(10, "first.example.com"), mx(10, "second.example.com"), mx(5, "priority.example.com"),
    ]})
    result = resolver.resolve_mx("example.com", 3)
    assert shuffled == [True]
    assert [item["host"] for item in result["selected"]] == ["priority.example.com", "second.example.com", "first.example.com"]


def test_address_lookup_failure_is_not_recipient_failure():
    resolver, _ = resolver_for({("mx.example.com", "A"): dns.resolver.NoNameservers()})
    with pytest.raises(DNSFailure):
        resolver.resolve_addresses("mx.example.com")


def test_available_address_survives_other_family_failure():
    resolver, _ = resolver_for({
        ("mx.example.com", "A"): [address("192.0.2.1")],
        ("mx.example.com", "AAAA"): dns.exception.Timeout(),
    })
    assert resolver.resolve_addresses("mx.example.com") == [{"ip": "192.0.2.1", "family": "IPv4"}]


def host_result(mx_record, code, text, control_code=550, control_text="5.1.1 Unknown"):
    target = common.classify_reply(code, text)
    control = common.classify_reply(control_code, control_text)
    status, explanation = common.derive_host_result(target, control)
    return {**mx_record, "target": target, "control": control, "status": status,
            "explanation": explanation, "ip": "192.0.2.1", "address_family": "IPv4",
            "tls": "unavailable", "phase": "quit", "failure_stage": None,
            "error": None, "cleanup": {}, "transcript": []}


def two_mx_resolver():
    return FakeResolver({
        ("example.com", "MX"): [mx(10, "first.example.com"), mx(20, "second.example.com")],
        ("first.example.com", "A"): [address("192.0.2.1")],
        ("second.example.com", "A"): [address("192.0.2.2")],
    })


def test_controls_reused_across_hosts_and_json_core_fields():
    control = common.make_control("auto", "Target@example.com")
    controls = []

    def probe(mx_record, addresses, settings, deadline):
        controls.append(settings["control"])
        return host_result(mx_record, 250, "Accepted")

    report = cli.run_probe(base_settings(control=control), resolver=two_mx_resolver(), host_probe=probe)
    assert controls == [control, control]
    assert report["status"] == "accepted_selectively"
    assert report["control"] == control
    assert len(report["hosts"]) == 2
    assert report["message_submitted"] is False
    assert report["ownership_verified"] is False
    assert report["schema_version"]
    assert report["timestamp_utc"].endswith(("Z", "+00:00"))
    assert report["duration_seconds"] >= 0


def test_cli_generates_exactly_one_auto_control_for_all_hosts(monkeypatch):
    generated = []
    seen = []
    actual_run = cli.run_probe

    def token_hex(size):
        generated.append(size)
        return "a1" * size

    def probe(record, addresses, settings, deadline):
        seen.append(settings["control"])
        return host_result(record, 250, "Accepted")

    monkeypatch.setattr(common.secrets, "token_hex", token_hex)
    monkeypatch.setattr(cli, "run_probe", lambda settings: actual_run(settings, resolver=two_mx_resolver(), host_probe=probe))
    assert invoke(BASE_ARGS + ["--timeout", "5"]) == 0
    assert generated == [16]
    assert seen == ["probe-nonexistent-" + "a1" * 16 + "@example.com"] * 2


def test_acceptance_and_permanent_target_rejection_are_mixed():
    def probe(mx_record, addresses, settings, deadline):
        return host_result(mx_record, 250, "Accepted") if mx_record["preference"] == 10 else host_result(mx_record, 550, "5.7.1 Policy")

    report = cli.run_probe(base_settings(), resolver=two_mx_resolver(), host_probe=probe)
    assert report["status"] == "mixed"
    assert len(report["hosts"]) == 2


def test_stronger_observation_with_unresolved_mx_flags_incomplete_coverage():
    raw = two_mx_resolver()
    raw.answers[("second.example.com", "A")] = dns.exception.Timeout()
    report = cli.run_probe(base_settings(), resolver=raw,
                           host_probe=lambda record, *_: host_result(record, 250, "Accepted"))
    assert report["status"] == "accepted_selectively"
    assert report["incomplete_coverage"] is True
    assert report["coverage_notes"]


def test_unavailability_and_unresolved_mx_are_inconclusive():
    raw = two_mx_resolver()
    raw.answers[("second.example.com", "A")] = dns.exception.Timeout()
    report = cli.run_probe(base_settings(), resolver=raw,
                           host_probe=lambda record, *_: host_result(record, 550, "5.1.1 Unknown"))
    assert report["status"] == "inconclusive"


def test_explicit_mx_failure_never_uses_domain_web_address():
    raw = FakeResolver({("example.com", "MX"): [mx(10, "mx.example.com")]})
    report = cli.run_probe(base_settings(), resolver=raw, host_probe=forbidden)
    assert report["status"] == "inconclusive"
    assert ("example.com", "A") not in [(host, kind) for host, kind, *_ in raw.calls]
    assert ("example.com", "AAAA") not in [(host, kind) for host, kind, *_ in raw.calls]


def test_max_mx_skips_are_reported():
    report = cli.run_probe(base_settings(max_mx=1), resolver=two_mx_resolver(),
                           host_probe=lambda record, *_: host_result(record, 250, "Accepted"))
    assert len(report["hosts"]) == 1
    assert [item["host"] for item in report["skipped_hosts"]] == ["second.example.com"]
    assert report["incomplete_coverage"] is True


def test_deadline_preserves_observation_and_records_skipped_host():
    def probe(record, addresses, settings, deadline):
        result = host_result(record, 250, "Accepted")
        deadline.end = deadline.started
        return result

    report = cli.run_probe(base_settings(), resolver=two_mx_resolver(), host_probe=probe)
    assert report["status"] == "accepted_selectively"
    assert len(report["hosts"]) == 1
    assert report["skipped_hosts"][0]["host"] == "second.example.com"
    assert report["skipped_hosts"][0]["reason"] == "deadline"
    assert report["incomplete_coverage"] is True


def test_invariant_failure_aborts_and_preserves_prior_observation():
    def probe(record, *_):
        if record["preference"] == 10:
            return host_result(record, 250, "Accepted")
        raise common.InvariantError("Prohibited command rejected before write")

    report = cli.run_probe(base_settings(), resolver=two_mx_resolver(), host_probe=probe)
    assert report["status"] == "internal_error"
    assert report["invariant_ok"] is False
    assert report["hosts"][0]["target"]["observation"] == "accepted"
    assert "Prohibited command" in report["internal_error"]


def test_write_failure_returns_three_and_preserves_existing_report(tmp_path, monkeypatch):
    path = tmp_path / "report.json"
    path.write_text("previous report", encoding="utf-8")

    def cannot_replace(*args):
        raise OSError("Simulated disk failure after probing")

    monkeypatch.setattr(cli.os, "replace", cannot_replace)
    assert invoke(BASE_ARGS + ["--dry-run", "--json", str(path)]) == 3
    assert path.read_text(encoding="utf-8") == "previous report"
    assert not list(tmp_path.glob(".smtp-probe-*.tmp"))


def test_terminal_control_information_is_escaped():
    result = common.terminal_safe("server\x1b[31m\r\n\x00")
    assert "\x1b" not in result and "\r" not in result and "\n" not in result
    assert "\\x1b" in result and "\\r" in result and "\\n" in result

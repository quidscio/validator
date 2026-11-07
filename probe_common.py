"""Validation, clocks, and deliberately conservative result interpretation."""
from __future__ import annotations

import ipaddress
import math
import re
import secrets
import time


class DeadlineExceeded(TimeoutError):
    """The invocation's wall-clock budget has expired."""


class InvariantError(RuntimeError):
    """An attempted operation violated the no-submission boundary."""


class Deadline:
    def __init__(self, seconds: float, timeout: float):
        self.started = time.monotonic()
        self.end = self.started + seconds
        self.timeout = timeout

    def remaining(self) -> float:
        return max(0.0, self.end - time.monotonic())

    def budget(self) -> float:
        remaining = self.remaining()
        if remaining <= 0:
            raise DeadlineExceeded("Overall deadline exceeded")
        return min(self.timeout, remaining)

    def operation_end(self) -> float:
        return time.monotonic() + self.budget()


def ascii_input(value: str, field: str) -> str:
    if not value or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise ValueError(f"{field} must contain printable ASCII without spaces or controls")
    return value


def domain_name(value: str, field: str = "domain") -> str:
    ascii_input(value, field)
    value = value.removesuffix(".").lower()
    labels = value.split(".")
    if len(value) > 253 or not all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in labels
    ):
        raise ValueError(f"{field} must be an ASCII DNS name")
    return value


def email_address(value: str, field: str = "address") -> str:
    ascii_input(value, field)
    if value.count("@") != 1:
        raise ValueError(f"{field} must contain exactly one email address")
    local, domain = value.split("@")
    atom = r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+"
    if len(local) > 64 or not re.fullmatch(atom + r"(?:\." + atom + r")*", local):
        raise ValueError(f"{field} requires an ASCII dot-atom local part (no quotes/display names)")
    address = local + "@" + domain_name(domain, field + " domain")
    if len(address) > 254:
        raise ValueError(f"{field} exceeds the 256-byte SMTP path limit")
    return address


def helo_name(value: str) -> str:
    ascii_input(value, "HELO")
    if value.startswith("[") and value.endswith("]"):
        inside = value[1:-1]
        ipv6 = inside.lower().startswith("ipv6:")
        try:
            addr = ipaddress.ip_address(inside[5:] if ipv6 else inside)
        except ValueError as exc:
            raise ValueError("HELO contains an invalid IP address literal") from exc
        if (addr.version == 6) != ipv6 or "%" in inside:
            raise ValueError("An IPv6 HELO literal must use [IPv6:address] without a scope ID")
        return f"[IPv6:{addr}]" if ipv6 else f"[{addr}]"
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        name = domain_name(value, "HELO")
        if "." not in name:
            raise ValueError("HELO must be a fully qualified DNS name or an IP address literal")
        return name
    if "%" in value:
        raise ValueError("HELO IP literals cannot include a scope ID")
    return f"[IPv6:{addr}]" if addr.version == 6 else f"[{addr}]"


def positive_seconds(value: str) -> float:
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise ValueError("time limits must be finite and greater than zero")
    return number


def make_control(value: str, target: str) -> str | None:
    if value == "none":
        return None
    domain = target.split("@", 1)[1]
    if value == "auto":
        # Shrink the explanatory prefix for long domains; retain 128 random bits.
        room = min(64, 254 - len(domain) - 1)
        if room < 33:
            raise ValueError("Target domain is too long for a 128-bit control; use --control none or an explicit address")
        prefix = "probe-nonexistent-"[:max(0, room - 32)]
        control = prefix + secrets.token_hex(16) + "@" + domain
        while control == target:
            control = prefix + secrets.token_hex(16) + "@" + domain
        return control
    control = email_address(value, "control")
    if control.split("@", 1)[1] != domain or control == target:
        raise ValueError("Control must differ from the target and use the same domain")
    return control


def classify_reply(code: int, reply: str) -> dict:
    match = re.search(r"(?<![\d.])([245]\.\d{1,3}\.\d{1,3})(?![\d.])", reply)
    enhanced = match.group(1) if match else None
    if code == 250:
        observation = "accepted"
    elif code == 251:
        observation = "accepted_forwarding"
    elif 400 <= code < 500:
        observation = "temporary_failure"
    elif code == 550 and enhanced == "5.1.1":
        observation = "recipient_unavailable"
    elif 500 <= code < 600 and (
        (enhanced and enhanced.startswith("5.7."))
        or re.search(r"\b(policy|spam|blacklist|blocklist|access denied|relay(?:ing)? (?:access )?denied)\b", reply, re.I)
    ):
        observation = "policy_rejected"
    elif 500 <= code < 600:
        observation = "rejected_other"
    else:
        observation = "unexpected_response"
    return {"code": code, "enhanced_code": enhanced, "reply": reply, "observation": observation}


ACCEPTED = {"accepted", "accepted_forwarding"}


def derive_host_result(target: dict, control: dict) -> tuple[str, str]:
    target_obs = target.get("observation")
    control_obs = control.get("observation")
    if target_obs in ACCEPTED:
        if control_obs == "recipient_unavailable":
            return "accepted_selectively", "Target accepted; presumed nonexistent control returned 550/5.1.1. This server distinguished the recipients; ownership is unknown."
        if control_obs in ACCEPTED:
            return "accepted_unverified", "Both recipients accepted. Accept-all behavior or deferred validation is possible; a catch-all mailbox is not proven."
        return "accepted_unverified", "Target accepted, but the presumed nonexistent control did not establish recipient-specific acceptance."
    if target_obs == "recipient_unavailable":
        return "recipient_unavailable", "Target returned 550/5.1.1: unavailable or blocked on this server; nonexistence is not conclusively proven."
    return "inconclusive", "The tested path did not establish recipient-specific acceptance or recipient unavailability."


def overall_result(hosts: list[dict]) -> tuple[str, str]:
    accepted = any(h.get("target", {}).get("observation") in ACCEPTED for h in hosts)
    rejected = any(500 <= (h.get("target", {}).get("code") or 0) < 600 for h in hosts)
    if accepted and rejected:
        return "mixed", "Tested MX hosts disagree: target acceptance and permanent target rejection were both observed."
    if any(h["status"] == "accepted_selectively" for h in hosts):
        return "accepted_selectively", "At least one tested server distinguished the accepted target from the presumed nonexistent control; ownership remains unknown."
    if accepted:
        return "accepted_unverified", "At least one tested server accepted the target; recipient-specific acceptance remains unverified."
    if hosts and all(h["status"] == "recipient_unavailable" for h in hosts):
        return "recipient_unavailable", "Target unavailable or blocked (550/5.1.1) on all attempted paths; this does not conclusively prove nonexistence."
    return "inconclusive", "DNS, SMTP, policy, or network observations leave the recipient unresolved."


def terminal_safe(value: object) -> str:
    text = str(value)
    return "".join(c if 32 <= ord(c) < 127 else c.encode("unicode_escape").decode("ascii") for c in text)

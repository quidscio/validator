#!/usr/bin/env python3
"""Observe acceptance of one SMTP recipient without submitting a message."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import sysconfig
import tempfile
import time

from probe_common import (
    Deadline, DeadlineExceeded, InvariantError, email_address, helo_name,
    make_control, overall_result, positive_seconds, terminal_safe,
)


def message(text: str, *, error: bool = False, file=None) -> None:
    """Prefix every console line, including multiline help and diagnostics."""
    stream = file if file is not None else (sys.stderr if error else sys.stdout)
    prefix = "** " if error else ".. "
    for line in text.splitlines():
        print(prefix + terminal_safe(line), file=stream, flush=True)


class ConsoleParser(argparse.ArgumentParser):
    def _print_message(self, text, file=None):
        if text:
            message(text, error=file is sys.stderr, file=file)


def invalid_input(reason: object | None = None) -> None:
    message("Result: invalid_input", error=True)
    if reason is not None:
        message(f"Reason: {reason}", error=True)
    message("No network operations performed.")


class SingleValue(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        seen = getattr(namespace, "_seen_options", set())
        if self.dest in seen:
            parser.error(f"{option_string} may only be supplied once")
        seen.add(self.dest)
        namespace._seen_options = seen
        setattr(namespace, self.dest, values)


def parser() -> argparse.ArgumentParser:
    cli = ConsoleParser(description=__doc__, epilog="Acceptance does not verify ownership or final delivery. No email is submitted.")
    cli.add_argument("--symlink-cli", action="store_true", help="Link the installed command into ~/bin and exit; use this option alone.")
    cli.add_argument("--target", metavar="ADDRESS", action=SingleValue, help="Required for probing: single recipient.")
    cli.add_argument("--mail-from", metavar="ADDRESS", dest="sender", action=SingleValue, help="Required for probing: operator envelope sender.")
    cli.add_argument("--helo", metavar="NAME", action=SingleValue, help="Required for probing: client FQDN or IP literal.")
    cli.add_argument("--control", default="auto", metavar="auto|none|ADDRESS", action=SingleValue)
    cli.add_argument("--max-mx", type=int, choices=range(1, 4), default=2)
    cli.add_argument("--timeout", type=positive_seconds, default=15.0, metavar="SECONDS")
    cli.add_argument("--deadline", type=positive_seconds, default=120.0, metavar="SECONDS")
    cli.add_argument("--tls", choices=("auto", "required"), default="auto")
    cli.add_argument("--json", metavar="PATH")
    cli.add_argument("--dry-run", action="store_true")
    return cli


def symlink_cli() -> Path:
    """Expose this interpreter's installed command without depending on PATH."""
    name = "smtp-recipient-probe.exe" if os.name == "nt" else "smtp-recipient-probe"
    entrypoint = Path(sysconfig.get_path("scripts")) / name
    if not entrypoint.is_file() or not os.access(entrypoint, os.X_OK):
        raise FileNotFoundError(
            "The command is not installed in this Python environment. "
            "Run python -m pip install -e . from the project directory first."
        )
    # Resolve before examining/replacing the destination so invoking this option
    # through ~/bin can never turn the launcher into a symlink to itself.
    source = entrypoint.resolve(strict=True)
    destination = Path.home() / "bin" / name
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_symlink():
        if destination.readlink() == source:
            return destination
    elif destination.exists():
        raise FileExistsError(f"Refusing to replace an existing file or directory: {destination}")
    # Stage the new link first: a failed creation leaves the previous link intact.
    with tempfile.TemporaryDirectory(prefix=".smtp-probe-link-", dir=destination.parent) as temporary:
        link = Path(temporary) / name
        link.symlink_to(source)
        link.replace(destination)
    return destination


def validate_settings(args: argparse.Namespace) -> dict:
    target = email_address(args.target, "target")
    sender = email_address(args.sender, "mail-from")
    helo = helo_name(args.helo)
    control = make_control(args.control, target)
    # The guarded transport checks these again at the writing boundary.
    for command in (f"EHLO {helo}", f"MAIL FROM:<{sender}>", f"RCPT TO:<{target}>", f"RCPT TO:<{control or target}>"):
        if len(command.encode("ascii")) + 2 > 512:
            raise ValueError("SMTP command exceeds 512 octets including CRLF")
    return dict(target=target, sender=sender, helo=helo, control=control,
                control_mode=args.control if args.control in {"auto", "none"} else "explicit",
                max_mx=args.max_mx, timeout=args.timeout, deadline=args.deadline,
                tls=args.tls, dry_run=args.dry_run)


def empty_host(mx: dict, error: str, stage: str) -> dict:
    return dict(mx, ip=None, address_family=None, tls="not_attempted", phase=stage,
                target={"observation": "not_tested"}, control={"observation": "not_tested"},
                status="inconclusive", explanation=error, failure_stage=stage, error=error,
                cleanup={"closed": True, "rset": "not_attempted", "quit": "not_attempted"}, transcript=[])


def run_probe(settings: dict, resolver=None, host_probe=None) -> dict:
    deadline = Deadline(settings["deadline"], settings["timeout"])
    report = dict(schema_version="1.0", timestamp_utc=datetime.now(timezone.utc).isoformat(),
                  duration_seconds=0.0, target=settings["target"], sender=settings["sender"],
                  helo=settings["helo"], control=settings["control"], settings=settings.copy(),
                  dns={"records": [], "queries": []}, selected_mx=[], tested_hosts=[],
                  skipped_hosts=[], hosts=[], status="inconclusive", explanation="",
                  incomplete_coverage=False, coverage_notes=[], message_submitted=False,
                  ownership_verified=False, invariant_ok=True)
    if settings["dry_run"]:
        report.update(status="dry_run", explanation="Inputs validated. No DNS lookups or network connections performed.")
        report["planned_operations"] = [
            "Resolve MX through the system-configured resolver; use implicit A/AAAA only on MX NODATA.",
            f"Test at most {settings['max_mx']} distinct MX hosts sequentially on TCP port 25.",
            f"EHLO {settings['helo']}; STARTTLS when advertised; EHLO again after TLS.",
            f"MAIL FROM:<{settings['sender']}>; RCPT TO:<{settings['target']}>; RSET.",
        ]
        if settings["control"]:
            report["planned_operations"].append(f"Fresh MAIL transaction; RCPT TO:<{settings['control']}> (presumed nonexistent control); RSET.")
        report["planned_operations"].append("QUIT and close. Never submit message content or authenticate.")
        report["duration_seconds"] = time.monotonic() - deadline.started
        return report
    # Lazy imports keep a dry run usable without DNS initialization.
    from probe_dns import DNSResolver, DNSFailure
    from probe_smtp import probe_host
    import dns.exception
    host_probe = host_probe or probe_host
    dns_client = None
    try:
        dns_client = DNSResolver(deadline, resolver)
        routing = dns_client.resolve_mx(settings["target"].split("@", 1)[1], settings["max_mx"])
        report["dns"]["records"] = routing["records"]
        report["dns"]["status"] = routing["status"]
        report["dns"]["explanation"] = routing["explanation"]
        report["selected_mx"] = routing["selected"]
        report["skipped_hosts"] = routing["skipped"]
        if routing["status"] != "ready":
            report.update(status=routing["status"], explanation=routing["explanation"])
        else:
            for index, mx in enumerate(routing["selected"]):
                if deadline.remaining() <= 0:
                    report["skipped_hosts"].extend(dict(rest, reason="deadline") for rest in routing["selected"][index:])
                    break
                report["tested_hosts"].append(mx["host"])
                try:
                    try:
                        addresses = dns_client.resolve_addresses(mx["host"])
                    except (DNSFailure, dns.exception.DNSException, OSError, DeadlineExceeded) as exc:
                        host = empty_host(mx, str(exc)[:4096], "address_resolution")
                    else:
                        host = host_probe(mx, addresses, settings, deadline)
                except InvariantError as exc:
                    host = getattr(exc, "host_result", empty_host(mx, str(exc), "invariant"))
                    report["hosts"].append(host)
                    report["invariant_ok"] = False
                    report["internal_error"] = str(exc)[:4096]
                    report["skipped_hosts"].extend(dict(rest, reason="invariant_failure") for rest in routing["selected"][index + 1:])
                    break
                report["hosts"].append(host)
            report["status"], report["explanation"] = overall_result(report["hosts"])
    except (dns.exception.DNSException, OSError, DeadlineExceeded) as exc:
        report.update(status="inconclusive", explanation=f"DNS initialization failed: {str(exc)[:4096]}")
    except InvariantError as exc:
        report.update(invariant_ok=False, internal_error=str(exc)[:4096])
    except Exception as exc:
        # Preserve observations and fail closed on unexpected implementation errors.
        report.update(invariant_ok=False, internal_error=f"{type(exc).__name__}: {str(exc)[:4096]}")
    finally:
        if dns_client is not None:
            report["dns"]["queries"] = dns_client.queries
        report["duration_seconds"] = time.monotonic() - deadline.started
    if not report["invariant_ok"]:
        report.update(status="internal_error", explanation="Probe aborted due to an internal error; inspect diagnostics. No clean success assertion is made.")
    notes = report["coverage_notes"]
    for host in report["skipped_hosts"]:
        notes.append(f"{host['host']} skipped: {host['reason']}.")
    for host in report["hosts"]:
        if host["status"] == "inconclusive" or host.get("failure_stage"):
            notes.append(f"{host['host']}: incomplete observation ({host.get('failure_stage') or 'unresolved recipient response'}).")
        if settings["control"] and host.get("control", {}).get("observation") == "not_tested":
            notes.append(f"{host['host']}: presumed nonexistent control was not tested.")
    if report["status"] == "inconclusive" and not report["hosts"]:
        notes.append("No SMTP recipient observation was obtained.")
    report["incomplete_coverage"] = bool(notes)
    return report


def prepare_output(path: str) -> tuple[Path, Path]:
    destination = Path(path).expanduser().absolute()
    if destination.exists():
        if not destination.is_file():
            raise ValueError("JSON output must be a file")
        # Verify access without truncating the old report.
        fd = os.open(destination, os.O_WRONLY)
        os.close(fd)
    fd, name = tempfile.mkstemp(prefix=".smtp-probe-", suffix=".tmp", dir=destination.parent)
    os.close(fd)
    return destination, Path(name)


def print_report(report: dict) -> None:
    execution_error = (
        not report["invariant_ok"]
        or report["status"] == "dns_configuration_error"
        or (report["status"] == "inconclusive" and not report["hosts"])
    )
    message(f"Target: {report['target']}")
    message(f"Result: {report['status']}", error=execution_error)
    message(f"Meaning: {report['explanation']}", error=execution_error)
    if report.get("internal_error"):
        message(f"Internal error: {report['internal_error']}", error=True)
    for host in report["hosts"]:
        message(f"MX {host['host']}: {host['status']} (TLS: {host['tls']})")
        message(f"  Meaning: {host['explanation']}")
        for recipient in ("target", "control"):
            observation = host.get(recipient, {})
            if observation.get("code") is not None:
                reply = str(observation.get("reply", ""))
                if not reply.startswith(str(observation["code"])):
                    reply = f"{observation['code']} {reply}"
                message(f"  {recipient}: {terminal_safe(reply)}")
        if host.get("error"):
            message(f"  Diagnostic: {host['error']}", error=True)
    for note in report.get("coverage_notes", []):
        message(f"Coverage: {note}")
    for step in report.get("planned_operations", []):
        message(f"Plan: {step}")
    if report["invariant_ok"]:
        message("Message submitted: no")
    else:
        message("Command invariant: internal error; review the transcript.", error=True)
    message("Ownership verified: no")


def main(argv: list[str] | None = None) -> int:
    try:
        from smtp_probe_build import BUILD_TIMESTAMP
    except ImportError:
        message("Build metadata missing. Install from the project directory with: python -m pip install -e .", error=True)
        return 3
    print(f"== smtp-recipient-probe {BUILD_TIMESTAMP}", flush=True)
    temporary = None
    try:
        try:
            arguments = list(sys.argv[1:] if argv is None else argv)
            cli = parser()
            args = cli.parse_args(arguments)
            if args.symlink_cli:
                if len(arguments) != 1:
                    cli.error("--symlink-cli must be used alone")
            else:
                missing = [flag for flag, value in (("--target", args.target), ("--mail-from", args.sender), ("--helo", args.helo)) if value is None]
                if missing:
                    cli.error("the following arguments are required for probing: " + ", ".join(missing))
        except SystemExit as exc:
            if exc.code:
                invalid_input()
            return int(exc.code)
        if args.symlink_cli:
            try:
                destination = symlink_cli()
            except (OSError, RuntimeError) as exc:
                message(f"Could not create CLI symlink: {exc}", error=True)
                return 3
            message(f"CLI symlink ready: {destination} -> {destination.readlink()}")
            message("Ensure ~/bin is on PATH to run smtp-recipient-probe without activating the environment.")
            return 0
        try:
            settings = validate_settings(args)
        except ValueError as exc:
            invalid_input(exc)
            return 2
        if args.json:
            try:
                destination, temporary = prepare_output(args.json)
            except ValueError as exc:
                invalid_input(exc)
                return 2
            except OSError as exc:
                message(f"Could not prepare JSON report: {exc}", error=True)
                message("No network operations performed.")
                return 3
        try:
            report = run_probe(settings)
        except ImportError as exc:
            message(f"Dependency missing: {exc}. Install with: python -m pip install -e .", error=True)
            return 3
        print_report(report)
        if temporary is not None:
            try:
                temporary.write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
                os.replace(temporary, destination)
                temporary = None
            except OSError as exc:
                message(f"Could not write JSON report: {exc}", error=True)
                return 3
        return 0 if report["invariant_ok"] else 3
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())

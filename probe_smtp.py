"""Small, guarded SMTP dialogue. There is intentionally no submission capability."""

from __future__ import annotations

import ipaddress
import re
import socket
import ssl
import time
from typing import Any

from probe_common import (
    Deadline,
    DeadlineExceeded,
    InvariantError,
    classify_reply,
    derive_host_result,
    email_address,
    helo_name,
)

ALLOWED_COMMANDS = frozenset({"EHLO", "HELO", "STARTTLS", "MAIL", "RCPT", "RSET", "QUIT"})
MAX_REPLY_BYTES = 16384
MAX_REPLY_LINES = 32
MAX_LINE_BYTES = 512


class ProtocolError(Exception):
    """The response cannot safely be followed by another SMTP command."""


def _command_bytes(command: str, argument: str = "") -> bytes:
    """The only route from application commands to bytes written on the socket."""
    if command not in ALLOWED_COMMANDS:
        raise InvariantError(f"Prohibited SMTP command: {command!r}")
    if not isinstance(argument, str) or any(ord(c) < 32 or ord(c) > 126 for c in argument):
        raise InvariantError("Non-ASCII or control character in SMTP command")
    if command in {"STARTTLS", "RSET", "QUIT"} and argument:
        raise InvariantError(f"{command} takes no argument")
    if command in {"EHLO", "HELO"}:
        try:
            helo_name(argument)
        except ValueError as exc:
            raise InvariantError("Invalid SMTP greeting identity") from exc
    if command in {"MAIL", "RCPT"}:
        prefix = "FROM:<" if command == "MAIL" else "TO:<"
        if not argument.startswith(prefix) or not argument.endswith(">"):
            raise InvariantError("Only a single bracketed envelope address is permitted")
        address = argument[len(prefix):-1]
        try:
            email_address(address)
        except ValueError as exc:
            raise InvariantError("Invalid envelope address at command boundary") from exc
    wire = (command + (" " + argument if argument else "") + "\r\n").encode("ascii")
    if len(wire) > 512:
        raise InvariantError("SMTP command exceeds 512 octets")
    return wire


class GuardedSMTP:
    """A connected transport with exactly one guarded command-writing boundary.

    Public raw-write and message-submission methods fail before touching the
    socket. No body is ever constructed. A reply's entire read shares a single
    operation deadline, so a slow multiline response cannot renew the timeout.
    """

    def __init__(self, sock: Any, deadline: Deadline, transcript: list[dict]):
        self.__socket = sock
        self.deadline = deadline
        self.transcript = transcript
        self.__buffer = bytearray()
        self.closed = False

    def _at(self) -> float:
        return round(time.monotonic() - self.deadline.started, 6)

    def _timeout(self, end: float) -> None:
        remaining = self.deadline.remaining()
        if remaining <= 0:
            raise DeadlineExceeded("Overall deadline expired")
        budget = min(remaining, end - time.monotonic())
        if budget <= 0:
            raise TimeoutError("SMTP operation timed out")
        self.__socket.settimeout(budget)

    def command(self, command: str, argument: str = "") -> tuple[int, str]:
        # Validate BEFORE recording a sent command or performing a socket write.
        wire = _command_bytes(command, argument)
        end = self.deadline.operation_end()
        self._timeout(end)
        entry = {"event": "command", "at_seconds": self._at(),
                 "command": command, "argument": argument, "write_state": "attempted"}
        self.transcript.append(entry)
        self.__socket.sendall(wire)
        entry["write_state"] = "completed"
        return self.read_reply(end)

    def read_reply(self, end: float | None = None) -> tuple[int, str]:
        end = self.deadline.operation_end() if end is None else end
        lines: list[bytes] = []
        total = 0
        code = None
        try:
            while True:
                while b"\n" not in self.__buffer:
                    self._timeout(end)
                    chunk = self.__socket.recv(512)
                    if not chunk:
                        raise ConnectionError("SMTP server disconnected")
                    self.__buffer.extend(chunk)
                    if len(self.__buffer) > MAX_REPLY_BYTES:
                        raise ProtocolError("SMTP reply exceeded storage bound")
                index = self.__buffer.index(b"\n") + 1
                line = bytes(self.__buffer[:index])
                del self.__buffer[:index]
                total += len(line)
                lines.append(line)
                if len(line) > MAX_LINE_BYTES or total > MAX_REPLY_BYTES or len(lines) > MAX_REPLY_LINES:
                    raise ProtocolError("SMTP reply exceeded line or storage bound")
                # RFC 5321 requires clients to tolerate an omitted space when
                # the final reply line has no text (for example b"250\r\n").
                if not re.fullmatch(rb"[2-5][0-9]{2}(?:[ -][^\r\n]*)?\r\n", line):
                    raise ProtocolError("Malformed SMTP reply")
                line_code = int(line[:3])
                if code is None:
                    code = line_code
                elif code != line_code:
                    raise ProtocolError("Multiline SMTP reply changed reply code")
                if line[3:4] != b"-":
                    reply = b"".join(lines).decode("utf-8", errors="backslashreplace").rstrip("\r\n")
                    self.transcript.append({"event": "response", "at_seconds": self._at(),
                                            "code": code, "reply": reply,
                                            "enhanced_code": classify_reply(code, reply)["enhanced_code"]})
                    # SMTP is sequential: unsolicited trailing response data is
                    # not allowed to masquerade as a future command's response.
                    if self.__buffer:
                        raise ProtocolError("Unsolicited bytes after SMTP reply")
                    return code, reply
        except Exception as exc:
            partial = (b"".join(lines) + bytes(self.__buffer))[:MAX_REPLY_BYTES]
            self.transcript.append({"event": "read_error", "at_seconds": self._at(),
                                    "error": str(exc),
                                    "partial_reply": partial.decode("utf-8", errors="backslashreplace")})
            raise

    def start_tls(self, hostname: str) -> None:
        end = self.deadline.operation_end()
        self._timeout(end)
        context = ssl.create_default_context()
        self.__socket = context.wrap_socket(self.__socket, server_hostname=hostname,
                                           do_handshake_on_connect=False)
        self._timeout(end)
        self.__socket.do_handshake()
        self.__buffer.clear()
        self.transcript.append({"event": "tls", "at_seconds": self._at(),
                                "state": "verified", "version": self.__socket.version()})

    def close(self) -> None:
        try:
            self.__socket.close()
        finally:
            self.closed = True

    def _prohibited(self, *_args: Any, **_kwargs: Any) -> None:
        raise InvariantError("Message submission, authentication, and raw writes are prohibited")

    send = _prohibited
    sendmail = _prohibited
    send_message = _prohibited
    data = _prohibited
    auth = _prohibited
    login = _prohibited


def _new_result(mx: dict, settings: dict) -> dict:
    return {"host": mx["host"], "preference": mx["preference"],
            "implicit": mx.get("implicit", False), "ip": None, "address_family": None,
            "tls": "not_attempted", "phase": "connect", "target": {"observation": "not_tested"},
            "control": {"observation": "not_tested" if settings.get("control") else "disabled"},
            "status": "inconclusive", "explanation": "No recipient response was observed.",
            "failure_stage": None, "error": None, "cleanup": {"closed": False},
            "transcript": [], "connection_attempts": []}


def probe_host(mx: dict, addresses: list[dict], settings: dict, deadline: Deadline) -> dict:
    """Probe one preselected MX, preserving replies even if later cleanup fails."""
    result = _new_result(mx, settings)
    client: GuardedSMTP | None = None
    usable = False
    transaction_open = False

    def failure(stage: str, error: str) -> None:
        if result["failure_stage"] is None:
            result["failure_stage"] = stage
            result["error"] = error

    def command(name: str, argument: str = "") -> tuple[int, str]:
        nonlocal usable
        assert client is not None
        try:
            reply = client.command(name, argument)
        except Exception:
            usable = False
            raise
        if reply[0] == 421:
            usable = False
        return reply

    def reset(label: str) -> bool:
        nonlocal usable, transaction_open
        result["phase"] = label
        try:
            code, text = command("RSET")
            result["cleanup"][label] = {"code": code, "reply": text,
                                         "enhanced_code": classify_reply(code, text)["enhanced_code"]}
            if code != 250:
                usable = False
                failure(label, "SMTP transaction reset failed; session closed")
                return False
            transaction_open = False
            return True
        except Exception as exc:
            result["cleanup"][label] = {"error": str(exc)}
            raise

    def transaction(label: str, address: str) -> None:
        nonlocal usable, transaction_open
        result["phase"] = f"{label}_mail"
        code, text = command("MAIL", f"FROM:<{settings['sender']}>")
        result.setdefault("mail_results", {})[label] = {
            "code": code, "reply": text, "enhanced_code": classify_reply(code, text)["enhanced_code"]}
        if code != 250:
            failure(result["phase"], f"Envelope sender rejected before {label} RCPT: {code}")
            if not (400 <= code <= 599):
                usable = False
            return
        transaction_open = True
        result["phase"] = f"{label}_rcpt"
        code, text = command("RCPT", f"TO:<{address}>")
        result[label] = classify_reply(code, text)
        if code == 421:
            failure(result["phase"], "Server sent 421 and closed the SMTP session")
        if code not in (250, 251) and not 400 <= code <= 599:
            usable = False
            failure(result["phase"], "Unexpected RCPT response; session closed without further commands")

    try:
        for address in addresses:
            deadline.budget()
            ip = ipaddress.ip_address(address["ip"])
            family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
            sock = socket.socket(family, socket.SOCK_STREAM)
            try:
                sock.settimeout(deadline.budget())
                endpoint = (str(ip), 25, 0, 0) if ip.version == 6 else (str(ip), 25)
                sock.connect(endpoint)
                result["connection_attempts"].append({"ip": str(ip), "connected": True})
                result["ip"] = str(ip)
                result["address_family"] = "IPv6" if ip.version == 6 else "IPv4"
                client = GuardedSMTP(sock, deadline, result["transcript"])
                break
            except (OSError, DeadlineExceeded) as exc:
                sock.close()
                result["connection_attempts"].append({"ip": str(ip), "connected": False, "error": str(exc)})
                if isinstance(exc, DeadlineExceeded):
                    raise
        if client is None:
            failure("connect", "No resolved MX address accepted a TCP connection on port 25")
            return result

        result["phase"] = "greeting"
        code, text = client.read_reply()
        if code != 220:
            failure("greeting", f"Expected SMTP 220 greeting; received {code}")
            return result
        usable = True
        result["phase"] = "ehlo"
        code, text = command("EHLO", settings["helo"])
        esmtp = code == 250
        if code in (500, 502, 504):
            result["phase"] = "helo"
            code, text = command("HELO", settings["helo"])
        if code != 250:
            if not 400 <= code <= 599:
                usable = False
            failure(result["phase"], f"SMTP greeting identity was not accepted: {code}")
            return result

        advertised = esmtp and any(re.match(r"^250[- ]STARTTLS(?:\s|$)", line, re.I)
                                  for line in text.splitlines())
        if advertised:
            result["phase"] = "starttls"
            code, text = command("STARTTLS")
            if code != 220:
                result["tls"] = "tls_error"
                usable = False
                failure("starttls", f"Advertised STARTTLS was rejected: {code}")
                return result
            # After STARTTLS the old plaintext protocol state cannot be reused.
            usable = False
            result["phase"] = "tls_handshake"
            result["tls"] = "tls_error"
            client.start_tls(mx["host"])
            result["tls"] = "verified"
            usable = True
            result["phase"] = "ehlo_after_tls"
            code, text = command("EHLO", settings["helo"])
            if code != 250:
                if not 400 <= code <= 599:
                    usable = False
                failure(result["phase"], f"Post-TLS EHLO failed: {code}")
                return result
        else:
            result["tls"] = "unavailable"
            if settings["tls"] == "required":
                failure("starttls", "STARTTLS is required but was not advertised")
                return result

        transaction("target", settings["target"])
        # A sender failure is not a reason to retry the same sender with control.
        if result["target"]["observation"] == "not_tested" or not usable:
            return result
        if not reset("target_rset"):
            return result
        if settings.get("control"):
            transaction("control", settings["control"])
            if usable and transaction_open:
                reset("control_rset")
    except InvariantError as exc:
        usable = False
        failure("invariant", str(exc))
        result["status"] = "invariant_failure"
        result["explanation"] = "The internal command invariant failed; the run must abort."
        exc.host_result = result
        raise
    except (DeadlineExceeded, TimeoutError, OSError, ProtocolError, ConnectionError) as exc:
        usable = False
        stage = "deadline" if isinstance(exc, DeadlineExceeded) or deadline.remaining() <= 0 else result["phase"]
        failure(stage, f"{type(exc).__name__}: {exc}")
    finally:
        if client is not None:
            try:
                if usable and deadline.remaining() > 0:
                    if transaction_open:
                        reset("final_rset")
                    if usable and deadline.remaining() > 0:
                        result["phase"] = "quit"
                        code, text = command("QUIT")
                        result["cleanup"]["quit"] = {
                            "code": code, "reply": text,
                            "enhanced_code": classify_reply(code, text)["enhanced_code"]}
                        if code != 221:
                            failure("quit", f"Unexpected QUIT response: {code}")
            except InvariantError as exc:
                failure("invariant", str(exc))
                result["status"] = "invariant_failure"
                result["explanation"] = "The internal command invariant failed; the run must abort."
                exc.host_result = result
                raise
            except (DeadlineExceeded, TimeoutError, OSError, ProtocolError, ConnectionError) as exc:
                failure(result["phase"], f"Cleanup failed: {type(exc).__name__}: {exc}")
                result["cleanup"]["error"] = str(exc)
            finally:
                try:
                    client.close()
                except OSError as exc:
                    failure("close", f"Socket close failed: {exc}")
                    result["cleanup"]["close_error"] = str(exc)
                result["cleanup"]["closed"] = client.closed
        else:
            result["cleanup"]["closed"] = True
        if result["status"] != "invariant_failure":
            result["status"], result["explanation"] = derive_host_result(result["target"], result["control"])
    return result

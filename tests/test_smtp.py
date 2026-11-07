"""All SMTP tests intercept the actual byte stream; none use public servers."""
import socket
import ssl
import threading
import time

import pytest

from probe_common import Deadline, InvariantError
import probe_smtp
from probe_smtp import ALLOWED_COMMANDS, GuardedSMTP, probe_host


MX = {"host": "mx.example.test", "preference": 10, "implicit": False}
ADDRESSES = [{"ip": "192.0.2.25", "family": "IPv4"}]
SETTINGS = {"target": "Target@example.test", "sender": "operator@sender.test",
            "control": "probe-nonexistent-0123456789abcdef0123456789abcdef@example.test",
            "helo": "client.sender.test", "tls": "auto", "timeout": 1}


class FakeSocket:
    def __init__(self, responses, *, greeting=b"220 mx.example.test ready\r\n", connect_error=None):
        self.responses = list(responses)
        self.pending = bytearray(greeting)
        self.writes = []
        self.closed = False
        self.endpoint = None
        self.connect_error = connect_error
        self.handshake_error = None
        self.receive_hook = None

    def settimeout(self, value):
        assert 0 < value <= 120

    def connect(self, endpoint):
        self.endpoint = endpoint
        if self.connect_error:
            raise self.connect_error

    def sendall(self, wire):
        # Every path checks the real byte stream, not just method invocation.
        assert wire.endswith(b"\r\n")
        assert wire.count(b"\r\n") == 1
        assert wire.split(b" ", 1)[0].strip().decode("ascii") in ALLOWED_COMMANDS
        assert len(wire) <= 512
        assert not self.pending
        self.writes.append(wire)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        self.pending.extend(response)

    def recv(self, amount):
        if self.receive_hook:
            self.receive_hook()
        chunk = self.pending[:amount]
        del self.pending[:amount]
        return bytes(chunk)

    def do_handshake(self):
        if self.handshake_error:
            raise self.handshake_error

    def version(self):
        return "TLSv1.3"

    def close(self):
        self.closed = True


@pytest.fixture
def run_session(monkeypatch):
    sockets = []

    def run(responses, *, settings=None, greeting=b"220 mx.example.test ready\r\n", deadline=None,
            configure=None):
        fake = FakeSocket(responses, greeting=greeting)
        sockets.append(fake)
        if configure:
            configure(fake)
        monkeypatch.setattr(socket, "socket", lambda *_args: fake)
        result = probe_host(MX, ADDRESSES, SETTINGS | (settings or {}), deadline or Deadline(10, 1))
        assert fake.closed
        assert result["cleanup"]["closed"]
        return result, fake

    yield run
    assert all(sock.closed for sock in sockets)


def replies(target=b"250 2.1.5 accepted\r\n", control=b"550 5.1.1 unavailable\r\n"):
    return [b"250 mx.example.test\r\n", b"250 2.1.0 sender accepted\r\n", target,
            b"250 reset\r\n", b"250 sender accepted\r\n", control,
            b"250 reset\r\n", b"221 goodbye\r\n"]


def test_selective_acceptance(run_session):
    result, fake = run_session(replies())
    assert result["status"] == "accepted_selectively"
    assert result["target"]["code"] == 250
    assert result["control"]["enhanced_code"] == "5.1.1"
    assert result["ip"] == "192.0.2.25"
    assert result["address_family"] == "IPv4"
    assert result["tls"] == "unavailable"
    assert fake.endpoint == ("192.0.2.25", 25)
    assert [x.split(b" ")[0].strip() for x in fake.writes] == [
        b"EHLO", b"MAIL", b"RCPT", b"RSET", b"MAIL", b"RCPT", b"RSET", b"QUIT"]


@pytest.mark.parametrize("control", [b"250 accepted\r\n", b"450 4.2.0 try later\r\n",
                                    b"550 5.7.1 policy rejection\r\n"])
def test_accepted_unverified(run_session, control):
    result, _ = run_session(replies(control=control))
    assert result["status"] == "accepted_unverified"
    if control.startswith(b"250"):
        assert "not proven" in result["explanation"]


def test_control_disabled(run_session):
    result, fake = run_session([b"250 mx\r\n", b"250 sender\r\n", b"250 target\r\n",
                                b"250 reset\r\n", b"221 bye\r\n"], settings={"control": None})
    assert result["status"] == "accepted_unverified"
    assert result["control"]["observation"] == "disabled"
    assert len([x for x in fake.writes if x.startswith(b"RCPT")]) == 1


@pytest.mark.parametrize("reply,observation,status", [
    (b"550 5.1.1 user unavailable\r\n", "recipient_unavailable", "recipient_unavailable"),
    (b"550 user unknown\r\n", "rejected_other", "inconclusive"),
    (b"550 5.7.1 prohibited\r\n", "policy_rejected", "inconclusive"),
    (b"450 4.2.0 later\r\n", "temporary_failure", "inconclusive"),
    (b"251 2.1.5 forward to <elsewhere@else.test>\r\n", "accepted_forwarding", "accepted_selectively"),
    (b"551 5.1.6 use elsewhere@else.test\r\n", "rejected_other", "inconclusive"),
    (b"553 5.1.3 syntax\r\n", "rejected_other", "inconclusive"),
    (b"550 5.2.1 mailbox disabled\r\n", "rejected_other", "inconclusive"),
])
def test_rcpt_classification_and_no_forwarding(run_session, reply, observation, status):
    result, fake = run_session(replies(target=reply))
    assert result["target"]["observation"] == observation
    assert result["status"] == status
    assert b"elsewhere" not in b"".join(fake.writes)
    if status == "recipient_unavailable":
        assert "blocked" in result["explanation"]


def test_421_stops_session(run_session):
    result, fake = run_session([b"250 mx\r\n", b"250 sender\r\n", b"421 4.3.2 closing\r\n"])
    assert result["target"]["observation"] == "temporary_failure"
    assert result["control"]["observation"] == "not_tested"
    assert len(fake.writes) == 3


def test_sender_rejection_does_not_issue_rcpt(run_session):
    result, fake = run_session([b"250 mx\r\n", b"550 5.7.1 sender blocked\r\n", b"221 bye\r\n"])
    assert result["target"]["observation"] == "not_tested"
    assert result["failure_stage"] == "target_mail"
    assert not any(x.startswith(b"RCPT") for x in fake.writes)


@pytest.mark.parametrize("ehlo", [b"500 unsupported\r\n", b"502 unsupported\r\n", b"504 unsupported\r\n"])
def test_helo_only_for_explicitly_unsupported_ehlo(run_session, ehlo):
    result, fake = run_session([ehlo, b"250 helo\r\n"] + replies()[1:])
    assert result["status"] == "accepted_selectively"
    assert fake.writes[1].startswith(b"HELO")


@pytest.mark.parametrize("ehlo", [b"450 later\r\n", b"550 5.7.1 blocked\r\n"])
def test_ehlo_rejection_never_falls_back(run_session, ehlo):
    result, fake = run_session([ehlo, b"221 bye\r\n"])
    assert result["status"] == "inconclusive"
    assert [x.split(b" ")[0].strip() for x in fake.writes] == [b"EHLO", b"QUIT"]


def test_starttls_refreshes_ehlo(monkeypatch, run_session):
    called = []

    class Context:
        def wrap_socket(self, sock, **kwargs):
            called.append(kwargs)
            return sock

    monkeypatch.setattr(ssl, "create_default_context", lambda: Context())
    result, fake = run_session([b"250-mx\r\n250 STARTTLS\r\n", b"220 go ahead\r\n"] + replies())
    assert result["status"] == "accepted_selectively"
    assert result["tls"] == "verified"
    assert called == [{"server_hostname": MX["host"], "do_handshake_on_connect": False}]
    assert [x.split(b" ")[0].strip() for x in fake.writes[:3]] == [b"EHLO", b"STARTTLS", b"EHLO"]


def test_certificate_failure_never_retries_plaintext(monkeypatch, run_session):
    class Context:
        def wrap_socket(self, sock, **kwargs):
            sock.handshake_error = ssl.SSLCertVerificationError("untrusted certificate")
            return sock

    monkeypatch.setattr(ssl, "create_default_context", lambda: Context())
    result, fake = run_session([b"250-mx\r\n250 STARTTLS\r\n", b"220 go ahead\r\n"])
    assert result["tls"] == "tls_error"
    assert result["failure_stage"] == "tls_handshake"
    assert len(fake.writes) == 2
    assert result["target"]["observation"] == "not_tested"


def test_required_tls_unavailable(run_session):
    result, fake = run_session([b"250 mx\r\n", b"221 bye\r\n"], settings={"tls": "required"})
    assert result["failure_stage"] == "starttls"
    assert not any(x.startswith(b"MAIL") for x in fake.writes)


@pytest.mark.parametrize("cleanup", [b"500 cannot reset\r\n", b"", TimeoutError("timeout")])
def test_cleanup_failure_preserves_target(run_session, cleanup):
    result, fake = run_session([b"250 mx\r\n", b"250 sender\r\n", b"250 target\r\n", cleanup])
    assert result["target"]["observation"] == "accepted"
    assert result["status"] == "accepted_unverified"
    assert result["control"]["observation"] == "not_tested"
    assert len(fake.writes) == 4


def test_quit_failure_preserves_both_recipients(run_session):
    result, _ = run_session(replies()[:-1] + [b""])
    assert result["status"] == "accepted_selectively"
    assert result["failure_stage"] == "quit"


@pytest.mark.parametrize("response", [b"garbage\r\n", b"250-one\r\n550 other\r\n",
                                    b"250 " + b"x" * 600 + b"\r\n",
                                    b"250 " + b"x" * 17000,
                                    b"250 okay\r\n250 unsolicited\r\n"])
def test_protocol_failure_closes_without_followup(run_session, response):
    result, fake = run_session([response])
    assert result["status"] == "inconclusive"
    assert result["failure_stage"] == "ehlo"
    assert len(fake.writes) == 1
    assert len(result["transcript"][-1].get("partial_reply", "")) <= 16384


def test_unexpected_252_is_not_acceptance(run_session):
    result, fake = run_session([b"250 mx\r\n", b"250 sender\r\n", b"252 cannot verify\r\n"])
    assert result["target"]["observation"] == "unexpected_response"
    assert result["status"] == "inconclusive"
    assert len(fake.writes) == 3


def test_deadline_preserves_target(run_session):
    deadline = Deadline(10, 1)

    def configure(fake):
        def hook():
            if len(fake.writes) == 3:
                deadline.end = time.monotonic() - 1
        fake.receive_hook = hook

    result, fake = run_session(replies(), deadline=deadline, configure=configure)
    assert result["target"]["observation"] == "accepted"
    assert result["control"]["observation"] == "not_tested"
    assert result["failure_stage"] == "deadline"
    assert len(fake.writes) == 3


def test_slow_multiline_uses_one_operation_deadline(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(time, "monotonic", lambda: now[0])
    deadline = Deadline(120, 1)
    fake = FakeSocket([], greeting=b"250-first\r\n250-second\r\n250 done\r\n")
    original_recv = fake.recv

    def slow_recv(_amount):
        now[0] += .4
        return original_recv(10)

    fake.recv = slow_recv
    client = GuardedSMTP(fake, deadline, [])
    with pytest.raises(TimeoutError):
        client.read_reply()
    client.close()
    assert now[0] < 2


@pytest.mark.parametrize("command,argument", [
    ("DATA", ""), ("BDAT", "0 LAST"), ("BURL", "imap://host"), ("AUTH", "PLAIN"),
    ("VRFY", "name"), ("NOOP", ""), ("MAIL", "FROM:<a@b.test>\r\nDATA"),
    ("RCPT", "TO:<a@b.test>\x00"), ("EHLO", "client.test\nDATA"),
    ("RSET", "body"), ("QUIT", "\x1b"), ("MAIL", "FROM:<>"),
])
def test_prohibited_commands_write_no_bytes(command, argument):
    fake = FakeSocket([])
    client = GuardedSMTP(fake, Deadline(10, 1), [])
    with pytest.raises(InvariantError):
        client.command(command, argument)
    assert fake.writes == []
    client.close()


@pytest.mark.parametrize("method", ["send", "sendmail", "send_message", "data", "auth", "login"])
def test_submission_and_raw_write_methods_fail_before_write(method):
    fake = FakeSocket([])
    client = GuardedSMTP(fake, Deadline(10, 1), [])
    with pytest.raises(InvariantError):
        getattr(client, method)("payload")
    assert fake.writes == []
    client.close()


def test_tries_resolved_addresses_until_first_connection(monkeypatch):
    failed = FakeSocket([], connect_error=ConnectionRefusedError("refused"))
    success = FakeSocket(replies())
    sockets = iter([failed, success])
    monkeypatch.setattr(socket, "socket", lambda *_args: next(sockets))
    result = probe_host(MX, [{"ip": "2001:db8::25", "family": "IPv6"}] + ADDRESSES,
                        SETTINGS, Deadline(10, 1))
    assert failed.closed and success.closed
    assert result["ip"] == "192.0.2.25"
    assert len(result["connection_attempts"]) == 2


def test_invariant_failure_preserves_diagnostics_and_closes(monkeypatch):
    fake = FakeSocket([b"250 mx\r\n"])
    monkeypatch.setattr(socket, "socket", lambda *_args: fake)
    with pytest.raises(InvariantError) as caught:
        probe_host(MX, ADDRESSES, SETTINGS | {"sender": "x@sender.test\r\nDATA"}, Deadline(10, 1))
    assert fake.closed
    assert caught.value.host_result["status"] == "invariant_failure"
    assert len(fake.writes) == 1


def test_replies_without_text_are_valid(run_session):
    result, _ = run_session([b"250\r\n", b"250\r\n", b"250\r\n", b"250\r\n", b"221\r\n"],
                            settings={"control": None}, greeting=b"220\r\n")
    assert result["status"] == "accepted_unverified"


@pytest.mark.parametrize("reply", [b"354 unexpected data request\r\n", b"251 unexpected\r\n"])
def test_desynchronized_ehlo_does_not_attempt_cleanup(run_session, reply):
    result, fake = run_session([reply])
    assert result["status"] == "inconclusive"
    assert len(fake.writes) == 1


def test_advertised_starttls_rejection_does_not_continue_plaintext(run_session):
    result, fake = run_session([b"250-mx\r\n250 STARTTLS\r\n", b"454 TLS unavailable\r\n"])
    assert result["tls"] == "tls_error"
    assert len(fake.writes) == 2


def test_control_421_keeps_target_but_stops_cleanup(run_session):
    result, fake = run_session(replies()[:5] + [b"421 shutting down\r\n"])
    assert result["status"] == "accepted_unverified"
    assert result["control"]["observation"] == "temporary_failure"
    assert len(fake.writes) == 6


def test_bad_greeting_sends_no_commands(run_session):
    result, fake = run_session([], greeting=b"421 no service\r\n")
    assert result["failure_stage"] == "greeting"
    assert fake.writes == []


def test_all_connections_failed(monkeypatch):
    fake = FakeSocket([], connect_error=ConnectionRefusedError("port blocked"))
    monkeypatch.setattr(socket, "socket", lambda *_args: fake)
    result = probe_host(MX, ADDRESSES, SETTINGS, Deadline(10, 1))
    assert fake.closed
    assert result["status"] == "inconclusive"
    assert result["failure_stage"] == "connect"
    assert result["ip"] is None
    assert fake.writes == []


def test_expired_deadline_opens_no_socket(monkeypatch):
    deadline = Deadline(10, 1)
    deadline.end = time.monotonic() - 1
    monkeypatch.setattr(socket, "socket", lambda *_args: pytest.fail("Socket opened after deadline"))
    result = probe_host(MX, ADDRESSES, SETTINGS, deadline)
    assert result["failure_stage"] == "deadline"
    assert result["cleanup"]["closed"]


def test_close_error_keeps_observations(monkeypatch):
    fake = FakeSocket(replies())

    def close():
        fake.closed = True
        raise OSError("close error")

    fake.close = close
    monkeypatch.setattr(socket, "socket", lambda *_args: fake)
    result = probe_host(MX, ADDRESSES, SETTINGS, Deadline(10, 1))
    assert result["status"] == "accepted_selectively"
    assert result["cleanup"]["close_error"] == "close error"


def test_reply_storage_remains_bounded(run_session):
    result, fake = run_session([b"250-more\r\n" * 100])
    assert result["failure_stage"] == "ehlo"
    assert len(fake.writes) == 1
    assert len(result["transcript"][-1]["partial_reply"]) <= 16384


def test_transcript_keeps_terminal_control_escaped_for_json(run_session):
    result, _ = run_session(replies(target=b"250 2.1.5 accepted\x1b[31m\r\n"))
    assert "\x1b" in result["target"]["reply"]


def test_invariant_during_finally_preserves_target(monkeypatch):
    fake = FakeSocket(replies()[:-1])
    monkeypatch.setattr(socket, "socket", lambda *_args: fake)
    original = probe_smtp._command_bytes

    def reject_quit(command, argument=""):
        if command == "QUIT":
            raise InvariantError("simulated boundary invariant")
        return original(command, argument)

    monkeypatch.setattr(probe_smtp, "_command_bytes", reject_quit)
    with pytest.raises(InvariantError) as caught:
        probe_host(MX, ADDRESSES, SETTINGS, Deadline(10, 1))
    assert caught.value.host_result["target"]["observation"] == "accepted"
    assert caught.value.host_result["status"] == "invariant_failure"
    assert caught.value.host_result["cleanup"]["closed"]
    assert fake.closed


def test_full_session_on_local_socketpair(monkeypatch):
    """Exercise real kernel socket reads/writes without any public connection."""
    client_socket, server_socket = socket.socketpair()
    server_socket.settimeout(3)
    captured = []
    server_errors = []
    expected = [b"EHLO", b"MAIL", b"RCPT", b"RSET", b"MAIL", b"RCPT", b"RSET", b"QUIT"]

    def server():
        try:
            with server_socket:
                server_socket.sendall(b"220 local test peer\r\n")
                for verb, response in zip(expected, replies(), strict=True):
                    line = bytearray()
                    while not line.endswith(b"\r\n"):
                        byte = server_socket.recv(1)
                        if not byte:
                            raise AssertionError("Client disconnected before completing the dialogue")
                        line.extend(byte)
                        assert len(line) <= 512
                    captured.append(bytes(line))
                    assert line.split(b" ")[0].strip() == verb
                    server_socket.sendall(response)
        except BaseException as exc:
            server_errors.append(exc)

    class AlreadyConnectedSocket:
        def connect(self, endpoint):
            # The production connection endpoint is verified but never used:
            # socketpair already connects only the local test's two sockets.
            assert endpoint == ("192.0.2.25", 25)

        def __getattr__(self, name):
            return getattr(client_socket, name)

    worker = threading.Thread(target=server, daemon=True)
    worker.start()
    monkeypatch.setattr(socket, "socket", lambda *_args: AlreadyConnectedSocket())
    try:
        result = probe_host(MX, ADDRESSES, SETTINGS, Deadline(10, 2))
    finally:
        client_socket.close()
        worker.join(timeout=4)
        server_socket.close()
    assert not worker.is_alive()
    assert not server_errors
    assert result["status"] == "accepted_selectively"
    assert len(captured) == len(expected)
    assert all(line.split(b" ")[0].strip().decode() in ALLOWED_COMMANDS for line in captured)

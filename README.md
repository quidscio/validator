# SMTP recipient probe

A Python 3.11+ command-line tool for checking whether a domain's inbound SMTP server accepts one recipient. It ends before message submission: it never sends `DATA`, a message body, or authentication credentials. Receiving servers can see and log the probe.

Recipient acceptance is an observation about the tested server and time. It does **not** verify mailbox ownership, final delivery, inbox placement, or readership.

## Install in WSL

Open your WSL terminal and run:

```bash
cd /mnt/c/q/arc/projects/validator
python3 --version  # Must be 3.11 or newer.
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
smtp-recipient-probe --symlink-cli
deactivate
export PATH="$HOME/bin:$PATH"
smtp-recipient-probe --help
```

If Ubuntu reports that `venv` is missing, install the `python3-venv` package for your Python version first. Keep this WSL environment separate from a Windows virtual environment.

`--symlink-cli` is a one-time setup step after installation. It creates `~/bin/smtp-recipient-probe` pointing to the installed executable in the current Python environment. It requires no recipient arguments and performs no DNS lookups or SMTP connections. Run it on its own. Repeating it updates an existing symlink; it refuses to replace a regular file or directory.

With `~/bin` on your `PATH`, you can run `smtp-recipient-probe` from any directory without activating the environment. The `export` above applies to the current terminal. If your shell does not already include `~/bin`, add that same line to `~/.bashrc` for future Bash sessions.

If the environment is already installed, create the link from the project directory with:

```bash
.venv/bin/smtp-recipient-probe --symlink-cli
```

The editable installation (`pip install -e .`) uses source changes on the next run. Its banner retains the timestamp of the last package build in `America/New_York` time; to refresh that timestamp, run `.venv/bin/python -m pip install -e .` from the project directory. The link remains valid across updates at the same path. If you move the project or virtual environment, recreate the environment, reinstall the package, and rerun the link setup.

## Run

First try a dry run. This example uses reserved domains and performs **no DNS lookups or network connections**:

```bash
smtp-recipient-probe \
  --target recipient@example.com \
  --mail-from operator@example.net \
  --helo client.example.net \
  --dry-run
```

For a real probe, supply the email address to check, **your own envelope sender address**, and **your client FQDN** (or an SMTP IP literal such as `[192.0.2.1]` or `[IPv6:2001:db8::1]`). Replace all example values before running:

```bash
smtp-recipient-probe \
  --target recipient@example.com \
  --mail-from operator@example.net \
  --helo client.example.net \
  --json result.json
```

You can also enter the target at a terminal prompt while retaining the same sender and HELO arguments:

```bash
read -r -p 'Email to check: ' target
smtp-recipient-probe --target "$target" \
  --mail-from operator@example.net --helo client.example.net --json result.json
```

From the project directory, the script form works too: `.venv/bin/python smtp_recipient_probe.py` followed by the same arguments. No mailbox password is required. No addresses are hard-coded or probed during installation or testing.

| Argument | Meaning |
| --- | --- |
| `--symlink-cli` | Standalone setup command: create or update the launcher in `~/bin`, then exit. |
| `--target ADDRESS` | Required single recipient when probing. |
| `--mail-from ADDRESS` | Required operator-supplied envelope sender when probing. |
| `--helo NAME` | Required operator client FQDN or SMTP IP literal when probing. |
| `--control auto\|none\|ADDRESS` | Default `auto`: generate one random presumed nonexistent control in the target domain and reuse it across MX hosts. `none` disables it; an explicit control must be a different address in the same domain. |
| `--max-mx N` | Maximum distinct MX hosts, 1–3; default 2. |
| `--timeout SECONDS` | Per-operation timeout; default 15. |
| `--deadline SECONDS` | Total run deadline; default 120. |
| `--tls auto\|required` | Default `auto`: use STARTTLS when advertised; otherwise record plaintext. `required` stops before recipient testing when STARTTLS is unavailable. Certificate verification failures never cause a plaintext retry. |
| `--json PATH` | Also save the structured report, including per-host replies and command transcript. |
| `--dry-run` | Validate inputs and describe the plan without DNS or network activity. |

Only ordinary ASCII dot-atom email local parts and DNS domains are supported. Quoted local parts, internationalized addresses, display names, address lists, and control characters are rejected. Local-part case is preserved; domain case is normalized.

## Console output

Each invocation starts with `== smtp-recipient-probe YYYY-MM-DD_HH:MM`. The timestamp is recorded when the package is built, so it stays the same between runs. The following dry-run opening uses an illustrative build timestamp:

```text
== smtp-recipient-probe 2026-11-07_19:28
.. Target: recipient@example.com
.. Result: dry_run
.. Meaning: Inputs validated. No DNS lookups or network connections performed.
```

Normal messages, including help, launcher setup, and probe reports, start with `.. `. Execution-error messages start with `** `. A negative recipient result such as `recipient_unavailable` is a normal probe observation and uses `.. `; it does not itself mean the program failed to execute. These prefixes do not change JSON report data or exit codes.

## Interpret the result

- `accepted_selectively`: target accepted and the presumed nonexistent control returned `550 5.1.1`; stronger evidence of recipient-specific acceptance on that server.
- `accepted_unverified`: target accepted, but the control did not establish selective acceptance. If both are accepted, accept-all behavior or deferred validation is possible; a catch-all mailbox is not proven.
- `recipient_unavailable`: a target returned `550 5.1.1` without contradictory acceptance or an unresolved attempted host. The recipient may be unavailable **or blocked**; nonexistence is not established.
- `mixed`: tested servers disagree through acceptance versus permanent target rejection.
- `inconclusive`: DNS, network, TLS, sender, policy, temporary, or other unresolved failure. A generic `550` is not proof that the mailbox is nonexistent.
- `domain_no_mail`, `domain_not_found`, `dns_configuration_error`, or `invalid_input`: the corresponding pre-SMTP outcome.

Connections go directly to MX servers on TCP port 25. Outbound port 25 may be blocked by your network or provider; that produces an inconclusive result. The tool does not switch to submission ports, authenticated relays, or verification services. It records skipped hosts and incomplete coverage rather than claiming every server was checked.

The JSON report retains DNS records, selected/tested/skipped hosts, IP and address family, TLS state, SMTP and enhanced codes, bounded replies, cleanup results, and a timed transcript. `message_submitted` and `ownership_verified` are false. An internal command-guard failure aborts with diagnostics rather than reporting clean success.

| Exit code | Meaning |
| --- | --- |
| `0` | Launcher setup succeeded, or a report was produced (including an inconclusive result). Inspect report status; zero does not mean “valid email.” |
| `2` | Invalid arguments or unsupported input. |
| `3` | Launcher setup failed, an internal invariant failed, or the requested report could not be written. |

## Local tests

```bash
cd /mnt/c/q/arc/projects/validator
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pytest
```

Tests use mocked DNS and controlled local transports. They must never probe public SMTP servers. They exercise reply classification, TLS handling, DNS outcomes, deadlines, partial results, input validation, and the guarded outgoing command stream. The only permitted SMTP commands are `EHLO`, `HELO`, `STARTTLS`, `MAIL`, `RCPT`, `RSET`, and `QUIT`.

Linux and macOS use the same installation commands with their local project path. On native Windows, use Python 3.11+ to create a separate virtual environment and activate it with its `Scripts/Activate.ps1` file; skip the Unix symlink and PATH steps. No `telnet`, `nc`, or `openssl` executable is needed.

## References

- [SMTP commands, replies, and MX routing (RFC 5321)](https://www.rfc-editor.org/rfc/rfc5321.html)
- [Null MX and implicit MX fallback (RFC 7505)](https://www.rfc-editor.org/rfc/rfc7505.html)
- [dnspython resolver behavior](https://dnspython.readthedocs.io/en/stable/resolver-class.html)
- [Microsoft recipient filtering and blocked recipients](https://learn.microsoft.com/en-us/Exchange/antispam-and-antimalware/antispam-protection/recipient-filtering)

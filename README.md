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
# Create your private defaults file if it does not already exist.
cp -n smtp-recipient-probe.example.toml smtp-recipient-probe.toml
# Edit smtp-recipient-probe.toml with your sender and HELO values.
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

## Save sender and HELO defaults

For this editable installation, keep `smtp-recipient-probe.toml` beside the Python script in `/mnt/c/q/arc/projects/validator`. Start with `smtp-recipient-probe.example.toml`, then replace its fictional values:

```toml
[smtp]
mail_from = "operator@example.net"
helo = "client.example.net"
```

The private `smtp-recipient-probe.toml` is ignored by Git. Only the example file is committed. No mailbox password or other credentials belong in this file.

Without `--config`, the program checks for `smtp-recipient-probe.toml` in this order:

1. Beside the resolved executable launcher. For the `~/bin` symlink in this setup, that is `.venv/bin`.
2. Beside `smtp_recipient_probe.py`, which is the project folder for an editable installation.

The first existing file is used; the files are not merged. The current working directory is not searched, so the saved defaults work when you launch the command from another directory. To select a particular file instead of automatic discovery, use:

```bash
smtp-recipient-probe --config /path/to/private.toml \
  --target recipient@example.com --dry-run
```

An explicitly selected file must exist and be valid. Missing required identities or invalid configuration stop the command before networking. `--help` and standalone `--symlink-cli` do not read configuration.

You can also supply defaults through environment variables:

```bash
export SMTP_PROBE_MAIL_FROM='operator@example.net'
export SMTP_PROBE_HELO='client.example.net'
```

For each value, precedence is **command-line option > environment variable > config file**. For example, `--helo client.other.example.net` overrides the saved HELO while retaining the saved sender. The target is always supplied with `--target`; it is not taken from configuration.

## Run

After saving your defaults, the usual command needs only the target. First use `--dry-run` to validate arguments and defaults with **no DNS lookups or network connections**:

```bash
smtp-recipient-probe --target recipient@example.com --dry-run
```

To perform the probe, replace the example target with the address to check and omit `--dry-run`:

```bash
smtp-recipient-probe --target recipient@example.com --json result.json
```

Explicit identity arguments remain available. This dry-run example uses reserved domains and overrides any saved values:

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

You can also enter the target at a terminal prompt and use your saved defaults:

```bash
read -r -p 'Email to check: ' target
smtp-recipient-probe --target "$target" --json result.json
```

From the project directory, the script form works too: `.venv/bin/python smtp_recipient_probe.py` followed by the same arguments. No mailbox password is required. No addresses are hard-coded or probed during installation or testing.

| Argument                        | Meaning                                                                                                                                                                                                            |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `--symlink-cli`                 | Standalone setup command: create or update the launcher in `~/bin`, then exit.                                                                                                                                     |
| `--target ADDRESS`              | Required single recipient when probing.                                                                                                                                                                            |
| `--mail-from ADDRESS`           | Envelope sender; overrides `SMTP_PROBE_MAIL_FROM` and config `smtp.mail_from`. A value must be provided by one of these sources.                                                                                   |
| `--helo NAME`                   | Client FQDN or SMTP IP literal; overrides `SMTP_PROBE_HELO` and config `smtp.helo`. A value must be provided by one of these sources.                                                                              |
| `--config PATH`                 | Use this TOML file instead of automatic config discovery.                                                                                                                                                          |
| `--control auto\|none\|ADDRESS` | Default `auto`: generate one random presumed nonexistent control in the target domain and reuse it across MX hosts. `none` disables it; an explicit control must be a different address in the same domain.        |
| `--max-mx N`                    | Maximum distinct MX hosts, 1–3; default 2.                                                                                                                                                                         |
| `--timeout SECONDS`             | Per-operation timeout; default 15.                                                                                                                                                                                 |
| `--deadline SECONDS`            | Total run deadline; default 120.                                                                                                                                                                                   |
| `--tls auto\|required`          | Default `auto`: use STARTTLS when advertised; otherwise record plaintext. `required` stops before recipient testing when STARTTLS is unavailable. Certificate verification failures never cause a plaintext retry. |
| `--json PATH`                   | Also save the structured report, including per-host replies and command transcript.                                                                                                                                |
| `--dry-run`                     | Validate inputs and describe the plan without DNS or network activity.                                                                                                                                             |

Only ordinary ASCII dot-atom email local parts and DNS domains are supported. Quoted local parts, internationalized addresses, display names, address lists, and control characters are rejected. Local-part case is preserved; domain case is normalized.

## Console output

Each invocation starts with `== smtp-recipient-probe YYYY-MM-DD_HH:MM`. The timestamp is recorded when the package is built, so it stays the same between runs. The following dry-run excerpt uses an illustrative build timestamp:

```text
== smtp-recipient-probe 2026-11-07_19:28
.. Target: recipient@example.com
.. Result: dry_run
.. Meaning: Inputs validated. No DNS lookups or network connections performed.
```

Primary output starts with `.. `: the target, overall `Result` and `Meaning`, MX server headings, each server's `MX result` and `Meaning`, final submission/ownership statements, and launcher setup success. Supporting details start with `.... `: the control address, plans, individual target/control observations and SMTP replies, coverage notes, and usage guidance. Execution-error messages retain `** `, and the build banner retains `== `.

The report is printed after probing finishes. Within each MX server section, Test 1 shows the target and its SMTP reply before `Test 1 result`; Test 2 then does the same for the control before `Test 2 result`. The server's `MX result` and `Meaning` follow both checks. After all MX sections and any coverage notes or dry-run plans, the overall `Result` and `Meaning` appear, followed by the submission and ownership statements.

This simulated excerpt shows one MX section in that order:

```text
.. MX server 1/2: mx.example.com (TLS: verified)
.... Test 1 - target address you supplied: recipient@example.com
.... SMTP reply: 250 2.1.5 OK
.... Test 1 result: accepted
.... Test 2 - presumed nonexistent control: control@example.com
.... SMTP reply: 550 5.1.1 No such recipient
.... Test 2 result: recipient_unavailable
.. MX result: accepted_selectively
.. Meaning: Target accepted; presumed nonexistent control returned 550/5.1.1. This server distinguished the recipients; ownership is unknown.
```

A negative recipient result such as `recipient_unavailable` remains a normal probe observation: the overall or per-MX conclusion uses `.. `, while an individual check's result uses `.... `. It does not itself mean the program failed to execute. These prefixes do not change JSON report data or exit codes.

Each numbered **MX server** section reports two separate recipient checks:

1. **Test 1 — target:** check the address you supplied with `--target`.
2. **Test 2 — control:** check a presumed nonexistent comparison address. With the default `--control auto`, one random address is generated in the target's domain and reused across all tested MX servers.

The two checks use separate `MAIL`/`RCPT` transactions with the same sender. The server's responses are compared: an accepted target plus a control rejected with `550 5.1.1` produces `accepted_selectively`. No message is submitted in either transaction.

The default is **up to two MX servers**, each receiving the same pair of checks: **up to four recipient checks in total**. The server numbers identify where the checks ran; Test 1 and Test 2 identify which address was checked. `--control none` disables Test 2, and connection or session failures can prevent either check from running. Disabled and untested checks are explicitly labeled in the report.

## Interpret the result

- `accepted_selectively`: target accepted and the presumed nonexistent control returned `550 5.1.1`; stronger evidence of recipient-specific acceptance on that server.
- `accepted_unverified`: target accepted, but the control did not establish selective acceptance. If both are accepted, accept-all behavior or deferred validation is possible; a catch-all mailbox is not proven.
- `recipient_unavailable`: a target returned `550 5.1.1` without contradictory acceptance or an unresolved attempted host. The recipient may be unavailable **or blocked**; nonexistence is not established.
- `mixed`: tested servers disagree through acceptance versus permanent target rejection.
- `inconclusive`: DNS, network, TLS, sender, policy, temporary, or other unresolved failure. A generic `550` is not proof that the mailbox is nonexistent.
- `domain_no_mail`, `domain_not_found`, `dns_configuration_error`, or `invalid_input`: the corresponding pre-SMTP outcome.

Connections go directly to MX servers on TCP port 25. Outbound port 25 may be blocked by your network or provider; that produces an inconclusive result. The tool does not switch to submission ports, authenticated relays, or verification services. It records skipped hosts and incomplete coverage rather than claiming every server was checked.

The JSON report retains DNS records, selected/tested/skipped hosts, IP and address family, TLS state, SMTP and enhanced codes, bounded replies, cleanup results, and a timed transcript. `message_submitted` and `ownership_verified` are false. An internal command-guard failure aborts with diagnostics rather than reporting clean success.

| Exit code | Meaning                                                                                                                                         |
| --------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `0`       | Launcher setup succeeded, or a report was produced (including an inconclusive result). Inspect report status; zero does not mean “valid email.” |
| `2`       | Invalid arguments or unsupported input.                                                                                                         |
| `3`       | Launcher setup failed, an internal invariant failed, or the requested report could not be written.                                              |

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

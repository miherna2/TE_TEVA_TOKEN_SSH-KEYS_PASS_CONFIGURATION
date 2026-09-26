#!/usr/bin/env python3
"""Verify TEVA key-only SSH and display hostname and interface addresses (read-only)."""

from __future__ import annotations

import argparse
import errno
import getpass
import logging
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import paramiko
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException, ReadTimeout

from common import (HERE, Device, EnvSettings, Reporter, StepError, execution_workers, expand_path,
                    prepare_console, read_inventory, run_devices)
from ssh_public_key import load_public_key
from teva_ui import UNREACHABLE


COMMAND = "hostname; echo; ip addr | grep inet"
DONE_MARKER = "TEVA_VERIFY_DONE"
# The echoed command shows "$((40+2))", only the shell's output shows "42", so the
# read stops on real completion instead of on the command echo or a silent pause.
MARKED_COMMAND = f"{COMMAND}; echo {DONE_MARKER}_$((40+2))"
STAGES = ("host_key", "ssh_connect", "ssh_command")
REFUSED = {errno.ECONNREFUSED, 10061}

# Paramiko logs raw tracebacks for handshake errors; this script reports them itself.
logging.getLogger("paramiko").setLevel(logging.CRITICAL)


@dataclass(frozen=True)
class Settings:
    ssh_user: str
    private_pkey: paramiko.PKey = field(repr=False)
    fingerprint: str
    port: int
    known_hosts: Path | None
    accept_new_host_key: bool
    timeout: int


def load_private_key(path: Path, passphrase: str | None) -> paramiko.PKey:
    if not path.is_file():
        raise StepError(f"private-key file not found: {path}")
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:200]
    except OSError as exc:
        raise StepError(f"private-key file could not be read: {path}") from exc
    if head.startswith("PuTTY-User-Key-File"):
        raise StepError(f"{path.name} is a PuTTY .ppk key; in PuTTYgen use Conversions > Export "
                        "OpenSSH key and point TE_SSH_PRIVATE_KEY at the exported file")
    encrypted = False

    def attempt(password: str | None) -> paramiko.PKey | None:
        nonlocal encrypted
        for key_type in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
            try:
                return key_type.from_private_key_file(str(path), password=password)
            except paramiko.PasswordRequiredException:
                encrypted = True
            except (paramiko.SSHException, ValueError, TypeError):
                continue
            except OSError as exc:
                raise StepError(f"private-key file could not be read: {path}") from exc
        return None

    key = attempt(passphrase)
    if key is None and encrypted and not passphrase:
        if not sys.stdin.isatty():
            raise StepError("the private key is protected by a passphrase; set "
                            "TE_SSH_PRIVATE_KEY_PASSPHRASE or run from an interactive terminal")
        key = attempt(getpass.getpass("SSH private-key passphrase: "))
    if key is None:
        raise StepError(f"the private key {path.name} could not be loaded: wrong passphrase, or not "
                        "an OpenSSH/PEM ed25519, RSA, or ECDSA key")
    return key


def load_settings(args: argparse.Namespace, env: EnvSettings) -> Settings:
    public_raw = args.public_key or env.get("TE_SSH_PUBLIC_KEY_PATHS")
    private_raw = args.private_key or env.get("TE_SSH_PRIVATE_KEY")
    if not public_raw or not private_raw:
        raise StepError("TE_SSH_PUBLIC_KEY_PATHS and TE_SSH_PRIVATE_KEY are required")
    public_path = expand_path(public_raw, Path.cwd() if args.public_key else env.path.parent)
    private_path = expand_path(private_raw, Path.cwd() if args.private_key else env.path.parent)
    public = load_public_key(public_path)
    key = load_private_key(private_path, env.get("TE_SSH_PRIVATE_KEY_PASSPHRASE"))
    if key.get_name() != public.key_type or key.get_base64() != public.base64_data:
        raise StepError("TE_SSH_PUBLIC_KEY_PATHS and TE_SSH_PRIVATE_KEY are not the same key pair")
    try:
        port = int(env.get("TE_SSH_PORT") or "22")
        if not 1 <= port <= 65535:
            raise ValueError
    except ValueError as exc:
        raise StepError("TE_SSH_PORT must be a number between 1 and 65535") from exc
    known_raw = args.known_hosts or env.get("TE_SSH_KNOWN_HOSTS")
    known_hosts = (expand_path(known_raw, Path.cwd() if args.known_hosts else env.path.parent)
                   if known_raw else Path.home() / ".ssh" / "known_hosts")
    user = env.get("TE_SSH_USERNAME") or "thousandeyes"
    if not known_hosts.is_file() and not args.accept_new_host_key:
        raise StepError(f"known_hosts file not found: {known_hosts}; connect once to each appliance "
                        f"with {ssh_hint('<ip>', user, port, known_hosts)} and accept its host key "
                        "after checking the fingerprint")
    return Settings(user, key,
                    public.fingerprint_sha256, port, known_hosts,
                    args.accept_new_host_key, args.timeout)


def load_trusted_hosts(settings: Settings) -> paramiko.HostKeys | None:
    """Load the one known_hosts file that paramiko will also enforce.

    paramiko aborts on the first line it cannot parse (for example an @cert-authority or a
    security-key entry), so such files are rejected here with a clear message instead.
    """
    if settings.accept_new_host_key or settings.known_hosts is None:
        return None
    path = settings.known_hosts
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise StepError(f"cannot read {path}: {exc.strerror or type(exc).__name__}") from exc
    if b"\x00" in raw or raw.startswith(b"\xef\xbb\xbf") or not raw.isascii():
        raise StepError(f"{path.name} contains UTF-16 or other non-ASCII text (Windows PowerShell "
                        "writes UTF-16 with > or >>), so the SSH library cannot read those lines. "
                        "Point TE_SSH_KNOWN_HOSTS at a separate file and add each appliance by "
                        "connecting once with ssh")
    text = raw.decode("ascii")
    trusted = paramiko.HostKeys()
    for number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            if line.startswith("@"):
                raise ValueError(line)
            entry = paramiko.hostkeys.HostKeyEntry.from_line(line, number)
        except paramiko.SSHException:
            continue  # paramiko itself skips these lines too
        except Exception as exc:  # paramiko raises several types for lines it cannot parse
            raise StepError(f"{path.name} line {number} is not supported by the SSH library; point "
                            "TE_SSH_KNOWN_HOSTS at a separate file that contains only the "
                            "appliance host keys") from exc
        if entry is not None:
            for name in entry.hostnames:
                trusted.add(name, entry.key.get_name(), entry.key)
    return trusted


def ssh_hint(ip: str, user: str, port: int, known_hosts: Path | None) -> str:
    """The exact ssh command that adds this appliance to the known_hosts file this tool reads."""
    command = f"ssh {user}@{ip}" + (f" -p {port}" if port != 22 else "")
    default = Path.home() / ".ssh" / "known_hosts"
    if known_hosts and known_hosts.resolve() != default.resolve():
        command += f' -o UserKnownHostsFile="{known_hosts}"'
    return command


def host_lookup_name(device: Device, settings: Settings) -> str:
    return device.ip if settings.port == 22 else f"[{device.ip}]:{settings.port}"


def host_key_present(device: Device, settings: Settings, trusted: paramiko.HostKeys | None) -> bool:
    if settings.accept_new_host_key:
        return True
    assert trusted is not None
    return bool(trusted.lookup(host_lookup_name(device, settings)))


def connect_ssh(device: Device, settings: Settings):
    strict = not settings.accept_new_host_key
    port = settings.port
    try:
        # Strict mode trusts exactly one file. In accept-new mode no file is passed at all, so
        # paramiko can never rewrite the operator's known_hosts.
        return ConnectHandler(
            device_type="terminal_server", host=device.ip, port=port,
            username=settings.ssh_user, password=None, pkey=settings.private_pkey,
            use_keys=False, allow_agent=False, ssh_strict=strict,
            system_host_keys=False, alt_host_keys=strict,
            alt_key_file=str(settings.known_hosts) if strict else "",
            conn_timeout=settings.timeout,
            auth_timeout=settings.timeout, banner_timeout=settings.timeout,
            blocking_timeout=settings.timeout,
        )
    except NetmikoAuthenticationException as exc:
        raise StepError(f"the appliance rejected the SSH key for user '{settings.ssh_user}'; run "
                        "load_keys.py for this device (changing the web-UI password can remove "
                        "uploaded keys) and check TE_SSH_USERNAME") from exc
    except NetmikoTimeoutException as exc:
        reason = str(exc).lower()
        chain: list[BaseException] = []
        current: BaseException | None = exc
        while current is not None and len(chain) < 8:
            chain.append(current)
            current = current.__cause__ or current.__context__
        known = settings.known_hosts
        if "not found in known_hosts" in reason:
            raise StepError(f"this appliance's SSH host key is not in {known}; connect once with "
                            f"{ssh_hint(device.ip, settings.ssh_user, port, known)}, check the "
                            "fingerprint, and accept it") from exc
        if "host key" in reason and "does not match" in reason:
            raise StepError(f"the SSH host key of {device.ip} differs from the one saved in {known}. "
                            f"If this appliance was redeployed, remove the old entry with "
                            f"ssh-keygen -R {host_lookup_name(device, settings)} and reconnect once; "
                            "otherwise stop and check the device identity") from exc
        # paramiko groups per-address socket errors in NoValidConnectionsError.errors.
        errors: list[BaseException] = list(chain)
        for cause in chain:
            if isinstance(cause, paramiko.ssh_exception.NoValidConnectionsError):
                errors.extend(cause.errors.values())
        if any(isinstance(error, OSError) and error.errno in UNREACHABLE for error in errors):
            raise StepError(f"no network route to {device.ip}; check the IP address, that the "
                            "appliance is powered on, and your network/VPN") from exc
        if any(isinstance(error, ConnectionRefusedError) or (
                isinstance(error, OSError) and error.errno in REFUSED) for error in errors):
            raise StepError(f"{device.ip} refused SSH on port {port}: SSH is not running on the "
                            "appliance yet, or TE_SSH_PORT is wrong") from exc
        if "banner" in reason:
            raise StepError(f"port {port} on {device.ip} answered, but no SSH service replied "
                            "(the appliance may be starting)") from exc
        raise StepError(f"no SSH answer from {device.ip} on port {port} within {settings.timeout} s; "
                        "check the IP address, that the appliance is on, and your network/VPN") from exc
    except paramiko.BadHostKeyException as exc:
        raise StepError(f"the SSH host key of {device.ip} differs from the one saved in "
                        f"{settings.known_hosts}") from exc
    except (paramiko.SSHException, OSError) as exc:
        raise StepError(f"SSH connection failed ({type(exc).__name__})") from exc
    except Exception as exc:
        raise StepError(f"SSH connection failed ({type(exc).__name__})") from exc


def clean_output(output: str) -> str:
    output = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", output)
    return "".join(ch for ch in output if ch in "\n\t" or ch.isprintable()).strip()


def command_result(raw: str) -> str:
    """Keep only what the command printed: drop the login banner, prompts, echo, and marker."""
    text = clean_output(raw)
    lines = text.splitlines()
    start = next((i + 1 for i in range(len(lines) - 1, -1, -1) if COMMAND in lines[i]), 0)
    kept = [line for line in lines[start:] if DONE_MARKER not in line]
    return "\n".join(kept).strip()


def process_device(device: Device, settings: Settings, trusted: paramiko.HostKeys | None,
                   report: Reporter) -> bool:
    report.task(device, "host_key", "Check trusted SSH host key")
    start = time.monotonic()
    if settings.accept_new_host_key:
        report.result(device, "host_key", "skipped", "strict checking disabled for this lab run", start)
    elif not host_key_present(device, settings, trusted):
        report.result(device, "host_key", "failed",
                      f"{host_lookup_name(device, settings)} is not in {settings.known_hosts}; connect "
                      f"once with "
                      f"{ssh_hint(device.ip, settings.ssh_user, settings.port, settings.known_hosts)}, "
                      "check the fingerprint, and accept it", start)
        report.skip(device, STAGES[1:], "host key not trusted")
        return False
    else:
        report.result(device, "host_key", "ok", f"trusted entry found in {settings.known_hosts}", start)

    report.task(device, "ssh_connect", f"Open key-only SSH as {settings.ssh_user} at {device.ip}")
    start = time.monotonic()
    try:
        connection = connect_ssh(device, settings)
    except StepError as exc:
        report.result(device, "ssh_connect", "failed", str(exc), start)
        report.skip(device, STAGES[2:], "SSH connection failed")
        return False
    report.result(device, "ssh_connect", "ok", "key-only SSH session established", start)

    try:
        report.task(device, "ssh_command", f"Run {COMMAND}")
        start = time.monotonic()
        try:
            connection.write_channel(MARKED_COMMAND + "\n")
            raw = connection.read_until_pattern(pattern=f"{DONE_MARKER}_42",
                                                read_timeout=settings.timeout)
            if not isinstance(raw, str):
                raise StepError("SSH command returned an unexpected result type")
            output = command_result(raw)
        except ReadTimeout:
            report.result(device, "ssh_command", "failed",
                          f"the command did not finish within {settings.timeout} s", start)
            return False
        except (OSError, paramiko.SSHException) as exc:
            report.result(device, "ssh_command", "failed",
                          f"SSH command failed ({type(exc).__name__})", start)
            return False
        except StepError as exc:
            report.result(device, "ssh_command", "failed", str(exc), start)
            return False
        except Exception as exc:
            report.result(device, "ssh_command", "failed",
                          f"SSH command failed ({type(exc).__name__})", start)
            return False
        if not re.search(r"(?m)^\s*inet6?\s+\S+", output):
            report.result(device, "ssh_command", "failed",
                          f"the command ran but printed no inet address. Command output:\n"
                          f"{output or '(empty)'}", start)
            return False
        if not re.search(rf"(?m)^\s*inet6?\s+{re.escape(device.ip)}/", output):
            report.result(device, "ssh_command", "ok",
                          f"command output (note: {device.ip} is not one of this host's addresses; "
                          f"unless you connect through NAT, check inventory.csv):\n{output}", start)
            return True
        report.result(device, "ssh_command", "ok", f"command output:\n{output}", start)
        return True
    finally:
        try:
            connection.disconnect()
        except Exception:
            pass


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--inventory", type=Path, default=HERE / "inventory.csv")
    p.add_argument("--env-file", type=Path, default=None, help="settings file (default: .env here)")
    p.add_argument("--public-key", type=str)
    p.add_argument("--private-key", type=str)
    p.add_argument("--known-hosts", type=str)
    p.add_argument("--only", action="append", default=[], metavar="NAME")
    p.add_argument("--parallel", action="store_true", help="process multiple devices concurrently")
    p.add_argument("--workers", type=int, default=None,
                   help="worker count with --parallel (default: 4); without it, only 1 is allowed")
    p.add_argument("--timeout", type=int, default=15)
    p.add_argument("--accept-new-host-key", action="store_true",
                   help="disable strict host-key checking for a trusted lab only")
    return p


def main(argv: list[str] | None = None) -> int:
    p = parser()
    args = p.parse_args(argv)
    if args.timeout < 1:
        p.error("--timeout must be positive")
    try:
        workers = execution_workers(args.parallel, args.workers)
    except ValueError as exc:
        p.error(str(exc))
    prepare_console()
    try:
        report = Reporter(HERE, prefix="teva-ssh-verify")
    except StepError as exc:
        print(f"failed: {exc}", file=sys.stderr)
        return 2
    try:
        report.say("PLAY [Verify TEVA key-only SSH and display hostname/IP]")
        try:
            devices = read_inventory(args.inventory.expanduser().resolve(), args.only)
            env = EnvSettings((args.env_file or HERE / ".env").expanduser().resolve(),
                              explicit=args.env_file is not None)
            settings = load_settings(args, env)
            trusted = load_trusted_hosts(settings)
        except StepError as exc:
            return report.preflight_failed(str(exc))
        report.say(f"Inventory: {args.inventory} ({len(devices)} selected device(s))")
        report.say("Settings: " + env.describe(("TE_SSH_USERNAME", "TE_SSH_PUBLIC_KEY_PATHS",
                                                "TE_SSH_PRIVATE_KEY", "TE_SSH_KNOWN_HOSTS")))
        for note in env.notes:
            report.say(f"Note: {note}")
        report.say(f"Preflight: matching public/private key loaded ({settings.fingerprint})")
        report.say("SSH host-key checking: " + ("disabled for this lab run; known_hosts is not "
                   "modified" if settings.accept_new_host_key else f"strict ({settings.known_hosts})"))
        active_workers = min(workers, len(devices))
        mode = ("serial (one device at a time)" if not args.parallel else
                f"parallel ({active_workers} worker(s))")
        report.say(f"Execution: {mode}; read-only command, no web-UI request, no password login")
        results, interrupted = run_devices(
            devices, lambda device: process_device(device, settings, trusted, report), report,
            parallel=args.parallel, workers=workers, stages=STAGES, confirm=False, canary=False,
            interrupt_hint="Nothing is changed by this read-only check.")
        report.recap(devices)
        if interrupted:
            return 130
        return 0 if len(results) == len(devices) and all(results.values()) else 1
    finally:
        report.write_csv()
        report.close()


if __name__ == "__main__":
    raise SystemExit(main())

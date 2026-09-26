"""Shared settings, inventory, device runner, and safe progress reporting."""

from __future__ import annotations

import csv
import io
import ipaddress
import logging
import os
import re
import sys
import threading
import time
import traceback
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from dotenv import dotenv_values


HERE = Path(__file__).resolve().parent
# Set on Ctrl+C: web-UI sessions check it before every request, so nothing new is sent.
STOP = threading.Event()
# Returned by a device step that found the work already done, so it proved nothing about
# the settings; the parallel first-device check keeps going until a device really runs.
DONE_BEFORE = "done-before"
SECRET_NAMES = frozenset({"TE_DEFAULT_PASSWORD", "TE_UI_PASSWORD", "TE_SSH_PRIVATE_KEY_PASSPHRASE"})
ENV_LINE = re.compile(r"(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)")

# This module reports malformed .env lines itself, with line numbers.
logging.getLogger("dotenv.main").setLevel(logging.ERROR)


class StepError(Exception):
    """A failure description safe for console, CSV, and log files."""


def sentence(text: str) -> str:
    """End a message with a full stop so further advice can follow it."""
    text = text.rstrip()
    return text if text.endswith((".", "!", "?")) else text + "."


def prepare_console() -> None:
    """Never crash on a console or pipe that cannot show a character (e.g. Windows cp1252)."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass


def read_text(path: Path) -> str:
    """Read a user-edited text file saved as UTF-8 (BOM optional) or UTF-16 with a BOM."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise StepError(f"cannot read {path}: {exc.strerror or type(exc).__name__}") from exc
    try:
        if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
            return raw.decode("utf-16")
        if b"\x00" in raw:
            raise UnicodeError
        return raw.decode("utf-8-sig")
    except UnicodeError as exc:
        raise StepError(f"{path.name} is not saved as UTF-8 text; open it in a text editor and "
                        "save it again with UTF-8 encoding") from exc


def execution_workers(parallel: bool, requested: int | None) -> int:
    """Use one worker unless parallel execution was explicitly requested."""
    if requested is not None and requested < 1:
        raise ValueError("--workers must be positive")
    if not parallel and requested not in (None, 1):
        raise ValueError("--workers greater than 1 requires --parallel")
    return requested if requested is not None else (4 if parallel else 1)


def require_serial_confirmation(devices: list[Device], parallel: bool) -> None:
    """Fail before contacting any device if a serial multi-device run cannot pause."""
    if not parallel and len(devices) > 1 and not sys.stdin.isatty():
        raise StepError("this terminal cannot answer the Y/N pause between devices (Git Bash, IDE "
                        "consoles, and pipes are often not detected as interactive); run from "
                        "PowerShell, cmd, Terminal, or prefix the command with winpty; or use "
                        "--only NAME for one device")


def confirm_next_device(previous: Device, previous_ok: bool, upcoming: Device, report: Reporter) -> bool:
    """Require explicit consent before beginning another device in serial mode."""
    if previous_ok:
        report.say(f"PAUSE [{previous.name} done; next: {upcoming.name}] "
                   "Type Y to continue; any other input stops this run.")
    else:
        report.say(f"PAUSE [{previous.name} FAILED; next: {upcoming.name}] Read the failure above "
                   "first: the same cause often affects the next device. Type Y only if it "
                   "concerns this device alone; any other input stops this run.")
    try:
        answer = input("Continue? [Y/N]: ").strip().upper()
    except EOFError:
        answer = ""
    if answer != "Y":
        report.say("Operator stopped the run; no further devices will be contacted.")
        return False
    report.say(f"Operator confirmed Y; continuing with {upcoming.name}.")
    return True


@dataclass(frozen=True)
class Device:
    name: str
    ip: str

    @property
    def url_host(self) -> str:
        return f"[{self.ip}]" if ":" in self.ip else self.ip


@dataclass(frozen=True)
class Record:
    timestamp_utc: str
    device: str
    ip_address: str
    stage: str
    status: str
    detail: str
    duration_seconds: float


class Reporter:
    def __init__(self, output_dir: Path, prefix: str = "teva-ssh-keys") -> None:
        run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"-{uuid4().hex[:8]}"
        try:
            (output_dir / "logs").mkdir(parents=True, exist_ok=True)
            (output_dir / "reports").mkdir(parents=True, exist_ok=True)
            self.log_path = output_dir / "logs" / f"{prefix}-{run_id}.log"
            self.csv_path = output_dir / "reports" / f"{prefix}-{run_id}.csv"
            self.log = self.log_path.open("w", encoding="utf-8")
        except OSError as exc:
            raise StepError(f"cannot write logs/ and reports/ in {output_dir} "
                            f"({exc.strerror or type(exc).__name__}); run from a folder you can "
                            "write to") from exc
        self.records: list[Record] = []
        self.lock = threading.Lock()

    def say(self, message: str) -> None:
        with self.lock:
            print(message, flush=True)
            self.log.write(f"{datetime.now(timezone.utc).isoformat()} {message}\n")
            self.log.flush()

    def task(self, device: Device, stage: str, description: str) -> None:
        self.say(f"\nTASK [{device.name} | {description}] ({stage})")

    def result(self, device: Device, stage: str, status: str, detail: str, start: float) -> None:
        record = Record(
            datetime.now(timezone.utc).isoformat(), device.name, device.ip, stage,
            status, detail, round(time.monotonic() - start, 3),
        )
        with self.lock:
            self.records.append(record)
            headline, separator, body = detail.partition("\n")
            message = (f"{status}: [{device.name}] {stage}: {headline} "
                       f"({record.duration_seconds:.3f}s)")
            if separator:
                message += f"\n{body}"
            print(message, flush=True)
            self.log.write(f"{record.timestamp_utc} {message}\n")
            self.log.flush()

    def skip(self, device: Device, stages: tuple[str, ...], reason: str) -> None:
        for stage in stages:
            self.result(device, stage, "skipped", f"not attempted: {reason}", time.monotonic())

    def unexpected(self, device: Device, exc: BaseException) -> None:
        # Exception text can carry request data, so the log gets code locations only.
        self.result(device, "internal", "failed",
                    f"unexpected {type(exc).__name__}; code locations are in the log file",
                    time.monotonic())
        frames = traceback.extract_tb(exc.__traceback__)
        with self.lock:
            for frame in frames:
                self.log.write(f"    at {Path(frame.filename).name}:{frame.lineno} in {frame.name}\n")
            self.log.flush()

    def preflight_failed(self, message: str) -> int:
        self.result(Device("*", ""), "preflight", "failed", message, time.monotonic())
        self.say("Nothing was sent to any device.")
        self.say(f"Log: {self.log_path}")
        self.say(f"CSV: {self.csv_path}")
        return 2

    def write_csv(self) -> None:
        with self.csv_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(Record.__dataclass_fields__)
            for row in self.records:
                writer.writerow((row.timestamp_utc, row.device, row.ip_address, row.stage,
                                 row.status, row.detail, row.duration_seconds))

    def recap(self, devices: list[Device]) -> None:
        self.say("\nPLAY RECAP")
        for device in devices:
            rows = [row for row in self.records if row.device == device.name]
            counts = {status: sum(row.status == status for row in rows)
                      for status in ("ok", "changed", "failed", "skipped")}
            self.say(f"{device.name:<20} ok={counts['ok']} changed={counts['changed']} "
                     f"failed={counts['failed']} skipped={counts['skipped']}")
        self.say(f"Log: {self.log_path}")
        self.say(f"CSV: {self.csv_path}")

    def close(self) -> None:
        self.log.close()


def run_devices(devices: list[Device], process: Callable[[Device], bool | str], report: Reporter, *,
                parallel: bool, workers: int, stages: tuple[str, ...], confirm: bool,
                interrupt_hint: str, canary: bool = True) -> tuple[dict[str, bool], bool]:
    """Run each device; return per-device results and whether Ctrl+C stopped the run.

    Serial runs pause for Y between devices when ``confirm`` is set. With ``canary``,
    parallel runs first finish one device on its own, so a problem shared by every device
    (wrong password, wrong key) stops the run after one device instead of hitting them all.
    """
    STOP.clear()
    results: dict[str, bool] = {}

    def run_one(device: Device) -> bool | str:
        try:
            return process(device)
        except Exception as exc:  # Keep other devices running; never log raw exception text.
            report.unexpected(device, exc)
            return False

    def interrupted(remaining: list[Device], during: Device | None) -> tuple[dict[str, bool], bool]:
        STOP.set()
        where = f"while {during.name} was in progress. {interrupt_hint}" if during else "at the pause."
        report.say(f"\nCtrl+C: stopped {where}")
        for other in remaining:
            report.skip(other, stages, "run interrupted with Ctrl+C")
        return results, True

    # Serial part: every device when serial; in parallel mode, devices one by one until one
    # really proves the settings (a device that was already done proves nothing).
    index = 0
    outcome: bool | str | None = None
    while index < len(devices):
        if parallel and not (canary and (index == 0 or outcome == DONE_BEFORE)):
            break
        device = devices[index]
        if index and not parallel and confirm:
            try:
                if not confirm_next_device(devices[index - 1], results[devices[index - 1].name],
                                           device, report):
                    for remaining in devices[index:]:
                        report.skip(remaining, stages, "operator stopped the run")
                    return results, False
            except KeyboardInterrupt:
                return interrupted(devices[index:], None)
        elif index and parallel:
            report.say(f"\n{devices[index - 1].name} was already done, so it did not test the "
                       f"settings; running {device.name} on its own first.")
        try:
            outcome = run_one(device)
        except KeyboardInterrupt:
            results[device.name] = False
            return interrupted(devices[index + 1:], device)
        results[device.name] = bool(outcome)
        index += 1
        if parallel and not results[device.name]:
            rest = devices[index:]
            if rest:
                report.say(f"\n{device.name} failed, so the other {len(rest)} device(s) were not "
                           "started: fix the problem shown above and rerun.")
                for other in rest:
                    report.skip(other, stages, f"{device.name} failed first; fix that and rerun")
            return results, False
    rest = devices[index:]
    if not rest:
        return results, False
    if index:
        report.say(f"\n{devices[index - 1].name} succeeded; starting the other {len(rest)} "
                   "device(s) in parallel.")

    pool = ThreadPoolExecutor(max_workers=min(workers, len(rest)))
    jobs = {pool.submit(run_one, device): device for device in rest}
    pending = set(jobs)
    stopped = False
    try:
        while pending:
            try:
                # A short wait keeps Ctrl+C responsive on Windows as well.
                done, pending = wait(pending, timeout=0.5, return_when=FIRST_COMPLETED)
            except KeyboardInterrupt:
                if not stopped:
                    stopped = True
                    STOP.set()
                    for future in pending:
                        future.cancel()
                    report.say("\nCtrl+C: no new requests will be sent. Devices in progress stop "
                               f"after their current request finishes. {interrupt_hint}")
                else:
                    report.say("Still waiting for the current request(s) to finish (at most the "
                               "--timeout); nothing new is being sent.")
                continue
            for future in done:
                if not future.cancelled():
                    results[jobs[future].name] = bool(future.result())
    finally:
        pool.shutdown(wait=False)
    for future, device in jobs.items():
        if future.cancelled():
            report.skip(device, stages, "run interrupted with Ctrl+C")
            results[device.name] = False
    return results, stopped


def read_inventory(path: Path, only: list[str]) -> list[Device]:
    if not path.is_file():
        raise StepError(f"inventory file not found: {path}")
    text = "".join("\n" if line.lstrip().startswith("#") else line
                   for line in read_text(path).splitlines(keepends=True))
    reader = csv.DictReader(io.StringIO(text), strict=True)
    try:
        fields = {name.strip().lower() for name in reader.fieldnames or [] if name}
        if not {"hostname", "ip_address"} <= fields:
            raise StepError(f"{path.name} must start with the header line: hostname,ip_address")
        reader.fieldnames = [name.strip().lower() for name in reader.fieldnames or []]
        devices: list[Device] = []
        names: dict[str, int] = {}
        ips: dict[str, int] = {}
        for row in reader:
            line = reader.line_num
            name = (row.get("hostname") or "").strip()
            raw_ip = (row.get("ip_address") or "").strip()
            if not name and not raw_ip:
                continue
            if not name or not raw_ip:
                raise StepError(f"{path.name} line {line}: both hostname and ip_address are required")
            try:
                ip = str(ipaddress.ip_address(raw_ip))
            except ValueError as exc:
                raise StepError(f"{path.name} line {line}: '{raw_ip}' is not an IP address "
                                "(DNS names are not supported)") from exc
            if name.casefold() in names:
                raise StepError(f"{path.name} lines {names[name.casefold()]} and {line} both use "
                                f"the name {name}")
            if ip in ips:
                raise StepError(f"{path.name} lines {ips[ip]} and {line} both use {ip}; "
                                "each appliance needs its own row")
            names[name.casefold()] = ips[ip] = line
            devices.append(Device(name, ip))
    except csv.Error as exc:
        raise StepError(f"{path.name} is not a valid CSV file (line {reader.line_num})") from exc
    if not devices:
        raise StepError(f"{path.name} contains no devices")
    if only:
        wanted = {name.casefold() for name in only}
        missing = wanted - set(names)
        if missing:
            raise StepError(f"device not in {path.name}: {', '.join(sorted(missing))}")
        devices = [device for device in devices if device.name.casefold() in wanted]
    return devices


def env_lines(text: str):
    """Yield (line number, name, raw value) for each setting line; name is None if malformed."""
    for number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = ENV_LINE.fullmatch(line)
        yield (number, *match.groups()) if match else (number, None, line)


def lint_env(text: str) -> str | None:
    """Return the first .env problem that would silently change a value, or None."""
    seen: dict[str, int] = {}
    for number, name, value in env_lines(text):
        if name is None:
            return f"line {number} is not in NAME=value form"
        if name in seen:
            return f"line {number}: {name} is already set on line {seen[name]}; keep only one"
        seen[name] = number
        if value[:1] in ("'", '"'):
            quote = value[0]
            end = value.find(quote, 1)
            if end == -1:
                return f"line {number}: the value of {name} opens a {quote} quote but never closes it"
            if value[end + 1:].strip()[:1] not in ("", "#"):
                other = '"' if quote == "'" else "'"
                return (f"line {number}: {name} has text after its closing {quote} quote; if the "
                        f"value itself contains {quote}, wrap it in {other} quotes instead")
            inner = value[1:end]
            if quote == '"' and "\\" in inner:
                return (f"line {number}: {name} is in double quotes and contains a backslash, which "
                        ".env would turn into a control character; use single quotes instead")
            if quote == "'" and (inner.endswith("\\") or "\\\\" in inner):
                return (f"line {number}: {name} has a backslash that .env would change inside "
                        "single quotes; write this value without quotes")
        elif name in SECRET_NAMES and re.search(r"\s#", value):
            return (f"line {number}: {name} contains ' #', which .env reads as the start of a "
                    f"comment; write it in single quotes: {name}='...'")
    return None


class EnvSettings:
    """Settings from .env first, then the process environment as fallback.

    The fallback covers bash/zsh ``export``, PowerShell ``$env:`` and cmd ``set``. The .env
    file is read literally (no ``${VAR}`` expansion) so a password reaches the appliance
    exactly as written.
    """

    def __init__(self, path: Path, explicit: bool = False) -> None:
        self.path = path
        self.file: dict[str, str] = {}
        self.sources: dict[str, str] = {}
        self.notes: list[str] = []
        if path.is_file():
            text = read_text(path)
            problem = lint_env(text)
            if problem:
                raise StepError(f"{path.name} {problem}")
            values = dotenv_values(stream=io.StringIO(text), interpolate=False)
            for number, name, _ in env_lines(text):
                if values.get(name) is None:
                    raise StepError(f"{path.name} line {number}: the value of {name} could not be "
                                    "read; retype it without quotes or in single quotes")
            self.file = {name: value for name, value in values.items() if value is not None}
        elif explicit:
            raise StepError(f"settings file given with --env-file not found: {path}")

    def get(self, name: str) -> str | None:
        file_value = self.file.get(name) or None
        env_value = os.environ.get(name) or None
        value, source = (file_value, ".env") if file_value else (env_value, "environment")
        if not value:
            return None
        if file_value and env_value and env_value != file_value and name not in self.sources:
            self.notes.append(f"{name} is also set in the environment with a different value; "
                              "using the .env value")
        check_value(name, value, source)
        self.sources[name] = source
        return value

    def describe(self, names: tuple[str, ...]) -> str:
        return ", ".join(f"{name}={self.sources.get(name, 'not set')}" for name in names)


def check_value(name: str, value: str, source: str) -> None:
    """Reject values that would reach the appliance differently than the operator typed them."""
    if any(char in "\t\r\n" for char in value):
        raise StepError(f"{name} (from {source}) contains a tab or line break; remove it and "
                        "retype the value")
    if any(not char.isprintable() for char in value):
        raise StepError(f"{name} (from {source}) contains an invisible character (for example a "
                        "non-breaking space copied from a web page or chat); retype the value")
    if value != value.strip():
        raise StepError(f"{name} (from {source}) starts or ends with a space; remove it "
                        "(in cmd, write: set \"NAME=value\")")
    if source == "environment" and len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        raise StepError(f"{name} (from the environment) is wrapped in quotes that would become part "
                        "of the value; in cmd write set \"NAME=value\" instead of set NAME=\"value\"")


def expand_path(raw: str, base: Path) -> Path:
    path = Path(os.path.expandvars(raw)).expanduser()
    return (path if path.is_absolute() else base / path).resolve()

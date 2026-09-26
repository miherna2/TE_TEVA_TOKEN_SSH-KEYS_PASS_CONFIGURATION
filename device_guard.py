"""Remember recent failed logins and web-UI outages per appliance, across runs.

TEVA locks its web login for 15 minutes after repeated failures, and an appliance whose
UI backend is down answers HTTP 5xx or not at all. Reruns that keep hitting either state
are exactly what must never happen, so this guard refuses to contact such an appliance
until it is safe again and tells the operator when that will be.

Every operation re-reads the file and changes only one appliance's entry, so two runs
started from different terminals see each other's records.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from common import Device, StepError


LOCK_WINDOW = 15 * 60   # TEVA's web-login lock time (app-config "locking_time": 15)
MAX_FAILED_LOGINS = 2   # per appliance within LOCK_WINDOW; stays below the lockout threshold
OUTAGE_PAUSE = 3 * 60   # after HTTP 5xx or no reply, leave the web UI alone while it recovers


def _clock(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime("%H:%M UTC")


def _minutes(seconds: float) -> int:
    return int(seconds // 60) + 1


def _recent(entry: dict, now: float) -> list[float]:
    return [t for t in entry.get("failed_logins", [])
            if isinstance(t, (int, float)) and now - t < LOCK_WINDOW]


class DeviceGuard:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.lock = threading.Lock()
        self.save_failed = False
        # A damaged or unwritable record stops the run before any device is contacted.
        self._modify(lambda data, now: None)
        if self.save_failed:
            raise StepError(f"cannot write the safety record {self.path}; make sure the logs/ "
                            "folder is writable (not read-only or locked by sync software), then "
                            "rerun. Nothing was sent to any device.")

    def _read(self) -> dict[str, dict]:
        try:
            text = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return {}
        except OSError as exc:
            # Often a temporary lock by sync or antivirus software; the record itself is fine.
            raise StepError(f"the safety record {self.path} cannot be read "
                            f"({exc.strerror or type(exc).__name__}). Close programs that may hold "
                            "it open (sync or antivirus software) and rerun. Nothing was sent to "
                            "any device.") from exc
        try:
            data = json.loads(text) if text.strip() else {}
        except ValueError as exc:
            raise self._damaged() from exc
        if not isinstance(data, dict) or not all(isinstance(entry, dict) for entry in data.values()):
            raise self._damaged()
        return data

    def _damaged(self) -> StepError:
        # The only case where deleting the record is the way out; waiting first lets any
        # login lock or outage pause it held expire on the appliances.
        return StepError(f"the safety record {self.path} is damaged, so this tool cannot tell "
                         "whether an appliance is still locked. Wait 15 minutes, check the "
                         "appliances in a browser, then delete that file and rerun. Nothing was "
                         "sent to any device.")

    def _write(self, data: dict[str, dict]) -> bool:
        """Replace the record atomically; return False if the target is briefly locked."""
        temporary = None
        try:
            handle, temporary = tempfile.mkstemp(dir=self.path.parent, prefix=".device-guard-",
                                                 suffix=".tmp")
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                json.dump(data, stream, indent=1)
            os.replace(temporary, self.path)
            return True
        except PermissionError:
            pass  # Windows/OneDrive/antivirus may hold the target open briefly
        except OSError:
            self.save_failed = True
        if temporary:
            try:
                os.unlink(temporary)
            except OSError:
                pass
        return False

    def _modify(self, change: Callable[[dict, float], None]) -> None:
        with self.lock:
            for _ in range(5):
                # Re-read on every attempt so another run's records are never overwritten.
                data = self._read()
                change(data, time.time())
                if self._write(data) or self.save_failed:
                    return
                time.sleep(0.2)
            self.save_failed = True

    def _update(self, device: Device, change: Callable[[dict, float], None]) -> None:
        def apply(data: dict, now: float) -> None:
            entry = data.setdefault(device.ip, {})
            entry["failed_logins"] = _recent(entry, now)
            change(entry, now)
        self._modify(apply)

    def _entry(self, device: Device) -> dict:
        with self.lock:
            entry = dict(self._read().get(device.ip, {}))
        entry["failed_logins"] = _recent(entry, time.time())
        return entry

    def check(self, device: Device) -> None:
        """Raise before any request if contacting this appliance now could harm it."""
        if self.save_failed:
            raise StepError(f"not contacted: this run could not update {self.path}, so it cannot "
                            "keep its safety record. Make sure the logs/ folder is writable (not "
                            "locked by sync software), then rerun.")
        entry = self._entry(device)
        now = time.time()
        locked_until = entry.get("locked_until")
        if isinstance(locked_until, (int, float)) and now < locked_until:
            raise StepError(
                f"not contacted: {device.ip} reported that its web login is locked. This tool waits "
                f"until {_clock(locked_until)} ({_minutes(locked_until - now)} min) before sending "
                f"another password; after that, check the password at https://{device.url_host} "
                "in a browser before rerunning.")
        failures = entry["failed_logins"]
        if len(failures) >= MAX_FAILED_LOGINS:
            until = min(failures) + LOCK_WINDOW
            raise StepError(
                f"not contacted: {device.ip} rejected {len(failures)} logins in the last 15 minutes. "
                f"To avoid locking the appliance's web login, this tool waits until {_clock(until)} "
                f"({_minutes(until - now)} min). Meanwhile, check the password by logging in "
                f"at https://{device.url_host} in a browser.")
        outage = entry.get("outage")
        if isinstance(outage, (int, float)) and now - outage < OUTAGE_PAUSE:
            until = outage + OUTAGE_PAUSE
            minutes = int((now - outage) // 60)
            ago = f"{minutes} min ago" if minutes else "less than a minute ago"
            raise StepError(
                f"not contacted: the web UI of {device.ip} did not answer normally (HTTP 5xx or no "
                f"reply) {ago}. This tool leaves it alone until {_clock(until)} "
                f"({_minutes(until - now)} min) so it can recover; check https://{device.url_host} "
                "in a browser meanwhile, and rerun after that time.")

    def failed_logins_left(self, device: Device) -> int:
        return MAX_FAILED_LOGINS - len(self._entry(device)["failed_logins"])

    def record_failed_login(self, device: Device) -> None:
        self._update(device, lambda entry, now: entry["failed_logins"].append(now))

    def record_lockout(self, device: Device) -> None:
        self._update(device, lambda entry, now: entry.__setitem__("locked_until", now + LOCK_WINDOW))

    def record_login_ok(self, device: Device) -> None:
        def clear(entry: dict, now: float) -> None:
            entry["failed_logins"] = []
            entry.pop("outage", None)
            entry.pop("locked_until", None)
        self._update(device, clear)

    def record_outage(self, device: Device) -> None:
        self._update(device, lambda entry, now: entry.__setitem__("outage", now))

    def record_password_changed(self, device: Device, changed: bool = True) -> None:
        self._update(device, lambda entry, now: entry.__setitem__("password_changed", changed))

    def password_changed(self, device: Device) -> bool:
        return self._entry(device).get("password_changed") is True

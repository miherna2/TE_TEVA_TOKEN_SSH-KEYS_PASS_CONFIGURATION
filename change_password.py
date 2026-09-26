#!/usr/bin/env python3
"""Change the TEVA web-UI password from TE_DEFAULT_PASSWORD to TE_UI_PASSWORD (no SSH)."""

from __future__ import annotations

import argparse
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from common import (DONE_BEFORE, HERE, Device, EnvSettings, Reporter, StepError, execution_workers,
                    prepare_console, read_inventory, require_serial_confirmation, run_devices,
                    sentence)
from device_guard import DeviceGuard
from teva_ui import LoginRejected, TevaUi


STAGES = ("ui_auth", "password_change", "ui_reauth")
PASSWORD_NAMES = ("TE_UI_USERNAME", "TE_DEFAULT_PASSWORD", "TE_UI_PASSWORD")
INTERRUPT_HINT = ("If its password change had already been sent, it may be active: rerun with "
                  "--check-login --only NAME to see which password works.")


@dataclass(frozen=True)
class Settings:
    ui_user: str
    default_password: str = field(repr=False)
    new_password: str = field(repr=False)
    verify_tls: bool = False
    timeout: int = 15


def load_settings(env: EnvSettings, *, verify_tls: bool, timeout: int,
                  require_new_password: bool = True) -> Settings:
    user = env.get("TE_UI_USERNAME")
    default = env.get("TE_DEFAULT_PASSWORD")
    new = env.get("TE_UI_PASSWORD")
    required = [("TE_UI_USERNAME", user), ("TE_DEFAULT_PASSWORD", default)]
    if require_new_password:
        required.append(("TE_UI_PASSWORD", new))
    missing = [name for name, value in required if not value]
    if missing:
        raise StepError(f"required setting(s) missing from {env.path.name} and the environment: "
                        + ", ".join(missing))
    assert user is not None and default is not None
    if new is not None and new == default:
        raise StepError("TE_UI_PASSWORD must differ from TE_DEFAULT_PASSWORD")
    if require_new_password:
        assert new is not None
        classes = sum((any(c.isupper() for c in new), any(c.islower() for c in new),
                       any(c.isdigit() for c in new), any(not c.isalnum() for c in new)))
        if len(new) < 8 or classes < 3:
            raise StepError("TE_UI_PASSWORD must be at least 8 characters and use 3 of: uppercase, "
                            "lowercase, digits, symbols")
    return Settings(user, default, new or "", verify_tls, timeout)


def sign_in(device: Device, settings: Settings, guard: DeviceGuard) -> tuple[TevaUi, str]:
    """Log in with the password this device most likely has; try the other one only after a
    clear rejection, and only while the appliance's failed-login budget allows it."""
    candidates = [("TE_DEFAULT_PASSWORD", settings.default_password)]
    if settings.new_password:
        candidates.append(("TE_UI_PASSWORD", settings.new_password))
        if guard.password_changed(device):
            candidates.reverse()
    rejected: list[str] = []
    for name, password in candidates:
        if rejected and guard.failed_logins_left(device) < 1:
            break
        ui = TevaUi(device, settings, guard)
        try:
            ui.authenticate(password)
            guard.record_password_changed(device, name == "TE_UI_PASSWORD")
            return ui, name
        except LoginRejected:
            ui.close()
            rejected.append(name)
        except BaseException:
            ui.close()
            raise
    untried = [name for name, _ in candidates if name not in rejected]
    raise StepError(
        f"the appliance rejected {' and '.join(rejected)} for user '{settings.ui_user}'"
        + (f" ({untried[0]} was not tried, to stay below the appliance's lockout limit)" if untried else "")
        + f". Nothing was changed. Check the current password by signing in at "
        f"https://{device.url_host} in a browser, then correct .env. Do not rerun repeatedly: the "
        "appliance locks its web login for 15 minutes after repeated failures.")


def process_device(device: Device, settings: Settings, report: Reporter,
                   guard: DeviceGuard) -> bool | str:
    report.task(device, "ui_auth", f"Sign in to the web UI at {device.ip}")
    start = time.monotonic()
    try:
        ui, used = sign_in(device, settings, guard)
    except StepError as exc:
        report.result(device, "ui_auth", "failed", str(exc), start)
        report.skip(device, STAGES[1:], "sign-in failed")
        return False
    if used == "TE_UI_PASSWORD":
        ui.close()
        report.result(device, "ui_auth", "ok", "signed in with TE_UI_PASSWORD", start)
        report.result(device, "password_change", "ok",
                      "already done: TE_UI_PASSWORD is active, so nothing was changed", time.monotonic())
        report.skip(device, STAGES[2:], "password was already changed")
        return DONE_BEFORE
    report.result(device, "ui_auth", "ok", "signed in with TE_DEFAULT_PASSWORD (initial password)", start)

    report.task(device, "password_change", "Submit TE_UI_PASSWORD as the new web-UI password")
    start = time.monotonic()
    try:
        ui.change_password(settings.default_password, settings.new_password)
    except StepError as exc:
        report.result(device, "password_change", "failed",
                      f"{sentence(str(exc))} To find out which password is active, rerun with --check-login "
                      f"--only {device.name} once https://{device.url_host} loads.", start)
        report.skip(device, STAGES[2:], "password change not confirmed")
        return False
    finally:
        ui.close()
    guard.record_password_changed(device)
    report.result(device, "password_change", "changed", "the appliance confirmed the new password", start)

    # Use a fresh cookie jar: the old session may be invalidated by the password change.
    report.task(device, "ui_reauth", "Sign in again with TE_UI_PASSWORD in a new session")
    start = time.monotonic()
    new_ui = TevaUi(device, settings, guard)
    try:
        new_ui.authenticate(settings.new_password)
        new_ui.request("GET", "/api/session")
    except StepError as exc:
        report.result(device, "ui_reauth", "failed",
                      f"{sentence(str(exc))} The appliance had confirmed the change; sign in at "
                      f"https://{device.url_host} with TE_UI_PASSWORD to check before rerunning.", start)
        return False
    finally:
        new_ui.close()
    report.result(device, "ui_reauth", "ok", "TE_UI_PASSWORD works in a new session", start)
    return True


def check_login(device: Device, settings: Settings, report: Reporter, guard: DeviceGuard) -> bool:
    """Read-only: report which configured password the appliance accepts; never changes anything."""
    report.task(device, "ui_auth", f"Check which password the web UI at {device.ip} accepts (read-only)")
    start = time.monotonic()
    try:
        ui, used = sign_in(device, settings, guard)
    except StepError as exc:
        report.result(device, "ui_auth", "failed", str(exc), start)
        return False
    try:
        ui.request("GET", "/api/session")
    except StepError as exc:
        report.result(device, "ui_auth", "failed", str(exc), start)
        return False
    finally:
        ui.close()
    state = ("password not changed yet; run with --apply to change it" if used == "TE_DEFAULT_PASSWORD"
             else "password already changed; continue with load_keys.py")
    report.result(device, "ui_auth", "ok", f"{used} works ({state}); nothing was changed", start)
    return True


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--inventory", type=Path, default=HERE / "inventory.csv")
    p.add_argument("--env-file", type=Path, default=None, help="settings file (default: .env here)")
    p.add_argument("--only", action="append", default=[], metavar="NAME")
    p.add_argument("--parallel", action="store_true", help="process multiple devices concurrently")
    p.add_argument("--workers", type=int, default=None,
                   help="worker count with --parallel (default: 4); without it, only 1 is allowed")
    p.add_argument("--timeout", type=int, default=15)
    p.add_argument("--verify-tls", action="store_true")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true",
                      help="actually change passwords; omitted = preflight only")
    mode.add_argument("--check-login", action="store_true",
                      help="read-only: show which password one device accepts; requires --only NAME")
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
        report = Reporter(HERE, prefix="teva-password")
    except StepError as exc:
        print(f"failed: {exc}", file=sys.stderr)
        return 2
    try:
        report.say("PLAY [Change the TEVA web-UI password before SSH-key onboarding]")
        try:
            devices = read_inventory(args.inventory.expanduser().resolve(), args.only)
            env = EnvSettings((args.env_file or HERE / ".env").expanduser().resolve(),
                              explicit=args.env_file is not None)
            settings = load_settings(env, verify_tls=args.verify_tls, timeout=args.timeout,
                                     require_new_password=not args.check_login)
            if args.check_login and (len(args.only) != 1 or len(devices) != 1):
                raise StepError("--check-login requires exactly one --only NAME")
            if args.apply:
                require_serial_confirmation(devices, args.parallel)
            guard = DeviceGuard(HERE / "logs" / "device-guard.json")
        except StepError as exc:
            return report.preflight_failed(str(exc))
        report.say(f"Inventory: {args.inventory} ({len(devices)} selected device(s))")
        report.say("Settings: " + env.describe(PASSWORD_NAMES) + " (values are never printed)")
        for note in env.notes:
            report.say(f"Note: {note}")
        report.say("HTTPS certificate verification: " + ("enabled" if args.verify_tls else
                   "disabled for the appliance's self-signed certificate"))
        if args.check_login:
            result = check_login(devices[0], settings, report, guard)
            report.recap(devices)
            if guard.save_failed:
                report.say(f"WARNING: {guard.path} could not be updated during this run, so its "
                           "safety record may be incomplete. Wait 15 minutes before rerunning, and "
                           "make sure the logs/ folder is writable.")
            return 0 if result else 1
        if not args.apply:
            report.say("Dry run: settings are valid and no device was contacted; add --apply to "
                       "change passwords")
            for device in devices:
                report.skip(device, STAGES, "dry run; add --apply")
            report.recap(devices)
            return 0
        mode = ("serial (Y required before each next device)" if not args.parallel else
                f"parallel ({min(workers, len(devices))} worker(s) after the first device succeeds)")
        report.say(f"Execution: {mode}; one isolated web-UI session per device")
        results, interrupted = run_devices(
            devices, lambda device: process_device(device, settings, report, guard), report,
            parallel=args.parallel, workers=workers, stages=STAGES, confirm=True,
            interrupt_hint=INTERRUPT_HINT)
        report.recap(devices)
        report.say("Next: run load_keys.py. Changing the web-UI password can remove SSH keys that "
                   "were uploaded before, so always upload keys after the password change.")
        if guard.save_failed:
            report.say(f"WARNING: {guard.path} could not be updated during this run, so its safety "
                       "record may be incomplete. Wait 15 minutes before rerunning, and make sure "
                       "the logs/ folder is writable.")
        if interrupted:
            return 130
        return 0 if len(results) == len(devices) and all(results.values()) else 1
    finally:
        report.write_csv()
        report.close()


if __name__ == "__main__":
    raise SystemExit(main())

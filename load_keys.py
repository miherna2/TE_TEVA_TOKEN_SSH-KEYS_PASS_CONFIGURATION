#!/usr/bin/env python3
"""Install a TEVA SSH public key through its HTTPS web UI, without opening SSH."""

from __future__ import annotations

import argparse
import getpass
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from common import (DONE_BEFORE, HERE, Device, EnvSettings, Reporter, StepError, check_value,
                    execution_workers, expand_path, prepare_console, read_inventory,
                    require_serial_confirmation, run_devices, sentence)
from device_guard import DeviceGuard
from ssh_public_key import load_public_key
from teva_ui import LoginRejected, TevaUi as BaseTevaUi

STAGES = ("ui_auth", "key_upload")
INTERRUPT_HINT = "If its key upload had already been sent, rerun for that device: it will detect the key."


@dataclass(frozen=True)
class Settings:
    ui_user: str
    ui_password: str = field(repr=False)
    public_key: str = field(repr=False)
    fingerprint: str
    md5_fingerprint: str
    key_type: str
    verify_tls: bool
    timeout: int


def load_settings(args: argparse.Namespace, env: EnvSettings) -> Settings:
    ui_user = env.get("TE_UI_USERNAME")
    if not ui_user:
        if not sys.stdin.isatty():
            raise StepError(f"TE_UI_USERNAME is missing from {env.path.name} and the environment")
        ui_user = input("TEVA web-UI username: ").strip()
        check_value("TE_UI_USERNAME", ui_user, "prompt")
    ui_password = env.get("TE_UI_PASSWORD")
    if not ui_password:
        if not sys.stdin.isatty():
            raise StepError(f"TE_UI_PASSWORD is missing from {env.path.name} and the environment")
        ui_password = getpass.getpass("TEVA web-UI password (TE_UI_PASSWORD): ")
        check_value("TE_UI_PASSWORD", ui_password, "prompt")
    if not ui_user or not ui_password:
        raise StepError("web-UI username and password are required")
    public_raw = args.public_key or env.get("TE_SSH_PUBLIC_KEY_PATHS")
    if not public_raw:
        raise StepError("TE_SSH_PUBLIC_KEY_PATHS (the .pub file to upload) is required")
    # A Windows drive-letter colon is not a path-list separator here.
    public_path = expand_path(public_raw, Path.cwd() if args.public_key else env.path.parent)
    public = load_public_key(public_path)
    return Settings(ui_user, ui_password, public.text, public.fingerprint_sha256,
                    public.fingerprint_md5, public.key_type, args.verify_tls, args.timeout)


class TevaUi(BaseTevaUi):
    def key_is_present(self) -> bool:
        # TEVA's key list uses "ssh-ed25519 aa:bb:..." (MD5), not our SHA256 display value.
        response = self.request("GET", "/api/access/sshkey")
        try:
            entries = response.json()
        except ValueError as exc:
            raise StepError("the appliance's SSH-key list was not readable (not JSON). "
                            "Nothing was changed.") from exc
        if isinstance(entries, dict):
            entries = entries.get("keys")
        if not isinstance(entries, list):
            raise StepError("the appliance's SSH-key list had an unexpected format. Nothing was changed.")
        fingerprints = {
            self.settings.fingerprint.casefold(),
            self.settings.md5_fingerprint,
            f"{self.settings.key_type} {self.settings.md5_fingerprint}".casefold(),
        }
        return any(
            isinstance(item, dict)
            and isinstance(item.get("fingerprint"), str)
            and item["fingerprint"].strip().casefold() in fingerprints
            for item in entries
        )

    def upload(self) -> bool:
        """Upload once if the key is missing; return True if it was added. Never retried."""
        if self.key_is_present():
            return False
        # request() refreshes the authenticated mutation CSRF token before POST.
        response = self.request("POST", "/api/access/sshkey",
                                payload={"key": self.settings.public_key}, allow=(409,))
        if response.status_code == 409:
            return False
        try:
            body = response.json()
        except ValueError as exc:
            raise StepError("the appliance's reply did not confirm the upload; rerun for this "
                            "device to check whether the key is present") from exc
        if isinstance(body, dict) and body.get("success") is False:
            raise StepError("the appliance refused the SSH public key. Nothing was changed.")
        if not self.key_is_present():
            raise StepError("the appliance accepted the upload, but the key is not in its SSH-key "
                            "list; check the SSH keys page in the web UI")
        return True


def process_device(device: Device, settings: Settings, report: Reporter,
                   guard: DeviceGuard) -> bool | str:
    ui = TevaUi(device, settings, guard)
    try:
        report.task(device, "ui_auth", f"Sign in to the web UI at {device.ip} with TE_UI_PASSWORD")
        start = time.monotonic()
        try:
            ui.authenticate(settings.ui_password)
        except LoginRejected as exc:
            report.result(device, "ui_auth", "failed",
                          f"{sentence(str(exc))} Nothing was changed. If this appliance still has "
                          "its initial password, run change_password.py first. Do not rerun repeatedly: the "
                          "appliance locks its web login for 15 minutes after repeated failures.", start)
            report.skip(device, STAGES[1:], "sign-in failed")
            return False
        except StepError as exc:
            report.result(device, "ui_auth", "failed", str(exc), start)
            report.skip(device, STAGES[1:], "sign-in failed")
            return False
        report.result(device, "ui_auth", "ok", "signed in with TE_UI_PASSWORD", start)

        report.task(device, "key_upload", f"Upload public key {settings.fingerprint}")
        start = time.monotonic()
        try:
            changed = ui.upload()
        except StepError as exc:
            report.result(device, "key_upload", "failed", sentence(str(exc)), start)
            return False
        report.result(device, "key_upload", "changed" if changed else "ok",
                      "key uploaded and confirmed in the appliance's SSH-key list" if changed
                      else "key already present; nothing was changed", start)
        return True if changed else DONE_BEFORE
    finally:
        ui.close()


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--inventory", type=Path, default=HERE / "inventory.csv")
    p.add_argument("--env-file", type=Path, default=None, help="settings file (default: .env here)")
    p.add_argument("--public-key", type=str)
    p.add_argument("--only", action="append", default=[], metavar="NAME")
    p.add_argument("--parallel", action="store_true", help="process multiple devices concurrently")
    p.add_argument("--workers", type=int, default=None,
                   help="worker count with --parallel (default: 4); without it, only 1 is allowed")
    p.add_argument("--timeout", type=int, default=15)
    p.add_argument("--verify-tls", action="store_true")
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
        report = Reporter(HERE)
    except StepError as exc:
        print(f"failed: {exc}", file=sys.stderr)
        return 2
    try:
        report.say("PLAY [Install the TEVA SSH public key through the web UI]")
        try:
            devices = read_inventory(args.inventory.expanduser().resolve(), args.only)
            env = EnvSettings((args.env_file or HERE / ".env").expanduser().resolve(),
                              explicit=args.env_file is not None)
            settings = load_settings(args, env)
            require_serial_confirmation(devices, args.parallel)
            guard = DeviceGuard(HERE / "logs" / "device-guard.json")
        except StepError as exc:
            return report.preflight_failed(str(exc))
        report.say(f"Inventory: {args.inventory} ({len(devices)} selected device(s))")
        report.say("Settings: " + env.describe(("TE_UI_USERNAME", "TE_UI_PASSWORD",
                                                "TE_SSH_PUBLIC_KEY_PATHS")) + " (values are never printed)")
        for note in env.notes:
            report.say(f"Note: {note}")
        report.say(f"Public key: {settings.key_type} {settings.fingerprint}")
        mode = ("serial (Y required before each next device)" if not args.parallel else
                f"parallel ({min(workers, len(devices))} worker(s) after the first device succeeds)")
        report.say(f"Execution: {mode}; web UI only, no SSH connection")
        report.say("HTTPS certificate verification: " + ("enabled" if settings.verify_tls
                   else "disabled for the appliance's self-signed certificate"))
        results, interrupted = run_devices(
            devices, lambda device: process_device(device, settings, report, guard), report,
            parallel=args.parallel, workers=workers, stages=STAGES, confirm=True,
            interrupt_hint=INTERRUPT_HINT)
        report.recap(devices)
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

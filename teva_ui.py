"""HTTPS session for the TEVA web UI: the browser's login/CSRF flow, with safety limits.

Safety rules enforced here, for every script and every future edit:
- Only the requests the appliance's own browser UI makes are allowed (ALLOWED).
- At most MAX_REQUESTS per session, over one connection, paced ``spacing`` apart per appliance.
- GET /login must answer normally before any credential is sent (health gate).
- HTTP 5xx, timeouts, and redirects stop the device immediately; nothing is retried.
- After Ctrl+C (common.STOP) no new request is sent.
"""

from __future__ import annotations

import errno
import ssl
import threading
import time
from typing import Any, Protocol

import httpx

from common import STOP, Device, StepError


ALLOWED = frozenset({
    ("GET", "/login"), ("GET", "/api/session"), ("GET", "/api/app-config"),
    ("POST", "/api/login"), ("POST", "/api/access"),
    ("GET", "/api/access/sshkey"), ("POST", "/api/access/sshkey"),
})
MUTATIONS = frozenset({"/api/access", "/api/access/sshkey"})
MAX_REQUESTS = 12       # per session; a normal run needs 5-8
CONNECT_TIMEOUT = 5.0   # an unreachable IP fails fast; replies may use the full --timeout
UNREACHABLE = {errno.EHOSTUNREACH, errno.ENETUNREACH, getattr(errno, "EHOSTDOWN", 64), 10051, 10065}
_LAST_SENT: dict[str, float] = {}  # per appliance IP, shared by every session in this run
_PACE_LOCK = threading.Lock()


class UiSettings(Protocol):
    ui_user: str
    verify_tls: bool
    timeout: int


class UiHttpError(StepError):
    def __init__(self, method: str, path: str, status: int, message: str) -> None:
        self.status = status
        super().__init__(message)


class UiUnavailable(UiHttpError):
    """HTTP 5xx: nginx answered but the web-UI backend behind it did not."""


class NotSent(StepError):
    """Refused locally before anything reached the appliance."""
    sent = False


class UiNoAnswer(StepError):
    """The connection failed or timed out; ``sent`` says whether the request left this computer."""

    def __init__(self, message: str, sent: bool) -> None:
        self.sent = sent
        super().__init__(message)


class LoginRejected(StepError):
    """The appliance checked the credentials and said no."""


class PasswordChangeRequired(StepError):
    def __init__(self) -> None:
        super().__init__("the appliance still requires its initial web-UI password change; run "
                         "change_password.py for this device first. Nothing was changed.")


def appliance_reason(body: Any) -> str:
    """The appliance's own short explanation from a JSON error body, made safe to print."""
    if not isinstance(body, dict):
        return ""
    reason = body.get("error") or body.get("detail") or body.get("message") or ""
    if isinstance(reason, dict):
        reason = reason.get("content") or ""
    text = "".join(char for char in str(reason) if char.isprintable()).strip()
    return text[:150]


def connection_problem(exc: httpx.HTTPError, device: Device, timeout: int) -> str:
    causes: list[BaseException] = []
    current: BaseException | None = exc
    while current is not None and len(causes) < 8:
        causes.append(current)
        current = current.__cause__ or current.__context__
    if isinstance(exc, httpx.ConnectTimeout):
        seconds = min(CONNECT_TIMEOUT, timeout)
        return (f"no answer from {device.ip} on port 443 within {seconds:g} s; check the IP "
                "address in inventory.csv, that the appliance is powered on, and your network/VPN")
    if isinstance(exc, httpx.TimeoutException):
        return (f"connected, but the web UI did not answer within {timeout} s; the appliance may "
                "be starting or overloaded")
    if any(isinstance(cause, ConnectionRefusedError) for cause in causes):
        return (f"{device.ip} refused the HTTPS connection: its web server is not running "
                "(still booting?) or this is not the right IP")
    if any(isinstance(cause, ssl.SSLCertVerificationError) for cause in causes):
        return ("the appliance's HTTPS certificate is not trusted; run without --verify-tls "
                "(the appliance uses a self-signed certificate) or install its CA certificate")
    if any(isinstance(cause, ssl.SSLError) for cause in causes):
        return "the TLS handshake failed: port 443 did not answer like the appliance web UI"
    if any(isinstance(cause, OSError) and cause.errno in UNREACHABLE for cause in causes):
        return f"no network route to {device.ip}; check the IP address and your network/VPN"
    return f"the HTTPS connection failed ({type(exc).__name__})"


class TevaUi:
    spacing = 0.25  # seconds between requests to one appliance; tests set 0
    transport: httpx.BaseTransport | None = None  # tests plug in a fake appliance here

    def __init__(self, device: Device, settings: UiSettings, guard: Any = None) -> None:
        self.device = device
        self.settings = settings
        self.guard = guard
        self.base = f"https://{device.url_host}"
        self.http = httpx.Client(
            verify=settings.verify_tls, trust_env=False, follow_redirects=False,
            timeout=httpx.Timeout(settings.timeout, connect=min(CONNECT_TIMEOUT, settings.timeout)),
            limits=httpx.Limits(max_connections=1), transport=self.transport,
        )
        self.csrf: str | None = None
        self.authenticated = False
        self.sent = 0

    def close(self) -> None:
        self.http.close()

    def request(self, method: str, path: str, *, payload: dict[str, Any] | None = None,
                allow: tuple[int, ...] = ()) -> httpx.Response:
        method = method.upper()
        if STOP.is_set():
            raise NotSent("stopped by Ctrl+C before the next request; nothing more was sent to "
                          "this appliance")
        if (method, path) not in ALLOWED:
            raise NotSent(f"internal safety check: {method} {path} is not part of the appliance's "
                          "web-UI flow, so it was not sent")
        mutation = method == "POST"
        if mutation and self.authenticated:
            self.refresh_mutation_csrf()
        if self.sent >= MAX_REQUESTS:
            raise NotSent(f"safety limit: stopped after {MAX_REQUESTS} requests to this appliance "
                          "in one session; nothing more was sent")
        with _PACE_LOCK:
            now = time.monotonic()
            wait = self.spacing - (now - _LAST_SENT.get(self.device.ip, float("-inf")))
            _LAST_SENT[self.device.ip] = now + max(wait, 0.0)
        if wait > 0:
            time.sleep(wait)
        if STOP.is_set():  # Ctrl+C may have arrived during the pause
            raise NotSent("stopped by Ctrl+C before the next request; nothing more was sent to "
                          "this appliance")
        if path == "/api/login" and self.guard:
            # Counted before sending, so an attempt interrupted by Ctrl+C, a killed process,
            # a 5xx, or a timeout is still counted; a successful login clears it again.
            self.guard.record_failed_login(self.device)
            if self.guard.save_failed:
                raise NotSent(f"could not update the safety record {self.guard.path}, so the "
                              "password was not sent. Make sure the logs/ folder is writable, "
                              "then rerun.")
        self.sent += 1
        changes = path in MUTATIONS
        headers = {"X-CSRFToken": self.csrf} if mutation and self.csrf else {}
        try:
            response = self.http.request(method, self.base + path, json=payload, headers=headers)
        except httpx.HTTPError as exc:
            problem = connection_problem(exc, self.device, self.settings.timeout)
            sent = not isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout))
            if sent and self.guard:
                # Connected but no proper reply: treat like a 5xx and leave the web UI alone.
                self.guard.record_outage(self.device)
            outcome = ("The appliance did not confirm the change, so it may or may not have been "
                       "applied." if changes and sent else "Nothing was changed.")
            raise UiNoAnswer(f"{problem}. {outcome}", sent) from exc
        token = response.headers.get("X-NewCSRFToken") or response.headers.get("X-CSRFToken")
        if isinstance(token, str) and token.strip() and token != "None":
            self.csrf = token
        try:
            body = response.json()
        except ValueError:
            body = None
        if isinstance(body, dict):
            body_token = body.get("csrfToken") or body.get("csrf_token")
            if isinstance(body_token, str) and body_token.strip():
                self.csrf = body_token
        status = response.status_code
        if 300 <= status < 400:
            raise StepError(f"{method} {path} was redirected (HTTP {status}); this address may not be "
                            "a ThousandEyes appliance web UI. The redirect was not followed.")
        if status >= 500:
            if self.guard:
                self.guard.record_outage(self.device)
            outcome = ("The change was not confirmed, so it may or may not have been applied."
                       if changes else "Nothing was changed.")
            raise UiUnavailable(method, path, status,
                                f"the appliance web server answered, but the web-UI service behind "
                                f"it is not running (HTTP {status}). {outcome} This tool stops here "
                                f"and does not retry. Open https://{self.device.url_host} in a "
                                "browser; if it does not load within about 10 minutes, restart the "
                                "appliance.")
        if (status == 403 and path != "/api/login" and isinstance(body, dict)
                and body.get("requiresPasswordChange")):
            raise PasswordChangeRequired()
        if status >= 400 and status not in allow:
            reason = appliance_reason(body)
            hint = {404: " The appliance does not offer this page; its software version may not "
                         "be supported by this tool.",
                    429: " The appliance is limiting requests; wait a few minutes."}.get(status, "")
            raise UiHttpError(method, path, status,
                              f"{method} {path} was refused (HTTP {status})"
                              + (f": appliance says \"{reason}\"" if reason else "") + "."
                              + hint + ("" if changes else " Nothing was changed."))
        return response

    def authenticate(self, password: str) -> None:
        if self.guard:
            self.guard.check(self.device)
        # Never reuse a previous session's token when starting a new login flow.
        self.authenticated = False
        self.csrf = None
        # Health gate: a 5xx, timeout, or refusal here stops before any credential is sent.
        self.request("GET", "/login")
        self.request("GET", "/api/session", allow=(401,))
        if not self.csrf:
            # The appliance UI performs this bootstrap GET before login POST
            # when /login and /api/session have not supplied a CSRF token.
            self.request("GET", "/api/app-config")
        if not self.csrf:
            raise StepError(f"{self.device.ip} answered, but not like a ThousandEyes appliance web UI "
                            "(no CSRF token), so no credentials were sent; check the IP address "
                            "in inventory.csv")
        # request() counts this attempt against the failed-login budget before sending it.
        response = self.request("POST", "/api/login", payload={
            "username": self.settings.ui_user, "password": password,
        }, allow=(403,))
        try:
            body = response.json()
        except ValueError:
            body = None
        locked = isinstance(body, dict) and bool(body.get("loginLocked") or body.get("lockedOut"))
        if self.guard and locked:
            self.guard.record_lockout(self.device)
        if locked:
            raise StepError("the appliance has temporarily locked its web login after repeated "
                            "failed attempts (about 15 minutes). Nothing was changed. Do not retry "
                            "now; afterwards, check the password in a browser before rerunning.")
        if response.status_code == 403:
            raise StepError("the appliance refused the login request itself (HTTP 403) before "
                            "checking the password; this usually means its session/CSRF check "
                            "failed. Nothing was changed. Wait a minute and rerun once; if it "
                            "repeats, sign in with a browser to check the appliance.")
        if not isinstance(body, dict):
            raise StepError("the login reply was not the appliance's usual JSON answer; this address "
                            "may not be a ThousandEyes appliance web UI. Nothing was changed.")
        if body.get("success") is not True:
            raise LoginRejected(f"the appliance rejected the password for user "
                                f"'{self.settings.ui_user}'")
        if self.guard:
            self.guard.record_login_ok(self.device)
        self.authenticated = True

    def refresh_mutation_csrf(self) -> None:
        # Never fall back to a bootstrap/login token if app-config omits its
        # authenticated mutation token; a stale token can look like a password gate.
        self.csrf = None
        self.request("GET", "/api/app-config")
        if not self.csrf:
            raise StepError("the appliance did not provide a CSRF token, so the change was not "
                            "sent. Nothing was changed.")

    def change_password(self, original: str, password: str) -> None:
        # The initial password gate allows /api/access even when other mutations fail.
        # request() refreshes CSRF in this authenticated cookie session before POST.
        response = self.request("POST", "/api/access", payload={
            "original": original, "password": password, "confirm": password,
        })
        try:
            body = response.json()
        except ValueError as exc:
            raise StepError("the appliance's reply did not confirm the password change, so it may "
                            "or may not have been applied") from exc
        if isinstance(body, dict) and body.get("success") is False:
            reason = appliance_reason(body)
            raise StepError("the appliance refused the new password"
                            + (f": \"{reason}\"" if reason else "")
                            + ". The password was not changed; choose a TE_UI_PASSWORD that meets "
                            "the appliance's password rules.")

"""Minimal SonicOS REST client for API-pull devices.

SonicOS 7 exposes a REST API under ``/api/sonicos``. The flow used here mirrors
the SonicWall KB ("Export Tech Support Report (TSR) using SonicOS API"):

    POST {base}/auth   (HTTP Basic, JSON body {"override": true} for Gen7)
    GET  {base}/export/tech-support-report   -> download the TSR
    DELETE {base}/auth                       -> release the session (best effort)

The client uses only the standard library (urllib + cookiejar) so it adds no
runtime dependency. Appliance certificates are typically self-signed, so TLS
verification is configurable and off by default. Every failure is surfaced as a
``SonicOSError`` carrying a machine-readable ``kind`` and (when available) the
HTTP ``status_code``, so callers can render precise, user-facing status.
"""

from __future__ import annotations

import base64
import http.cookiejar
import json
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional

from .config import get_settings

settings = get_settings()

# Error classifications surfaced to the UI.
KIND_AUTH_FAILED = "auth_failed"          # reached the API, login rejected
KIND_INVALID_CREDENTIALS = "invalid_credentials"  # HTTP 401
KIND_SSL = "ssl_error"                    # certificate / TLS handshake problem
KIND_TIMEOUT = "timeout"                  # connection or read timed out
KIND_UNREACHABLE = "unreachable"          # host/port not reachable
KIND_API_DISABLED = "api_disabled"        # 403/404 — API off or no API access
KIND_HTTP = "http_error"                  # any other HTTP status
KIND_BAD_RESPONSE = "bad_response"        # empty/garbled payload


class SonicOSError(Exception):
    """Any connectivity or API error talking to a SonicWall, with a category."""

    def __init__(self, message: str, *, kind: str = "error",
                 status_code: Optional[int] = None, detail: str = "") -> None:
        super().__init__(message)
        self.kind = kind
        self.status_code = status_code
        self.detail = detail


def _parse_json(raw: bytes) -> dict:
    try:
        data = json.loads(raw or b"{}")
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, ValueError):
        return {}


def _explicit_failure(data: dict) -> bool:
    """True only when the payload explicitly reports failure."""
    st = data.get("status")
    if isinstance(st, dict) and st.get("success") is False:
        return True
    return data.get("success") is False


def _extract_message(raw: bytes) -> str:
    """Pull a human-readable message out of a SonicOS status payload."""
    data = _parse_json(raw)
    st = data.get("status") if isinstance(data, dict) else None
    info = (st.get("info") if isinstance(st, dict) else None) or data.get("info")
    if isinstance(info, list) and info and isinstance(info[0], dict):
        msg = info[0].get("message") or info[0].get("msg")
        if msg:
            return str(msg).strip()
    if isinstance(st, dict) and st.get("message"):
        return str(st["message"]).strip()
    if data.get("message"):
        return str(data["message"]).strip()
    text = (raw or b"").decode("utf-8", "replace").strip()
    return text[:200]


def _unwrap_report(raw: bytes) -> str:
    """Extract the report text from a JSON-wrapped TSR response.

    Firmware envelopes vary, so we return the longest string found anywhere in
    the structure — the report body dwarfs any status/metadata strings.
    """
    data = _parse_json(raw)
    best = ""

    def walk(obj: object) -> None:
        nonlocal best
        if isinstance(obj, str):
            if len(obj) > len(best):
                best = obj
        elif isinstance(obj, dict):
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)

    walk(data)
    return best


@dataclass
class SonicOSClient:
    hostname: str
    port: int
    username: str
    password: str
    verify_tls: Optional[bool] = None
    timeout: Optional[int] = None
    send_override: Optional[bool] = None  # Gen7 login override (release other sessions)

    def __post_init__(self) -> None:
        if self.verify_tls is None:
            self.verify_tls = settings.sonicos_verify_tls
        if self.timeout is None:
            self.timeout = settings.sonicos_timeout_seconds
        if self.send_override is None:
            self.send_override = getattr(settings, "sonicos_login_override", True)
        self._jar = http.cookiejar.CookieJar()
        ctx = ssl.create_default_context()
        if not self.verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self._jar),
            urllib.request.HTTPSHandler(context=ctx))

    @property
    def _base(self) -> str:
        return f"https://{self.hostname}:{self.port}{settings.sonicos_api_base}"

    def _auth_header(self) -> str:
        raw = f"{self.username}:{self.password}".encode("utf-8")
        return "Basic " + base64.b64encode(raw).decode("ascii")

    # -- low level --------------------------------------------------------
    def _open(self, req: urllib.request.Request) -> tuple[int, bytes]:
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                return getattr(resp, "status", 200), resp.read()
        except urllib.error.HTTPError as exc:
            body = b""
            try:
                body = exc.read()
            except Exception:  # noqa: BLE001
                pass
            raise self._http_error(exc.code, body) from exc
        except urllib.error.URLError as exc:
            raise self._url_error(exc.reason) from exc
        except ssl.SSLError as exc:
            raise SonicOSError(f"TLS error: {exc}", kind=KIND_SSL, detail=str(exc)) from exc
        except (socket.timeout, TimeoutError) as exc:
            raise SonicOSError("Connection timed out", kind=KIND_TIMEOUT, detail=str(exc)) from exc
        except OSError as exc:
            raise SonicOSError(
                f"Could not reach {self.hostname}:{self.port}",
                kind=KIND_UNREACHABLE, detail=str(exc)) from exc

    def _http_error(self, code: int, body: bytes) -> SonicOSError:
        msg = _extract_message(body)
        if code == 401:
            return SonicOSError(msg or "Invalid administrator credentials",
                                kind=KIND_INVALID_CREDENTIALS, status_code=code, detail=msg)
        if code == 403:
            return SonicOSError(
                msg or "Access forbidden — the account may lack API access or the SonicOS API is disabled",
                kind=KIND_API_DISABLED, status_code=code, detail=msg)
        if code == 404:
            return SonicOSError(
                msg or "SonicOS API endpoint not found — the API may be disabled or unsupported on this firmware",
                kind=KIND_API_DISABLED, status_code=code, detail=msg)
        return SonicOSError(msg or f"SonicOS returned HTTP {code}",
                            kind=KIND_HTTP, status_code=code, detail=msg)

    def _url_error(self, reason: object) -> SonicOSError:
        if isinstance(reason, ssl.SSLCertVerificationError):
            return SonicOSError(
                "TLS certificate verification failed (self-signed certificate?). "
                "Disable TLS verification to connect.",
                kind=KIND_SSL, detail=str(reason))
        if isinstance(reason, ssl.SSLError):
            return SonicOSError(f"TLS error: {reason}", kind=KIND_SSL, detail=str(reason))
        if isinstance(reason, (socket.timeout, TimeoutError)):
            return SonicOSError("Connection timed out", kind=KIND_TIMEOUT, detail=str(reason))
        return SonicOSError(
            f"Could not reach {self.hostname}:{self.port} ({reason})",
            kind=KIND_UNREACHABLE, detail=str(reason))

    # -- operations -------------------------------------------------------
    def login(self) -> dict:
        """Authenticate (HTTP Basic) and establish a session cookie.

        Sends ``{"override": true}`` so a Gen7 login pre-empts an existing admin
        session. Success requires HTTP 2xx without an explicit ``success:false``.
        """
        body = json.dumps({"override": bool(self.send_override)}).encode("utf-8")
        req = urllib.request.Request(f"{self._base}/auth", data=body, method="POST")
        req.add_header("Authorization", self._auth_header())
        req.add_header("Accept", "application/json")
        req.add_header("Content-Type", "application/json")
        status_code, raw = self._open(req)
        data = _parse_json(raw)
        if _explicit_failure(data):
            msg = _extract_message(raw) or "Authentication failed"
            raise SonicOSError(msg, kind=KIND_AUTH_FAILED, status_code=status_code, detail=msg)
        return data

    def get_version(self) -> dict:
        """Best-effort identity probe. Never raises — returns {} on any error."""
        req = urllib.request.Request(f"{self._base}/version", method="GET")
        req.add_header("Accept", "application/json")
        try:
            _code, raw = self._open(req)
        except SonicOSError:
            return {}
        return _parse_json(raw)

    def export_tech_support(self) -> bytes:
        """Download the Tech Support Report (returns the raw report bytes).

        The SonicOS export endpoint validates the request headers and only
        accepts ``application/json`` (otherwise: "API does not support the
        content type requested"). The report itself is returned as text; some
        firmware wraps it in a JSON envelope, which we unwrap.
        """
        req = urllib.request.Request(
            f"{self._base}/export/tech-support-report", method="GET")
        req.add_header("Accept", "application/json")
        req.add_header("Content-Type", "application/json")
        _code, raw = self._open(req)
        if not raw or not raw.strip():
            raise SonicOSError("The TSR export returned an empty response",
                               kind=KIND_BAD_RESPONSE, status_code=_code)
        # If the firmware returned a JSON envelope, pull the report text out of it.
        if raw.lstrip()[:1] in (b"{", b"["):
            text = _unwrap_report(raw)
            if text:
                return text.encode("utf-8")
        return raw

    def logout(self) -> None:
        """Release the SonicOS session (best effort; never raises)."""
        try:
            req = urllib.request.Request(f"{self._base}/auth", method="DELETE")
            req.add_header("Accept", "application/json")
            self._open(req)
        except SonicOSError:
            pass

    def test_connection(self) -> dict:
        """Login + identity probe. Returns the version dict or raises SonicOSError."""
        self.login()
        return self.get_version()

"""Configurable SonicOS API workflow engine.

Executes a DB-stored :class:`~app.models.ApiFlowConfig` (an ordered list of
steps) against a firewall using only the standard library, so the whole
"Connect via API" flow — endpoints, HTTP methods, headers, query, body, auth,
SSL verification, success conditions, and value extraction — is editable from
the Server Admin UI without code changes.

A step is a JSON dict::

    {
      "name": "Authenticate",
      "method": "POST",
      "path": "/auth",                       # appended to config.api_base
      "auth": "basic",                       # basic | bearer | none | inherit
      "headers": {"Accept": "application/json", "Content-Type": "application/json"},
      "query": {},
      "body": "{\\"override\\": true}",         # string or JSON; supports {{vars}}
      "success": {                            # all conditions must hold
        "status_codes": [200],
        "json_not_false": "status.success",   # this JSON path must not be false
        "body_contains": ""
      },
      "extract": {                            # capture values for later steps
        "token": {"source": "json", "path": "status.token"}
      },
      "is_tsr": false,                        # this step's body IS the TSR
      "continue_on_error": false              # e.g. logout
    }

Template variables available in path/query/headers/body: ``{{ip}}``,
``{{hostname}}``, ``{{port}}``, ``{{username}}``, ``{{password}}``,
``{{basic_credentials}}`` (base64 user:pass), plus anything ``extract``-ed.
``run_flow`` returns a per-step trace for the tester and the captured TSR text.
"""

from __future__ import annotations

import base64
import http.cookiejar
import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import ApiFlowConfig

_VAR_RE = re.compile(r"\{\{\s*([a-zA-Z0-9_]+)\s*\}\}")
_REDACTED = "***"


# ---------------------------------------------------------------------------
# default configuration (mirrors the verified hardcoded SonicOS Gen7 flow)
# ---------------------------------------------------------------------------
def default_gen7_steps() -> list[dict]:
    return [
        {"name": "Authenticate", "method": "POST", "path": "/auth", "auth": "basic",
         "headers": {"Accept": "application/json", "Content-Type": "application/json"},
         "query": {}, "body": '{"override": true}',
         "success": {"status_codes": [200], "json_not_false": "status.success"},
         "extract": {}, "is_tsr": False, "continue_on_error": False},
        {"name": "Export TSR", "method": "GET", "path": "/export/tech-support-report",
         "auth": "basic",
         "headers": {"Accept": "application/json", "Content-Type": "application/json"},
         "query": {}, "body": "",
         "success": {"status_codes": [200]},
         "extract": {}, "is_tsr": True, "continue_on_error": False},
        {"name": "Logout", "method": "DELETE", "path": "/auth", "auth": "basic",
         "headers": {"Accept": "application/json"}, "query": {}, "body": "",
         "success": {"status_codes": [200]},
         "extract": {}, "is_tsr": False, "continue_on_error": True},
    ]


def default_config_dict() -> dict:
    return {
        "name": "SonicOS Gen7", "description": "Default SonicOS 7 API flow.",
        "version_label": "Gen7", "auth_type": "basic", "verify_tls": False,
        "timeout_seconds": 30, "api_base": "/api/sonicos",
        "steps": default_gen7_steps(),
    }


def config_to_dict(cfg: ApiFlowConfig) -> dict:
    return {
        "id": cfg.id, "name": cfg.name, "description": cfg.description,
        "version_label": cfg.version_label, "is_active": cfg.is_active,
        "auth_type": cfg.auth_type, "verify_tls": cfg.verify_tls,
        "timeout_seconds": cfg.timeout_seconds, "api_base": cfg.api_base,
        "steps": cfg.steps or [],
    }


def get_active_config(db: Session) -> Optional[ApiFlowConfig]:
    """The active flow config, or None. No side effects (so connect falls back
    to the legacy client when nothing is configured)."""
    return db.scalar(select(ApiFlowConfig).where(ApiFlowConfig.is_active.is_(True)))


def ensure_default_config(db: Session) -> ApiFlowConfig:
    """Create the default Gen7 config (active) if no configs exist yet."""
    existing = db.scalar(select(ApiFlowConfig).limit(1))
    if existing is not None:
        return db.scalar(select(ApiFlowConfig).where(ApiFlowConfig.is_active.is_(True))) or existing
    d = default_config_dict()
    cfg = ApiFlowConfig(name=d["name"], description=d["description"],
                        version_label=d["version_label"], is_active=True,
                        auth_type=d["auth_type"], verify_tls=d["verify_tls"],
                        timeout_seconds=d["timeout_seconds"], api_base=d["api_base"],
                        steps=d["steps"])
    db.add(cfg)
    db.commit()
    db.refresh(cfg)
    return cfg


# ---------------------------------------------------------------------------
# template + extraction helpers
# ---------------------------------------------------------------------------
def _render(template: Any, ctx: dict) -> Any:
    if not isinstance(template, str):
        return template
    return _VAR_RE.sub(lambda m: str(ctx.get(m.group(1), m.group(0))), template)


def _render_obj(obj: Any, ctx: dict) -> Any:
    if isinstance(obj, str):
        return _render(obj, ctx)
    if isinstance(obj, dict):
        return {k: _render_obj(v, ctx) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_render_obj(v, ctx) for v in obj]
    return obj


def _parse_json(raw: bytes) -> Any:
    try:
        return json.loads(raw or b"")
    except (json.JSONDecodeError, ValueError):
        return None


def _json_path(data: Any, path: str) -> Any:
    cur = data
    for part in str(path).split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return cur


def _longest_string(data: Any) -> str:
    best = ""

    def walk(o: Any) -> None:
        nonlocal best
        if isinstance(o, str):
            if len(o) > len(best):
                best = o
        elif isinstance(o, dict):
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(data)
    return best


def _body_text(raw: bytes) -> str:
    if raw[:1].lstrip() in (b"{", b"[") or raw.lstrip()[:1] in (b"{", b"["):
        data = _parse_json(raw)
        if data is not None:
            longest = _longest_string(data)
            if longest:
                return longest
    return raw.decode("utf-8", "replace")


def _redact(headers: dict) -> dict:
    out = {}
    for k, v in headers.items():
        out[k] = _REDACTED if k.lower() == "authorization" else v
    return out


def _excerpt(raw: bytes, limit: int = 1500) -> str:
    text = raw.decode("utf-8", "replace")
    return text[:limit] + ("…" if len(text) > limit else "")


def _classify(exc: Exception) -> str:
    if isinstance(exc, ssl.SSLCertVerificationError):
        return ("TLS certificate verification failed (self-signed?). "
                "Disable TLS verification to connect.")
    if isinstance(exc, ssl.SSLError):
        return f"TLS error: {exc}"
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "Connection timed out"
    if isinstance(exc, urllib.error.URLError):
        reason = getattr(exc, "reason", exc)
        if isinstance(reason, ssl.SSLCertVerificationError):
            return ("TLS certificate verification failed (self-signed?). "
                    "Disable TLS verification to connect.")
        if isinstance(reason, (socket.timeout, TimeoutError)):
            return "Connection timed out"
        return f"Could not reach host ({reason})"
    return f"{type(exc).__name__}: {exc}"


def _eval_success(spec: dict, status: int, raw: bytes) -> tuple[bool, str]:
    codes = spec.get("status_codes")
    if codes:
        if status not in codes:
            return False, f"HTTP {status} (expected {codes})"
    elif not (200 <= status < 300):
        return False, f"HTTP {status}"
    path = spec.get("json_not_false")
    if path:
        val = _json_path(_parse_json(raw), path)
        if val is False:
            return False, f"response '{path}' reported failure"
    needle = spec.get("body_contains")
    if needle and needle not in raw.decode("utf-8", "replace"):
        return False, f"response did not contain '{needle}'"
    return True, ""


def _extract_value(rule: dict, raw: bytes, resp_headers: dict) -> Any:
    source = (rule or {}).get("source", "json")
    if source == "json":
        return _json_path(_parse_json(raw), rule.get("path", ""))
    if source == "regex":
        m = re.search(rule.get("pattern", ""), raw.decode("utf-8", "replace"))
        if m:
            return m.group(1) if m.groups() else m.group(0)
        return None
    if source == "header":
        return resp_headers.get(rule.get("name", ""))
    return None


# ---------------------------------------------------------------------------
# executor
# ---------------------------------------------------------------------------
def run_flow(config: dict, ctx: dict) -> dict:
    """Execute a flow config against a firewall.

    ``ctx`` must include hostname/ip, port, username, password and may include
    ``verify_tls`` (overrides the config default). Returns a dict with
    ``success``, ``error``, ``traces`` (one per step), ``extracted`` (captured
    vars) and ``tsr_text`` (the report body from the ``is_tsr`` step).
    """
    verify_tls = ctx.get("verify_tls")
    if verify_tls is None:
        verify_tls = bool(config.get("verify_tls", False))
    timeout = int(config.get("timeout_seconds") or 30)
    api_base = config.get("api_base", "") or ""
    auth_type_cfg = config.get("auth_type", "basic")

    ip = ctx.get("ip") or ctx.get("hostname") or ""
    port = ctx.get("port", 443)
    username = ctx.get("username", "")
    password = ctx.get("password", "")
    vars_: dict = {
        "ip": ip, "hostname": ip, "port": port,
        "username": username, "password": password,
        "basic_credentials": base64.b64encode(
            f"{username}:{password}".encode("utf-8")).decode("ascii"),
    }

    jar = http.cookiejar.CookieJar()
    sslctx = ssl.create_default_context()
    if not verify_tls:
        sslctx.check_hostname = False
        sslctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=sslctx))

    traces: list[dict] = []
    tsr_text = ""
    success = True
    error = ""

    for step in config.get("steps", []):
        name = step.get("name") or step.get("method") or "Step"
        method = (step.get("method") or "GET").upper()
        path = _render(step.get("path", ""), vars_)
        url = f"https://{ip}:{port}{api_base}{path}"
        query = {k: v for k, v in _render_obj(step.get("query") or {}, vars_).items()
                 if v not in (None, "")}
        if query:
            url = f"{url}?{urllib.parse.urlencode(query)}"

        headers = {k: _render(v, vars_) for k, v in (step.get("headers") or {}).items()}
        eff_auth = step.get("auth", "inherit")
        if eff_auth == "inherit":
            eff_auth = auth_type_cfg
        if "authorization" not in {h.lower() for h in headers}:
            if eff_auth == "basic":
                headers["Authorization"] = "Basic " + vars_["basic_credentials"]
            elif eff_auth == "bearer" and vars_.get("bearer_token"):
                headers["Authorization"] = "Bearer " + str(vars_["bearer_token"])

        body = step.get("body")
        data: Optional[bytes] = None
        if body not in (None, ""):
            if isinstance(body, str):
                data = _render(body, vars_).encode("utf-8")
            else:
                data = json.dumps(_render_obj(body, vars_)).encode("utf-8")

        trace = {"step": name, "method": method, "url": url,
                 "request_headers": _redact(headers), "status_code": None,
                 "response_excerpt": "", "elapsed_ms": 0, "success": False, "error": ""}
        start = time.perf_counter()
        try:
            req = urllib.request.Request(url, data=data, method=method)
            for k, v in headers.items():
                req.add_header(k, v)
            with opener.open(req, timeout=timeout) as resp:
                status_code = getattr(resp, "status", 200)
                raw = resp.read()
                resp_headers = {k: v for k, v in resp.headers.items()}
        except urllib.error.HTTPError as exc:
            status_code = exc.code
            try:
                raw = exc.read()
            except Exception:  # noqa: BLE001
                raw = b""
            resp_headers = {}
        except Exception as exc:  # noqa: BLE001 - connectivity/TLS/timeout
            trace["elapsed_ms"] = int((time.perf_counter() - start) * 1000)
            trace["error"] = _classify(exc)
            traces.append(trace)
            if step.get("continue_on_error"):
                continue
            success = False
            error = f"{name}: {trace['error']}"
            break

        trace["elapsed_ms"] = int((time.perf_counter() - start) * 1000)
        trace["status_code"] = status_code
        trace["response_excerpt"] = _excerpt(raw)

        ok, why = _eval_success(step.get("success") or {}, status_code, raw)
        trace["success"] = ok
        if not ok:
            trace["error"] = why

        for var, rule in (step.get("extract") or {}).items():
            val = _extract_value(rule, raw, resp_headers)
            if val is not None:
                vars_[var] = val

        if step.get("is_tsr") and ok:
            tsr_text = _body_text(raw)

        traces.append(trace)
        if not ok:
            if step.get("continue_on_error"):
                continue
            success = False
            error = f"{name}: {why}"
            break

    extracted = {k: v for k, v in vars_.items()
                 if k not in ("password", "basic_credentials")}
    return {"success": success, "error": error, "traces": traces,
            "extracted": extracted, "tsr_text": tsr_text}

"""Tests for the SonicOS API 'Connect via API' flow.

Covers the SonicOS client's auth contract and error classification, and the
``/devices/connect`` endpoint's streamlined (auto-register) and failure paths
with per-step status.
"""

from __future__ import annotations

import pytest

from app import sonicos
from app.sonicos import (
    SonicOSError, _explicit_failure, _extract_message, _parse_json,
    KIND_INVALID_CREDENTIALS, KIND_SSL, KIND_TIMEOUT,
)
from tests.conftest import auth_headers


# --- client payload helpers ----------------------------------------------
def test_parse_json_tolerant():
    assert _parse_json(b'{"a":1}') == {"a": 1}
    assert _parse_json(b"not json") == {}
    assert _parse_json(b"") == {}


def test_success_payload_not_failure():
    assert _explicit_failure({"status": {"success": True}}) is False
    assert _explicit_failure({}) is False  # empty 200 body is treated as success


def test_failure_payload_detected():
    assert _explicit_failure({"status": {"success": False}}) is True
    assert _explicit_failure({"success": False}) is True


def test_extract_message_from_status_info():
    raw = b'{"status":{"success":false,"info":[{"message":"Authentication failed."}]}}'
    assert _extract_message(raw) == "Authentication failed."


def test_login_raises_on_explicit_failure(monkeypatch):
    client = sonicos.SonicOSClient("10.0.0.1", 443, "admin", "bad")
    # Pretend the appliance returned 200 with an explicit failure payload.
    monkeypatch.setattr(
        client, "_open",
        lambda req: (200, b'{"status":{"success":false,"info":[{"message":"nope"}]}}'))
    with pytest.raises(SonicOSError) as exc:
        client.login()
    assert exc.value.kind == sonicos.KIND_AUTH_FAILED


def test_http_error_classification():
    client = sonicos.SonicOSClient("10.0.0.1", 443, "admin", "pw")
    assert client._http_error(401, b"").kind == KIND_INVALID_CREDENTIALS
    assert client._http_error(403, b"").kind == sonicos.KIND_API_DISABLED
    assert client._http_error(404, b"").kind == sonicos.KIND_API_DISABLED
    assert client._http_error(500, b"").status_code == 500


# --- endpoint: streamlined success + failure -----------------------------
class _OkClient:
    def __init__(self, *a, **k):
        pass

    def test_connection(self):
        return {"serial": "API-CONN-1", "model": "NSa 2700", "firmware_version": "SonicOS 7.3.0"}

    def export_tech_support(self):
        return b"SonicWall Tech Support Report\nSerial Number: API-CONN-1\n"

    def logout(self):
        return None


class _AuthFailClient:
    def __init__(self, *a, **k):
        pass

    def test_connection(self):
        raise SonicOSError("Invalid administrator credentials",
                           kind=KIND_INVALID_CREDENTIALS, status_code=401)


def _patch(monkeypatch, fake):
    import app.routers.devices as devices_mod
    import app.tasks as tasks_mod
    monkeypatch.setattr(devices_mod, "SonicOSClient", fake)
    monkeypatch.setattr(tasks_mod, "SonicOSClient", fake)


def test_connect_streamlined_registers_and_analyzes(client, org_a, monkeypatch):
    _patch(monkeypatch, _OkClient)
    h = auth_headers(client, org_a["email"], org_a["password"])
    res = client.post("/api/v1/devices/connect", headers=h, json={
        "customer_id": org_a["customer_id"], "hostname": "10.0.0.2", "port": 443,
        "username": "admin", "password": "pw", "verify_tls": False})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["connection_status"] == "ok"
    assert body["device_id"]
    # Step-by-step status is reported.
    names = [s["step"] for s in body["steps"]]
    assert "Authenticate" in names and "Export TSR" in names and "Analyze" in names
    assert all(s["status"] in ("ok", "warn") for s in body["steps"])
    # Device is now an API device.
    dev = client.get(f"/api/v1/devices/{body['device_id']}", headers=h).json()
    assert dev["connection_method"] == "api"


def test_connect_auth_failure_reports_clear_status(client, org_a, monkeypatch):
    _patch(monkeypatch, _AuthFailClient)
    h = auth_headers(client, org_a["email"], org_a["password"])
    res = client.post("/api/v1/devices/connect", headers=h, json={
        "customer_id": org_a["customer_id"], "hostname": "10.0.0.3", "port": 443,
        "username": "admin", "password": "wrong"})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["connection_status"] == "failed"
    assert body["error_kind"] == KIND_INVALID_CREDENTIALS
    assert body["http_status"] == 401
    auth_step = next(s for s in body["steps"] if s["step"] == "Authenticate")
    assert auth_step["status"] == "failed"

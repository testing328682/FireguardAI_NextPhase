"""Tests for the configurable SonicOS API flow (superadmin) + executor."""

from __future__ import annotations

from app.database import SessionLocal
from app.models import User
from app import api_flow


def _auth(client, email, password):
    res = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert res.status_code == 200, res.text
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


def _promote(user_id: str) -> None:
    db = SessionLocal()
    try:
        db.get(User, user_id).is_superadmin = True
        db.commit()
    finally:
        db.close()


# --- executor unit tests (no network for templating/extraction) ----------
def test_default_config_has_tsr_and_logout_steps():
    cfg = api_flow.default_config_dict()
    names = [s["name"] for s in cfg["steps"]]
    assert "Authenticate" in names and "Export TSR" in names and "Logout" in names
    assert any(s.get("is_tsr") for s in cfg["steps"])


def test_run_flow_unreachable_reports_failed_trace():
    res = api_flow.run_flow(api_flow.default_config_dict(), {
        "hostname": "127.0.0.1", "port": 1, "username": "a", "password": "b", "verify_tls": False})
    assert res["success"] is False
    assert res["traces"] and res["traces"][0]["success"] is False
    assert res["traces"][0]["error"]


def test_body_text_unwraps_json_envelope():
    raw = b'{"status":{"success":true},"report":"SonicWall Tech Support Report ' + b"x" * 80 + b'"}'
    assert api_flow._body_text(raw).startswith("SonicWall Tech Support Report")


# --- endpoint tests ------------------------------------------------------
def test_list_seeds_default_config(client, org_a):
    _promote(org_a["owner_id"])
    h = _auth(client, org_a["email"], org_a["password"])
    res = client.get("/api/v1/platform/api-configs", headers=h)
    assert res.status_code == 200, res.text
    configs = res.json()
    assert len(configs) >= 1
    assert any(c["is_active"] for c in configs)
    assert any(c["version_label"] == "Gen7" for c in configs)


def test_create_activate_delete_lifecycle(client, org_a):
    _promote(org_a["owner_id"])
    h = _auth(client, org_a["email"], org_a["password"])
    client.get("/api/v1/platform/api-configs", headers=h)  # seed default

    created = client.post("/api/v1/platform/api-configs", headers=h, json={
        "name": "Gen8 draft", "version_label": "Gen8", "auth_type": "basic",
        "steps": [{"name": "Auth", "method": "POST", "path": "/auth", "is_tsr": False}]}).json()
    assert created["name"] == "Gen8 draft"

    act = client.post(f"/api/v1/platform/api-configs/{created['id']}/activate", headers=h).json()
    assert act["is_active"] is True
    # Only one active at a time.
    configs = client.get("/api/v1/platform/api-configs", headers=h).json()
    assert sum(1 for c in configs if c["is_active"]) == 1

    d = client.delete(f"/api/v1/platform/api-configs/{created['id']}", headers=h)
    assert d.status_code == 204


def test_non_superadmin_forbidden(client, org_b):
    h = _auth(client, org_b["email"], org_b["password"])
    assert client.get("/api/v1/platform/api-configs", headers=h).status_code == 403


def test_tester_endpoint_returns_step_traces(client, org_a):
    _promote(org_a["owner_id"])
    h = _auth(client, org_a["email"], org_a["password"])
    res = client.post("/api/v1/platform/api-configs/test", headers=h, json={
        "hostname": "127.0.0.1", "port": 1, "username": "admin", "password": "pw",
        "verify_tls": False})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["success"] is False
    assert body["traces"] and body["traces"][0]["step"]
    # Credentials must never leak into the trace headers.
    assert "***" in str(body["traces"][0]["request_headers"]).lower() or \
        "authorization" not in str(body["traces"][0]["request_headers"]).lower()

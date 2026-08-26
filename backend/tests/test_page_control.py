"""Page Control — global Server Admin visibility switches for customer pages."""

from __future__ import annotations

from app.database import SessionLocal
from app.models import User, PageControlSetting


def auth_headers(client, email, password):
    res = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert res.status_code == 200, res.text
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


def _promote(user_id: str) -> None:
    db = SessionLocal()
    try:
        u = db.get(User, user_id)
        u.is_superadmin = True
        db.commit()
    finally:
        db.close()


def _set_sso(db, enabled: bool) -> None:
    row = db.query(PageControlSetting).filter(PageControlSetting.key == "sso").one_or_none()
    if row is None:
        row = PageControlSetting(key="sso", label="SAML / OIDC / Single Sign-On",
                                 description="Configure customer SSO capabilities", enabled=enabled)
        db.add(row)
    else:
        row.enabled = enabled
    db.commit()


# ---- admin endpoints ------------------------------------------------------

def test_sso_disabled_by_default(client, org_a):
    """Catalogued pages default to disabled — no rows needed before seeding."""
    _promote(org_a["owner_id"])
    h = auth_headers(client, org_a["email"], org_a["password"])
    res = client.get("/api/v1/platform/page-control", headers=h)
    assert res.status_code == 200, res.text
    body = res.json()
    assert isinstance(body, list)
    assert any(item["key"] == "sso" and item["enabled"] is False for item in body)


def test_non_superadmin_cannot_view_or_modify(client, org_b):
    h = auth_headers(client, org_b["email"], org_b["password"])
    assert client.get("/api/v1/platform/page-control", headers=h).status_code == 403
    assert client.put("/api/v1/platform/page-control/sso",
                      json={"enabled": True}, headers=h).status_code == 403


def test_superadmin_can_toggle_and_persists(client, org_a):
    _promote(org_a["owner_id"])
    h = auth_headers(client, org_a["email"], org_a["password"])

    res = client.put("/api/v1/platform/page-control/sso", json={"enabled": True}, headers=h)
    assert res.status_code == 200, res.text
    assert res.json()["enabled"] is True

    # Persisted: a fresh GET (new session/request) still sees the change.
    res = client.get("/api/v1/platform/page-control", headers=h)
    assert res.status_code == 200, res.text
    sso = next(item for item in res.json() if item["key"] == "sso")
    assert sso["enabled"] is True

    res = client.put("/api/v1/platform/page-control/sso", json={"enabled": False}, headers=h)
    assert res.status_code == 200 and res.json()["enabled"] is False


def test_unknown_key_is_404(client, org_a):
    _promote(org_a["owner_id"])
    h = auth_headers(client, org_a["email"], org_a["password"])
    assert client.put("/api/v1/platform/page-control/nope",
                      json={"enabled": True}, headers=h).status_code == 404


# ---- customer-facing endpoint ---------------------------------------------

def test_customer_state_endpoint_reflects_setting(client, org_a, org_b):
    h_a = auth_headers(client, org_a["email"], org_a["password"])

    res = client.get("/api/v1/page-control", headers=h_a)
    assert res.status_code == 200, res.text
    assert res.json() == {"sso": False}

    _promote(org_a["owner_id"])
    h_sa = auth_headers(client, org_a["email"], org_a["password"])
    client.put("/api/v1/platform/page-control/sso", json={"enabled": True}, headers=h_sa)

    # Global setting: applies to every organization, including org_b.
    h_b = auth_headers(client, org_b["email"], org_b["password"])
    res = client.get("/api/v1/page-control", headers=h_b)
    assert res.status_code == 200, res.text
    assert res.json() == {"sso": True}


# ---- SSO configuration API gating -----------------------------------------

def test_sso_config_gated_when_disabled(client, org_a):
    """Customers are blocked from SSO config while the page is disabled; the
    SSO authentication endpoints themselves keep working."""
    db = SessionLocal()
    try:
        _set_sso(db, False)
    finally:
        db.close()
    h = auth_headers(client, org_a["email"], org_a["password"])
    assert client.get("/api/v1/sso/config", headers=h).status_code == 403
    assert client.put("/api/v1/sso/config",
                      json={"enabled": True, "protocol": "oidc"}, headers=h).status_code == 403
    # Login-page status endpoint stays reachable (auth flow untouched).
    assert client.get(f"/api/v1/sso/{org_a['org_id']}/status").status_code == 200


def test_sso_config_allowed_when_enabled(client, org_a):
    db = SessionLocal()
    try:
        _set_sso(db, True)
    finally:
        db.close()
    h = auth_headers(client, org_a["email"], org_a["password"])
    res = client.get("/api/v1/sso/config", headers=h)
    assert res.status_code == 200, res.text
    res = client.put("/api/v1/sso/config",
                     json={"enabled": False, "protocol": "oidc"}, headers=h)
    assert res.status_code == 200, res.text


def test_superadmin_bypasses_sso_gate(client, org_a):
    db = SessionLocal()
    try:
        _set_sso(db, False)
    finally:
        db.close()
    _promote(org_a["owner_id"])
    h = auth_headers(client, org_a["email"], org_a["password"])
    assert client.get("/api/v1/sso/config", headers=h).status_code == 200

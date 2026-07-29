"""Platform-operator (superadmin) access control and overview."""

from __future__ import annotations

from app.database import SessionLocal
from app.models import User, Device


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


def test_superadmin_sees_all_organizations(client, org_a, org_b):
    # Give org_a a device so counts are exercised.
    db = SessionLocal()
    try:
        db.add(Device(organization_id=org_a["org_id"], customer_id=org_a["customer_id"],
                      serial="D1", model="TZ", firmware="x", latest_score=42, latest_grade="F"))
        db.commit()
    finally:
        db.close()
    _promote(org_a["owner_id"])

    h = auth_headers(client, org_a["email"], org_a["password"])
    res = client.get("/api/v1/platform/overview", headers=h)
    assert res.status_code == 200, res.text
    body = res.json()
    # Both org_a and org_b are visible to the operator.
    assert body["stats"]["organizations"] >= 2
    names = {o["name"] for o in body["organizations"]}
    assert {"Org A", "Org B"} <= names
    assert body["stats"]["total_firewalls"] >= 1


def test_non_superadmin_is_forbidden(client, org_b):
    h = auth_headers(client, org_b["email"], org_b["password"])
    assert client.get("/api/v1/platform/overview", headers=h).status_code == 403


def test_me_exposes_superadmin_flag(client, org_a):
    _promote(org_a["owner_id"])
    h = auth_headers(client, org_a["email"], org_a["password"])
    assert client.get("/api/v1/auth/me", headers=h).json()["is_superadmin"] is True

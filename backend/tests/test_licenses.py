"""Regression tests for the license system.

Covers the two reported defects:
  * Issue 1 — Free plan must grant 1 usable license (created at registration,
    with start/expiry) and allow exactly one device.
  * Issue 2 — registering a device against a license purchase must not 500
    (the device-count query was malformed: func.count(...).where(...)).

A license conveys only the right to register and continuously analyze a
device — there is no analysis-frequency dimension.
"""

from __future__ import annotations


def _register(client, email: str) -> dict:
    res = client.post("/api/v1/auth/register", json={
        "company_name": "LicCo", "email": email, "full_name": "Owner",
        "password": "Sup3rStrongPass!"})
    assert res.status_code in (200, 201), res.text
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


def test_free_license_created_at_registration(client, db_schema):
    h = _register(client, "lic1@example.com")
    r = client.get("/api/v1/organization/licenses", headers=h)
    assert r.status_code == 200, r.text          # Issue 1: endpoint must not 500
    body = r.json()
    assert body["free"] is True
    fl = body["free_license"]
    assert fl["total"] == 1 and fl["remaining"] == 1 and fl["expired"] is False
    assert fl["start_date"] and fl["expiry_date"]   # dates present for the UI
    # The free bundle must carry a purchase_id so registration can target it.
    assert body["bundles"][0]["purchase_id"]


def test_free_plan_allows_exactly_one_device(client, db_schema):
    h = _register(client, "lic2@example.com")
    cust = client.get("/api/v1/customers", headers=h).json()[0]
    bundles = client.get("/api/v1/organization/licenses", headers=h).json()["bundles"]
    purchase_id = bundles[0]["purchase_id"]

    # First device consumes the free license — must not 500 (Issue 2).
    r1 = client.post("/api/v1/devices", headers=h, json={
        "customer_id": cust["id"], "friendly_name": "FW1", "serial": "S1",
        "license_purchase_id": purchase_id})
    assert r1.status_code == 201, r1.text
    # Second device exceeds the single free license.
    r2 = client.post("/api/v1/devices", headers=h, json={
        "customer_id": cust["id"], "friendly_name": "FW2", "serial": "S2",
        "license_purchase_id": purchase_id})
    assert r2.status_code == 402, r2.text
    assert "no licenses remaining" in r2.json()["detail"].lower()


def test_licensed_register_counts_existing_devices(client, db_schema):
    """Registering against a specific license purchase is capped at its
    total device count (the previously crashing used-count query)."""
    from app.database import SessionLocal
    from app.models import Customer, LicensePurchase
    from datetime import datetime, timezone, timedelta

    h = _register(client, "lic3@example.com")
    cust = client.get("/api/v1/customers", headers=h).json()[0]

    # Capture the auto-granted free bundle's purchase_id before adding another
    # purchase directly — while allocations are empty the bundle listing only
    # surfaces the free license, so this must happen first.
    bundles = client.get("/api/v1/organization/licenses", headers=h).json()["bundles"]
    free_id = bundles[0]["purchase_id"]

    db = SessionLocal()
    try:
        org_id = db.get(Customer, cust["id"]).organization_id
        lp = LicensePurchase(
            organization_id=org_id, subscription_term="monthly",
            count=2, total_devices=2,
            purchased_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(days=365))
        db.add(lp)
        db.commit()
        db.refresh(lp)
        purchase_id = lp.id
    finally:
        db.close()

    # Free bundle: exactly 1 device.
    r = client.post("/api/v1/devices", headers=h, json={
        "customer_id": cust["id"], "friendly_name": "D-free", "serial": "SER-FREE",
        "license_purchase_id": free_id})
    assert r.status_code == 201, r.text
    r_over = client.post("/api/v1/devices", headers=h, json={
        "customer_id": cust["id"], "friendly_name": "D-free-2", "serial": "SER-FREE-2",
        "license_purchase_id": free_id})
    assert r_over.status_code == 402, r_over.text

    # Purchased bundle: exactly 2 devices.
    for i in range(2):
        r = client.post("/api/v1/devices", headers=h, json={
            "customer_id": cust["id"], "friendly_name": f"D{i}", "serial": f"SER{i}",
            "license_purchase_id": purchase_id})
        assert r.status_code == 201, f"device {i}: {r.text}"
    r4 = client.post("/api/v1/devices", headers=h, json={
        "customer_id": cust["id"], "friendly_name": "D4", "serial": "SER4",
        "license_purchase_id": purchase_id})
    assert r4.status_code == 402, r4.text

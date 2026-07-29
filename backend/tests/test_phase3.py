"""Phase 3 tests: SSO role mapping/provisioning, MSP customer CRUD + isolation,
plan enforcement, billing trial/checkout, PSIRT refresh hashing, ticket sync.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from app.database import SessionLocal
from app.models import (
    Organization, Device, Finding, FindingStatus, SSOConfig, SSOProtocol, PlanTier,
)
from app import sso as sso_mod
from app import billing
from app.psirt_refresh import refresh_psirt
from app.ticketing import apply_external_status


def auth_headers(client, email, password):
    res = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert res.status_code == 200, res.text
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


# ---- SSO -----------------------------------------------------------------
def test_sso_role_mapping():
    cfg = SSOConfig(organization_id="o", group_role_map={"fw-admins": "admin", "auditors": "viewer"},
                    default_role="viewer")
    assert sso_mod.map_role(cfg, ["fw-admins"]) == "admin"
    assert sso_mod.map_role(cfg, ["auditors", "fw-admins"]) == "admin"   # highest wins
    assert sso_mod.map_role(cfg, ["unknown"]) == "viewer"                # default


def test_sso_provision_user(db_schema, org_a):
    db = SessionLocal()
    try:
        user = sso_mod.provision_user(db, org_a["org_id"], "sso-user@example.com", "analyst")
        assert user.email == "sso-user@example.com"
        assert user.role.value == "analyst"
        # Re-provisioning aligns role and does not duplicate.
        user2 = sso_mod.provision_user(db, org_a["org_id"], "sso-user@example.com", "admin")
        assert user2.id == user.id and user2.role.value == "admin"
    finally:
        db.close()


def test_sso_config_crud_and_status(client, org_a):
    h = auth_headers(client, org_a["email"], org_a["password"])
    put = client.put("/api/v1/sso/config", headers=h, json={
        "enabled": True, "protocol": "oidc",
        "oidc_discovery_url": "https://idp.example.com/.well-known/openid-configuration",
        "oidc_client_id": "client123", "oidc_client_secret": "shh",
        "group_role_map": {"admins": "admin"}, "default_role": "viewer"})
    assert put.status_code == 200
    assert put.json()["has_client_secret"] is True       # secret stored, not echoed
    status = client.get(f"/api/v1/sso/{org_a['org_id']}/status")
    assert status.status_code == 200 and status.json()["enabled"] is True


# ---- MSP customers -------------------------------------------------------
def test_customer_crud_and_isolation(client, org_a, org_b):
    ha = auth_headers(client, org_a["email"], org_a["password"])
    created = client.post("/api/v1/customers", headers=ha,
                          json={"name": "Acme", "location": "NYC", "business_unit": "Retail"})
    assert created.status_code == 201
    cid = created.json()["id"]
    upd = client.patch(f"/api/v1/customers/{cid}", headers=ha, json={"notes": "VIP"})
    assert upd.status_code == 200 and upd.json()["notes"] == "VIP"

    # Org B cannot see or edit Org A's customer.
    hb = auth_headers(client, org_b["email"], org_b["password"])
    assert client.get(f"/api/v1/customers/{cid}", headers=hb).status_code == 404


# ---- plan enforcement ----------------------------------------------------
def test_device_limit_enforced_on_free_plan(db_schema, org_a):
    db = SessionLocal()
    try:
        org = db.get(Organization, org_a["org_id"])
        org.plan = PlanTier.free
        db.add(Device(organization_id=org.id, customer_id=org_a["customer_id"],
                      serial="D1", model="TZ", firmware="x"))
        db.commit()
        with pytest.raises(HTTPException) as exc:
            billing.enforce_device_limit(db, org)
        assert exc.value.status_code == 402
    finally:
        db.close()


# ---- billing -------------------------------------------------------------
def test_trial_start_and_expiry(db_schema, org_a):
    db = SessionLocal()
    try:
        org = db.get(Organization, org_a["org_id"])
        org.subscription_status = "none"
        db.commit()
        billing.start_trial(db, org)
        assert org.subscription_status == "trialing"
        assert org.plan == PlanTier.professional
        # Force expiry and downgrade.
        org.trial_ends_at = datetime.now(timezone.utc) - timedelta(days=1)
        db.commit()
        assert billing.downgrade_expired_trials(db) == 1
        db.refresh(org)
        assert org.plan == PlanTier.free and org.subscription_status == "none"
    finally:
        db.close()


def test_checkout_local_mode(db_schema, org_a):
    """With no Stripe key configured, checkout applies the plan locally."""
    db = SessionLocal()
    try:
        org = db.get(Organization, org_a["org_id"])
        result = billing.create_checkout(db, org, PlanTier.msp)
        assert result["mode"] == "local"
        db.refresh(org)
        assert org.plan == PlanTier.msp and org.subscription_status == "active"
    finally:
        db.close()


# ---- PSIRT refresh -------------------------------------------------------
def test_psirt_refresh_hashing(db_schema):
    db = SessionLocal()
    try:
        first = refresh_psirt(db, source="manual")
        assert first.content_hash and first.advisory_count > 0
        assert first.changed is True            # no prior log
        second = refresh_psirt(db, source="manual")
        assert second.content_hash == first.content_hash
        assert second.changed is False          # identical dataset
    finally:
        db.close()


# ---- ticket sync ---------------------------------------------------------
def test_ticket_status_sync_closes_finding(db_schema, org_a):
    db = SessionLocal()
    try:
        f = Finding(organization_id=org_a["org_id"], device_id="d", analysis_id="a",
                    rule_id="R", fingerprint="R::x::y", severity="High", title="t",
                    status=FindingStatus.in_progress, ticket_system="jira", ticket_ref="FW-1")
        db.add(f)
        db.commit()
        assert apply_external_status(db, "jira", "FW-1", "Done") is True
        db.refresh(f)
        assert f.status == FindingStatus.fixed
        assert f.ticket_status == "Done"
    finally:
        db.close()

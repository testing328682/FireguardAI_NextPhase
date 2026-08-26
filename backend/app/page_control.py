"""Global Page Control — platform-level visibility switches for customer pages.

Reusable feature-flag system: a catalog of known page/feature keys plus one
persisted ``PageControlSetting`` row per key. Adding a future customer-facing
page is a single entry in :data:`PAGE_CONTROL_CATALOG`; the row is auto-seeded,
the Server Admin Page Control page picks it up automatically, and the customer
frontend reads it from the lightweight ``GET /api/v1/page-control`` endpoint.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import PageControlSetting


PAGE_CONTROL_CATALOG: dict[str, dict] = {
    # key: {"label", "description", "default_enabled"}
    "sso": {
        "label": "SAML / OIDC / Single Sign-On",
        "description": "Configure customer SSO capabilities",
        "default_enabled": False,
    },
}


def ensure_default_settings(db: Session) -> None:
    """Create rows for any catalog keys missing from the DB (idempotent)."""
    existing = {r.key for r in db.scalars(select(PageControlSetting)).all()}
    for key, meta in PAGE_CONTROL_CATALOG.items():
        if key not in existing:
            db.add(PageControlSetting(
                key=key,
                label=meta["label"],
                description=meta.get("description", ""),
                enabled=bool(meta.get("default_enabled", False)),
            ))
    db.commit()


def is_page_enabled(db: Session, key: str) -> bool:
    """True when the page/feature is enabled for customers.

    Missing rows fall back to the catalog default (opt-in: new pages start
    disabled), so gating works even before seeding has run.
    """
    row = db.scalar(select(PageControlSetting).where(PageControlSetting.key == key))
    if row is not None:
        return bool(row.enabled)
    return bool(PAGE_CONTROL_CATALOG.get(key, {}).get("default_enabled", False))


def state_dict(db: Session) -> dict[str, bool]:
    """Customer-facing ``{key: enabled}`` map covering every catalog key."""
    rows = {r.key: bool(r.enabled) for r in db.scalars(select(PageControlSetting)).all()}
    return {
        key: rows.get(key, bool(meta.get("default_enabled", False)))
        for key, meta in PAGE_CONTROL_CATALOG.items()
    }


def catalog_list(db: Session) -> list[dict]:
    """Admin-facing catalog entries merged with persisted state (ordered)."""
    rows = {r.key: r for r in db.scalars(select(PageControlSetting)).all()}
    out: list[dict] = []
    for key, meta in PAGE_CONTROL_CATALOG.items():
        row = rows.get(key)
        out.append({
            "key": key,
            "label": row.label if row else meta["label"],
            "description": row.description if row else meta.get("description", ""),
            "enabled": bool(row.enabled) if row else bool(meta.get("default_enabled", False)),
        })
    return out

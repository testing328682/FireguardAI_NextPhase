"""FirewallGuard AI - FastAPI application entrypoint.

Wires together the routers, health checks and OpenAPI metadata. Run locally with:

    uvicorn app.main:app --reload

In production the app is served by Gunicorn with Uvicorn workers behind a
reverse proxy; analyses are processed by a separate Celery worker fleet.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import get_settings
from .ratelimit import RateLimitMiddleware
from .secheaders import SecurityHeadersMiddleware
from .routers import (
    auth, devices, analyses, reports, fleet, alerts,
    findings, schedules, dashboard, audit_log,
    rules, compliance, integrations, tokens,
    sso, billing, psirt, privacy, analytics, platform,
    platform_config, plans, licenses,
)

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version="2.0.0",
    description=(
        "Continuous security posture analysis for SonicWall firewalls. "
        "Upload a Tech Support Report (TSR) or connect a device over the SonicOS "
        "API to receive a scored, prioritised set of findings, correlated attack "
        "paths, firmware vulnerability intelligence, configuration drift tracking, "
        "a CEL-based rule engine, compliance reporting and executive/technical "
        "reports.\n\n"
        "**Authentication.** Most endpoints require a bearer token. Obtain one via "
        "`POST /api/v1/auth/login` (JWT), or create a programmatic API token under "
        "`/api/v1/settings/api-tokens` and send it as `Authorization: Bearer fgat_…`."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_tags=[
        {"name": "auth", "description": "Login, MFA, refresh and user management."},
        {"name": "tenancy", "description": "Customers and devices, including SonicOS API-pull."},
        {"name": "analysis", "description": "TSR upload and analysis results."},
        {"name": "findings", "description": "Finding triage workflow and comments."},
        {"name": "rules", "description": "Rule library, CEL editor, approval workflow, overrides."},
        {"name": "compliance", "description": "Per-framework compliance matrices."},
        {"name": "dashboard", "description": "Fleet posture and findings roll-up."},
        {"name": "schedules", "description": "Per-device scan schedules."},
        {"name": "integrations", "description": "Slack and other external integrations."},
        {"name": "api-tokens", "description": "Programmatic API tokens."},
        {"name": "audit", "description": "Append-only audit log."},
        {"name": "drift", "description": "Configuration drift history and comparison."},
    ],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.debug else [],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

for module in (auth, devices, analyses, reports, fleet, alerts,
               findings, schedules, dashboard, audit_log,
                rules, compliance, integrations, tokens,
                sso, billing, psirt, privacy, analytics, platform, platform_config,
                plans, licenses):
    app.include_router(module.router)


@app.on_event("startup")
def _ensure_schema() -> None:
    """Create any tables added since the DB was provisioned (idempotent; only
    issues CREATE TABLE for missing tables — never alters existing ones). Lets
    new features like the configurable API flow work after a plain image rebuild.
    """
    try:
        from .database import engine
        from .models import Base
        Base.metadata.create_all(bind=engine)
        # ── Lightweight column migrations (safe to run repeatedly) ──────
        with engine.connect() as conn:
            # Tsr.favorite (2026-07-03)
            conn.execute(
                __import__("sqlalchemy").text(
                    "ALTER TABLE tsrs ADD COLUMN IF NOT EXISTS favorite BOOLEAN DEFAULT FALSE"))
            # Device.decommissioned (2026-07-03)
            conn.execute(
                __import__("sqlalchemy").text(
                    "ALTER TABLE devices ADD COLUMN IF NOT EXISTS decommissioned BOOLEAN DEFAULT FALSE"))
            conn.execute(
                __import__("sqlalchemy").text(
                    "ALTER TABLE devices ADD COLUMN IF NOT EXISTS decommissioned_at TIMESTAMPTZ"))
            # Device.was_ever_configured (2026-07-04)
            conn.execute(
                __import__("sqlalchemy").text(
                    "ALTER TABLE devices ADD COLUMN IF NOT EXISTS was_ever_configured BOOLEAN DEFAULT FALSE"))
            # ApiConnectionLog table (2026-07-05) — create_all handles new tables
            conn.commit()
    except Exception as exc:  # noqa: BLE001 - never block app startup on this
        import logging
        logging.getLogger(__name__).warning("startup create_all skipped: %s", exc)


@app.get("/health", tags=["meta"])
def health() -> dict[str, str]:
    return {"status": "ok", "service": settings.app_name, "version": "1.0.0"}


@app.get("/", tags=["meta"])
def root() -> dict[str, str]:
    return {"name": settings.app_name,
            "docs": "/docs",
            "description": "Continuous SonicWall firewall security analysis."}

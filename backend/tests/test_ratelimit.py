"""Rate-limiting middleware test.

Builds a throwaway app with the middleware and a low auth budget, then confirms
that exceeding the budget yields HTTP 429 with a Retry-After header.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import ratelimit


def _build_app() -> TestClient:
    app = FastAPI()
    app.add_middleware(ratelimit.RateLimitMiddleware)

    @app.get("/api/v1/auth/ping")
    def ping():
        return {"ok": True}

    return TestClient(app)


def test_auth_endpoint_is_rate_limited(monkeypatch):
    monkeypatch.setattr(ratelimit.settings, "rate_limit_enabled", True)
    monkeypatch.setattr(ratelimit.settings, "auth_rate_limit_per_minute", 3)
    monkeypatch.setattr(ratelimit.settings, "rate_limit_per_minute", 1000)
    client = _build_app()

    statuses = [client.get("/api/v1/auth/ping").status_code for _ in range(5)]
    assert statuses.count(200) == 3
    assert 429 in statuses
    last = client.get("/api/v1/auth/ping")
    assert last.status_code == 429
    assert "Retry-After" in last.headers


def test_health_is_never_limited(monkeypatch):
    monkeypatch.setattr(ratelimit.settings, "rate_limit_enabled", True)
    monkeypatch.setattr(ratelimit.settings, "auth_rate_limit_per_minute", 1)
    monkeypatch.setattr(ratelimit.settings, "rate_limit_per_minute", 1)
    app = FastAPI()
    app.add_middleware(ratelimit.RateLimitMiddleware)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    client = TestClient(app)
    assert all(client.get("/health").status_code == 200 for _ in range(5))

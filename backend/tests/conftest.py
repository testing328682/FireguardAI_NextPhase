"""Shared test configuration and fixtures.

Environment variables are set *before* the application modules are imported so
the cached Settings pick up a throwaway SQLite database, local file storage and
synchronous (inline) task execution. Rate limiting is disabled for the API
suite; it is exercised directly in ``test_ratelimit.py``.
"""

from __future__ import annotations

import os
import tempfile

_TMP = tempfile.mkdtemp(prefix="fgai_test_")
os.environ.setdefault("FGAI_DATABASE_URL", f"sqlite+pysqlite:///{_TMP}/test.db")
os.environ.setdefault("FGAI_STORAGE_BACKEND", "local")
os.environ.setdefault("FGAI_LOCAL_STORAGE_DIR", _TMP)
os.environ.setdefault("FGAI_INLINE_TASKS", "1")
os.environ.setdefault("FGAI_RATE_LIMIT_ENABLED", "false")
os.environ.setdefault("FGAI_JWT_SECRET", "test-secret")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.database import engine, SessionLocal  # noqa: E402
from app.models import Base, Organization, User, Customer, Role, PlanTier  # noqa: E402
from app.security import hash_password  # noqa: E402
from app.main import app  # noqa: E402

# Safety net: the fixtures below drop/create ALL tables. If the resolved DB URL
# points at a real database (e.g. because the process already had
# FGAI_DATABASE_URL set — as containers do — so the setdefault above was a
# no-op), refuse to run rather than wipe live data. Only a SQLite DB or one
# whose name contains "test" is treated as a disposable test database.
if engine.url.get_backend_name() != "sqlite" and "test" not in (engine.url.database or ""):
    raise RuntimeError(
        f"Refusing to run the test suite against non-test database "
        f"'{engine.url.render_as_string(hide_password=True)}'. The suite drops "
        f"and recreates every table. Point FGAI_DATABASE_URL at a SQLite URL or a "
        f"database whose name contains 'test' (unset it entirely to use the "
        f"default throwaway SQLite DB)."
    )


@pytest.fixture(scope="function")
def db_schema():
    """Fresh schema per test for isolation."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client(db_schema) -> TestClient:
    return TestClient(app)


def _make_org(name: str, owner_email: str, password: str = "Sup3rStrongPass!") -> dict:
    db = SessionLocal()
    try:
        org = Organization(name=name, plan=PlanTier.professional)
        db.add(org)
        db.flush()
        owner = User(organization_id=org.id, email=owner_email, full_name="Owner",
                     role=Role.owner, hashed_password=hash_password(password))
        cust = Customer(organization_id=org.id, name=name)
        db.add_all([owner, cust])
        db.commit()
        return {"org_id": org.id, "owner_id": owner.id, "customer_id": cust.id,
                "email": owner_email, "password": password}
    finally:
        db.close()


@pytest.fixture()
def org_a() -> dict:
    return _make_org("Org A", "owner-a@example.com")


@pytest.fixture()
def org_b() -> dict:
    return _make_org("Org B", "owner-b@example.com")


def auth_headers(client: TestClient, email: str, password: str) -> dict:
    res = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert res.status_code == 200, res.text
    body = res.json()
    return {"Authorization": f"Bearer {body['access_token']}"}

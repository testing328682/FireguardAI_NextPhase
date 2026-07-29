"""Database bootstrap.

For production, schema changes are managed with Alembic. For local development
and tests this helper creates all tables directly from the SQLAlchemy metadata
and can seed an initial organization, owner user and customer.

    python -m app.bootstrap --seed --email owner@example.com --password 'StrongPassw0rd!'
"""

from __future__ import annotations

import argparse

from .database import engine, SessionLocal
from .models import Base, Organization, User, Customer, Role, PlanTier
from .security import hash_password


def create_all() -> None:
    Base.metadata.create_all(bind=engine)


def seed(email: str, password: str, org_name: str, is_msp: bool,
         superadmin: bool = False) -> None:
    db = SessionLocal()
    try:
        org = Organization(name=org_name, is_msp=is_msp,
                           plan=PlanTier.msp if is_msp else PlanTier.professional)
        db.add(org)
        db.flush()
        db.add(User(organization_id=org.id, email=email, full_name="Owner",
                    role=Role.owner, is_superadmin=superadmin,
                    hashed_password=hash_password(password)))
        db.add(Customer(organization_id=org.id, name=f"{org_name} (default)"))
        db.commit()
        suffix = " (platform superadmin)" if superadmin else ""
        print(f"Seeded organization '{org_name}' with owner {email}{suffix}")
    finally:
        db.close()


def main() -> None:
    p = argparse.ArgumentParser(description="FirewallGuard AI DB bootstrap")
    p.add_argument("--seed", action="store_true", help="Seed an initial org/user")
    p.add_argument("--email", default="owner@example.com")
    p.add_argument("--password", default="ChangeMe-Strong-123!")
    p.add_argument("--org", default="Demo Organization")
    p.add_argument("--msp", action="store_true", help="Create an MSP organization")
    p.add_argument("--superadmin", action="store_true",
                   help="Mark the seeded owner as a platform operator (cross-tenant)")
    args = p.parse_args()

    create_all()
    print("Schema created.")

    # Mirror the built-in Python catalog into the rules table so the admin GUI
    # lists every rule. Idempotent — safe to run on every bootstrap.
    from .rule_engine import seed_system_rules
    from .routers.plans import seed_plans
    from .database import SessionLocal
    db = SessionLocal()
    try:
        n = seed_system_rules(db)
        print(f"Seeded {n} system rule(s).")
        p = seed_plans(db)
        print(f"Seeded {p} default plan(s).")
        from .api_flow import ensure_default_config
        ensure_default_config(db)
        print("Ensured default API flow config (SonicOS Gen7).")
    finally:
        db.close()

    if args.seed:
        seed(args.email, args.password, args.org, args.msp, superadmin=args.superadmin)


if __name__ == "__main__":
    main()

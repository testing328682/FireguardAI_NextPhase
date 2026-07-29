"""remove license-frequency coupling; simplify plan pricing

A license now conveys only the right to register and continuously analyze a
fixed number of devices — manual TSR uploads and API pulls are unlimited.
This drops the analysis-frequency dimension from Plan pricing, Organization
license allocations, LicensePurchase records, and Device — while preserving
subscription term (monthly/yearly) and MSP tier (device-count bundle size),
and leaving the independent per-device Schedule (customer-configured scan
cadence) untouched.

Revision ID: k1l2m3n4o5p6
Revises: j0k1l2m3n4o5
Create Date: 2026-07-02 00:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'k1l2m3n4o5p6'
down_revision: Union[str, None] = 'j0k1l2m3n4o5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_column(table: str, column: str) -> bool:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    return column in [c["name"] for c in insp.get_columns(table)]


def upgrade() -> None:
    bind = op.get_bind()

    # 1. Add Plan.price_per_device and backfill it (Professional) / flatten
    #    pricing_tiers (MSP) from the legacy frequency-keyed shape.
    if not _has_column('plans', 'price_per_device'):
        with op.batch_alter_table('plans', schema=None) as batch_op:
            batch_op.add_column(sa.Column('price_per_device', sa.Float(), nullable=False,
                                          server_default='0'))

    plans_tbl = sa.table(
        'plans',
        sa.column('id', sa.String),
        sa.column('plan_type', sa.String),
        sa.column('pricing_tiers', sa.JSON),
        sa.column('price_per_device', sa.Float),
    )
    for row in bind.execute(sa.select(plans_tbl.c.id, plans_tbl.c.plan_type,
                                       plans_tbl.c.pricing_tiers)):
        tiers = row.pricing_tiers or {}
        if not isinstance(tiers, dict):
            continue
        if row.plan_type == "msp":
            new_tiers = {}
            for tier, val in tiers.items():
                if isinstance(val, dict):
                    new_tiers[tier] = float(val.get("monthly", 0) or 0)
                elif isinstance(val, (int, float)):
                    new_tiers[tier] = float(val)
            bind.execute(plans_tbl.update().where(plans_tbl.c.id == row.id)
                         .values(pricing_tiers=new_tiers))
        else:
            price = float(tiers.get("monthly", 0) or 0)
            bind.execute(plans_tbl.update().where(plans_tbl.c.id == row.id)
                         .values(price_per_device=price, pricing_tiers={}))

    # 2. Collapse Organization.license_allocations — drop the frequency layer.
    #    Professional: {term: {freq: count}}        -> {term: {"licenses": count}}
    #    MSP:          {term: {tier: {freq: count}}} -> {term: {tier: count}}
    orgs_tbl = sa.table(
        'organizations',
        sa.column('id', sa.String),
        sa.column('license_allocations', sa.JSON),
    )
    for row in bind.execute(sa.select(orgs_tbl.c.id, orgs_tbl.c.license_allocations)):
        alloc = row.license_allocations or {}
        if not alloc or not isinstance(alloc, dict):
            continue
        terms = alloc if all(k in ("monthly", "yearly") for k in alloc.keys()) else {"monthly": alloc}
        new_alloc: dict = {}
        for term, items in terms.items():
            items = items or {}
            collapsed: dict = {}
            for key, val in items.items():
                if isinstance(val, dict):
                    # MSP: {tier: {freq: count}} -> {tier: count}
                    collapsed[key] = collapsed.get(key, 0) + sum(
                        v for v in val.values() if isinstance(v, (int, float)))
                elif isinstance(val, (int, float)):
                    # Professional: {freq: count} -> {"licenses": count}
                    collapsed["licenses"] = collapsed.get("licenses", 0) + val
            if collapsed:
                new_alloc[term] = collapsed
        bind.execute(orgs_tbl.update().where(orgs_tbl.c.id == row.id)
                     .values(license_allocations=new_alloc))

    # 3. Drop the frequency columns entirely.
    if _has_column('organizations', 'analysis_frequency'):
        with op.batch_alter_table('organizations', schema=None) as batch_op:
            batch_op.drop_column('analysis_frequency')
    if _has_column('license_purchases', 'analysis_frequency'):
        with op.batch_alter_table('license_purchases', schema=None) as batch_op:
            batch_op.drop_column('analysis_frequency')
    if _has_column('devices', 'scan_frequency'):
        with op.batch_alter_table('devices', schema=None) as batch_op:
            batch_op.drop_column('scan_frequency')


def downgrade() -> None:
    if not _has_column('devices', 'scan_frequency'):
        with op.batch_alter_table('devices', schema=None) as batch_op:
            batch_op.add_column(sa.Column('scan_frequency', sa.String(length=16), nullable=False,
                                          server_default=''))
    if not _has_column('license_purchases', 'analysis_frequency'):
        with op.batch_alter_table('license_purchases', schema=None) as batch_op:
            batch_op.add_column(sa.Column('analysis_frequency', sa.String(length=32), nullable=False,
                                          server_default='monthly'))
    if not _has_column('organizations', 'analysis_frequency'):
        with op.batch_alter_table('organizations', schema=None) as batch_op:
            batch_op.add_column(sa.Column('analysis_frequency', sa.String(length=32), nullable=False,
                                          server_default='monthly'))
    if _has_column('plans', 'price_per_device'):
        with op.batch_alter_table('plans', schema=None) as batch_op:
            batch_op.drop_column('price_per_device')
    # Note: the license_allocations / pricing_tiers shape collapse in upgrade()
    # is lossy (the frequency dimension is discarded) and is not reversible.

"""Compliance matrix endpoints.

Findings carry a ``compliance`` mapping of framework -> control IDs. The catalog
uses verbose framework labels (e.g. "CIS Controls v8 - 4 (Secure Configuration)");
``_group_of`` collapses those to the five headline frameworks the UI tabs by.

The matrix presents devices as columns and referenced controls as rows. A cell
is "fail" when the device has an open finding mapped to that control, else
"pass"; clicking a failing cell surfaces the contributing finding ids.
"""

from __future__ import annotations

from collections import defaultdict

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User, Device, Finding, FindingStatus
from ..security import current_user

router = APIRouter(prefix="/api/v1", tags=["compliance"])

ACTIVE = (FindingStatus.open, FindingStatus.acknowledged, FindingStatus.in_progress)

FRAMEWORKS = ["CIS v8", "NIST CSF 2.0", "PCI DSS 4.0", "ISO 27001", "SonicWall BP"]


def _group_of(framework_label: str) -> str | None:
    f = framework_label.upper()
    if "CIS" in f:
        return "CIS v8"
    if "NIST" in f:
        return "NIST CSF 2.0"
    if "PCI" in f:
        return "PCI DSS 4.0"
    if "ISO" in f:
        return "ISO 27001"
    if "SONICWALL" in f:
        return "SonicWall BP"
    return None


@router.get("/compliance/frameworks")
def frameworks() -> dict:
    return {"frameworks": FRAMEWORKS}


@router.get("/compliance/matrix")
def matrix(framework: str = Query(...),
           user: User = Depends(current_user),
           db: Session = Depends(get_db)) -> dict:
    """Device × control pass/fail matrix for one framework."""
    devices = [d for d in db.scalars(select(Device).where(
        Device.organization_id == user.organization_id)) if d.latest_grade]
    device_rows = [{"device_id": d.id, "serial": d.serial,
                    "model": d.model, "grade": d.latest_grade} for d in devices]

    findings = db.scalars(select(Finding).where(
        Finding.organization_id == user.organization_id,
        Finding.status.in_(ACTIVE)))

    controls: set[str] = set()
    fail_map: dict[str, list[str]] = defaultdict(list)   # "device|control" -> finding ids
    for f in findings:
        for label, ctrls in (f.compliance or {}).items():
            if _group_of(label) != framework:
                continue
            for ctrl in ctrls:
                controls.add(ctrl)
                fail_map[f"{f.device_id}|{ctrl}"].append(f.id)

    cells = {}
    for d in devices:
        for ctrl in controls:
            key = f"{d.id}|{ctrl}"
            ids = fail_map.get(key, [])
            cells[key] = {"status": "fail" if ids else "pass", "finding_ids": ids}

    return {
        "framework": framework,
        "devices": device_rows,
        "controls": sorted(controls),
        "cells": cells,
    }

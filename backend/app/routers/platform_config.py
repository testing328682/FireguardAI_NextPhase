"""Product & Platform Configuration router (superadmin-only).

Manage device generations, per-generation device models, and recommended
firmware versions.  Used by the TSR pipeline to detect device generation
and flag outdated firmware.
"""

from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import (
    DeviceGeneration, GenerationDevice, FirmwareRecommendation,
    FirmwareVersion, FirmwareCve, FirmwareIssue, Rule,
)
from ..rule_engine import firmware_matches, normalize_firmware_version
from ..security import current_user, require_superadmin
from .. import audit
from sqlalchemy import func

router = APIRouter(prefix="/api/v1/platform", tags=["platform-config"])

_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}
_RULE_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def _strip_branding(version: str) -> str:
    return re.sub(r"^SonicOS\s*(?:Enhanced\s*)?", "",
                  (version or "").strip(), flags=re.IGNORECASE).strip()


def _rule_out(rec: FirmwareRecommendation | None) -> dict:
    if rec is None:
        return {"enabled": True, "key": "FW-FIRMWARE-COMPLIANCE", "title": "",
                "description": "", "severity": "Critical",
                "category": "Firmware Compliance", "remediation": ""}
    return {"enabled": rec.rule_enabled, "key": rec.rule_key,
            "title": rec.rule_title, "description": rec.rule_description,
            "severity": rec.rule_severity, "category": rec.rule_category,
            "remediation": rec.rule_remediation}


def _fw_version_out(fv: FirmwareVersion, detail: bool = False) -> dict:
    out = {"id": fv.id, "version": fv.version, "remediation": fv.remediation,
           "cve_count": len(fv.cves), "issue_count": len(fv.issues)}
    if detail:
        out["cves"] = [{"id": c.id, "cve_id": c.cve_id, "description": c.description,
                        "cvss": c.cvss, "remediation": c.remediation}
                       for c in fv.cves]
        out["issues"] = [{"id": i.id, "title": i.title, "description": i.description,
                          "severity": i.severity, "remediation": i.remediation}
                         for i in fv.issues]
    return out


# ── Public read-only: generations + firmware (visible to all tenants) ───
@router.get("/generations/public")
def list_generations_public(
    user=Depends(current_user),
    db: Session = Depends(get_db),
):
    """List device generations with firmware versions — read-only, all users."""
    gens = db.scalars(
        select(DeviceGeneration).order_by(DeviceGeneration.sort_order)
    ).all()
    return [
        {
            "id": g.id,
            "name": g.name,
            "devices": sorted([d.model for d in g.devices]),
            "firmware_version": g.firmware[0].version if g.firmware else "",
        }
        for g in gens
    ]


# ── Generations (superadmin CRUD) ──────────────────────────────────────

@router.get("/generations")
def list_generations(
    user=Depends(require_superadmin),
    db: Session = Depends(get_db),
):
    """List all device generations with their devices and firmware recs."""
    gens = db.scalars(
        select(DeviceGeneration).order_by(DeviceGeneration.sort_order)
    ).all()
    return [
        {
            "id": g.id,
            "name": g.name,
            "sort_order": g.sort_order,
            "devices": [{"id": d.id, "model": d.model} for d in g.devices],
            "firmware_version": g.firmware[0].version if g.firmware else "",
            "firmware_rule": _rule_out(g.firmware[0] if g.firmware else None),
            "firmware_versions": [
                _fw_version_out(fv) for fv in
                sorted(g.firmware_versions, key=lambda v: v.version, reverse=True)],
        }
        for g in gens
    ]


@router.post("/generations", status_code=status.HTTP_201_CREATED)
def create_generation(
    body: dict,
    request: Request,
    user=Depends(require_superadmin),
    db: Session = Depends(get_db),
):
    """Create a new device generation."""
    name = (body.get("name") or "").strip()
    if not name:
        raise HTTPException(400, "Generation name is required")
    existing = db.scalar(select(DeviceGeneration).where(DeviceGeneration.name == name))
    if existing:
        raise HTTPException(409, f"Generation '{name}' already exists")
    g = DeviceGeneration(name=name, sort_order=body.get("sort_order", 0))
    db.add(g)
    db.commit()
    db.refresh(g)
    audit.log_action(db, organization_id=None, action="generation_created",
                     resource_type="device_generation", resource_id=g.id,
                     user=user, request=request, after={"name": name})
    return {"id": g.id, "name": g.name, "sort_order": g.sort_order,
            "devices": [], "firmware_version": ""}


@router.patch("/generations/{gen_id}")
def update_generation(
    gen_id: str, body: dict, request: Request,
    user=Depends(require_superadmin),
    db: Session = Depends(get_db),
):
    """Update a generation's name or sort order."""
    g = db.get(DeviceGeneration, gen_id)
    if not g:
        raise HTTPException(404, "Generation not found")
    if "name" in body:
        g.name = body["name"].strip()
    if "sort_order" in body:
        g.sort_order = body["sort_order"]
    db.commit()
    return {"id": g.id, "name": g.name, "sort_order": g.sort_order}


@router.delete("/generations/{gen_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_generation(
    gen_id: str, user=Depends(require_superadmin),
    db: Session = Depends(get_db),
):
    """Delete a generation and its devices/firmware rec."""
    g = db.get(DeviceGeneration, gen_id)
    if not g:
        raise HTTPException(404, "Generation not found")
    db.delete(g)
    db.commit()
    return None


# ── Devices per generation ─────────────────────────────────────────────

@router.post("/generations/{gen_id}/devices", status_code=status.HTTP_201_CREATED)
def add_device(
    gen_id: str, body: dict, request: Request,
    user=Depends(require_superadmin),
    db: Session = Depends(get_db),
):
    g = db.get(DeviceGeneration, gen_id)
    if not g:
        raise HTTPException(404, "Generation not found")
    model = (body.get("model") or "").strip()
    if not model:
        raise HTTPException(400, "Device model is required")
    d = GenerationDevice(generation_id=gen_id, model=model)
    db.add(d)
    db.commit()
    db.refresh(d)
    return {"id": d.id, "generation_id": gen_id, "model": model}


@router.delete("/generations/{gen_id}/devices/{dev_id}",
               status_code=status.HTTP_204_NO_CONTENT)
def remove_device(
    gen_id: str, dev_id: str,
    user=Depends(require_superadmin),
    db: Session = Depends(get_db),
):
    d = db.get(GenerationDevice, dev_id)
    if not d or d.generation_id != gen_id:
        raise HTTPException(404, "Device not found")
    db.delete(d)
    db.commit()
    return None


# ── Firmware recommendation + compliance-rule metadata ─────────────────

@router.put("/generations/{gen_id}/firmware")
def set_firmware(
    gen_id: str, body: dict, request: Request,
    user=Depends(require_superadmin),
    db: Session = Depends(get_db),
):
    """Partial update of the latest recommended firmware and the compliance
    rule metadata (enabled/key/title/description/severity/category/remediation)."""
    g = db.get(DeviceGeneration, gen_id)
    if not g:
        raise HTTPException(404, "Generation not found")
    rec = g.firmware[0] if g.firmware else None
    if rec is None:
        rec = FirmwareRecommendation(generation_id=gen_id, version="")
        db.add(rec)
        db.flush()

    if "version" in body:
        version = _strip_branding(body.get("version") or "")
        # The same release cannot be both latest and a previous version.
        clash = next((fv for fv in g.firmware_versions
                      if version and firmware_matches(version, fv.version)), None)
        if clash:
            raise HTTPException(
                409, f"'{version}' is already recorded as a previous firmware "
                     f"version ('{clash.version}'). Delete that record first or "
                     "choose a different latest version.")
        rec.version = version

    if "rule_key" in body:
        key = (body.get("rule_key") or "").strip()
        if not _RULE_KEY_RE.match(key):
            raise HTTPException(400, "Rule key must be 1-64 characters "
                                     "(letters, digits, spaces, dot, dash, underscore)")
        # Firmware rules may share a key across generations (the default does),
        # but must not collide with a global rule-library key.
        if key != rec.rule_key and db.scalar(select(Rule).where(
                Rule.key == key, Rule.organization_id.is_(None))):
            raise HTTPException(409, f"Rule key '{key}' is already used by a "
                                     "global rule in the rule library")
        rec.rule_key = key
    if "rule_enabled" in body:
        rec.rule_enabled = bool(body.get("rule_enabled"))
    if "rule_title" in body:
        rec.rule_title = (body.get("rule_title") or "").strip()
    if "rule_description" in body:
        rec.rule_description = (body.get("rule_description") or "").strip()
    if "rule_severity" in body:
        severity = (body.get("rule_severity") or "").strip()
        if severity not in _SEVERITIES:
            raise HTTPException(400, f"Severity must be one of {sorted(_SEVERITIES)}")
        rec.rule_severity = severity
    if "rule_category" in body:
        category = (body.get("rule_category") or "").strip()
        if not category:
            raise HTTPException(400, "Category is required")
        rec.rule_category = category
    if "rule_remediation" in body:
        rec.rule_remediation = (body.get("rule_remediation") or "").strip()

    db.commit()
    audit.log_action(db, organization_id=None, action="firmware_rule_updated",
                     resource_type="firmware_recommendation", resource_id=rec.id,
                     user=user, request=request,
                     after={"generation": g.name, "version": rec.version,
                            "rule_key": rec.rule_key, "enabled": rec.rule_enabled})
    return {"generation_id": gen_id, "version": rec.version,
            "firmware_rule": _rule_out(rec)}


# ── Previous firmware versions (firmware intelligence) ─────────────────

@router.get("/generations/{gen_id}/firmware-versions")
def list_firmware_versions(
    gen_id: str, user=Depends(require_superadmin),
    db: Session = Depends(get_db),
):
    g = db.get(DeviceGeneration, gen_id)
    if not g:
        raise HTTPException(404, "Generation not found")
    return [_fw_version_out(fv, detail=True) for fv in
            sorted(g.firmware_versions, key=lambda v: v.version, reverse=True)]


@router.post("/generations/{gen_id}/firmware-versions",
             status_code=status.HTTP_201_CREATED)
def add_firmware_version(
    gen_id: str, body: dict, request: Request,
    user=Depends(require_superadmin),
    db: Session = Depends(get_db),
):
    g = db.get(DeviceGeneration, gen_id)
    if not g:
        raise HTTPException(404, "Generation not found")
    version = _strip_branding(body.get("version") or "")
    if not version:
        raise HTTPException(400, "Firmware version is required")
    latest = g.firmware[0].version if g.firmware else ""
    if latest and firmware_matches(version, latest):
        raise HTTPException(
            409, f"'{version}' is the latest recommended firmware for {g.name}; "
                 "it cannot also be a previous version.")
    if any(firmware_matches(version, fv.version) for fv in g.firmware_versions):
        raise HTTPException(409, f"Firmware version '{version}' is already "
                                 f"configured for {g.name}")
    fv = FirmwareVersion(generation_id=gen_id, version=version,
                         version_norm=normalize_firmware_version(version),
                         remediation=(body.get("remediation") or "").strip())
    db.add(fv)
    db.commit()
    db.refresh(fv)
    audit.log_action(db, organization_id=None, action="firmware_version_added",
                     resource_type="firmware_version", resource_id=fv.id,
                     user=user, request=request,
                     after={"generation": g.name, "version": version})
    return _fw_version_out(fv, detail=True)


@router.patch("/firmware-versions/{fv_id}")
def update_firmware_version(
    fv_id: str, body: dict, request: Request,
    user=Depends(require_superadmin),
    db: Session = Depends(get_db),
):
    fv = db.get(FirmwareVersion, fv_id)
    if not fv:
        raise HTTPException(404, "Firmware version not found")
    g = fv.generation
    if "version" in body:
        version = _strip_branding(body.get("version") or "")
        if not version:
            raise HTTPException(400, "Firmware version is required")
        latest = g.firmware[0].version if g.firmware else ""
        if latest and firmware_matches(version, latest):
            raise HTTPException(409, f"'{version}' is the latest recommended "
                                     f"firmware for {g.name}")
        if any(fv2.id != fv.id and firmware_matches(version, fv2.version)
               for fv2 in g.firmware_versions):
            raise HTTPException(409, f"Firmware version '{version}' is already "
                                     f"configured for {g.name}")
        fv.version = version
        fv.version_norm = normalize_firmware_version(version)
    if "remediation" in body:
        fv.remediation = (body.get("remediation") or "").strip()
    db.commit()
    db.refresh(fv)
    return _fw_version_out(fv, detail=True)


@router.delete("/firmware-versions/{fv_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_firmware_version(
    fv_id: str, user=Depends(require_superadmin),
    db: Session = Depends(get_db),
):
    fv = db.get(FirmwareVersion, fv_id)
    if not fv:
        raise HTTPException(404, "Firmware version not found")
    # Historical findings keep their snapshotted evidence; this only removes
    # the configuration used for FUTURE analyses.
    db.delete(fv)
    db.commit()
    return None


# ── CVEs per firmware version ──────────────────────────────────────────

@router.post("/firmware-versions/{fv_id}/cves", status_code=status.HTTP_201_CREATED)
def add_firmware_cve(
    fv_id: str, body: dict, request: Request,
    user=Depends(require_superadmin),
    db: Session = Depends(get_db),
):
    fv = db.get(FirmwareVersion, fv_id)
    if not fv:
        raise HTTPException(404, "Firmware version not found")
    cve_id = (body.get("cve_id") or "").strip().upper()
    if not _CVE_RE.match(cve_id):
        raise HTTPException(400, "CVE ID must look like CVE-2026-12345")
    if any(c.cve_id == cve_id for c in fv.cves):
        raise HTTPException(409, f"{cve_id} is already associated with "
                                 f"firmware {fv.version}")
    cvss = body.get("cvss")
    if cvss is not None and cvss != "":
        try:
            cvss = float(cvss)
        except (TypeError, ValueError):
            raise HTTPException(400, "CVSS must be a number")
        if not 0.0 <= cvss <= 10.0:
            raise HTTPException(400, "CVSS must be between 0 and 10")
    else:
        cvss = None
    cve = FirmwareCve(firmware_version_id=fv.id, cve_id=cve_id,
                      description=(body.get("description") or "").strip(),
                      cvss=cvss,
                      remediation=(body.get("remediation") or "").strip(),
                      extra={})
    db.add(cve)
    db.commit()
    db.refresh(cve)
    return {"id": cve.id, "cve_id": cve.cve_id, "description": cve.description,
            "cvss": cve.cvss, "remediation": cve.remediation}


@router.delete("/firmware-cves/{cve_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_firmware_cve(
    cve_id: str, user=Depends(require_superadmin),
    db: Session = Depends(get_db),
):
    cve = db.get(FirmwareCve, cve_id)
    if not cve:
        raise HTTPException(404, "CVE not found")
    db.delete(cve)
    db.commit()
    return None


# ── Known issues per firmware version ──────────────────────────────────

@router.post("/firmware-versions/{fv_id}/issues", status_code=status.HTTP_201_CREATED)
def add_firmware_issue(
    fv_id: str, body: dict, request: Request,
    user=Depends(require_superadmin),
    db: Session = Depends(get_db),
):
    fv = db.get(FirmwareVersion, fv_id)
    if not fv:
        raise HTTPException(404, "Firmware version not found")
    title = (body.get("title") or "").strip()
    if not title:
        raise HTTPException(400, "Issue title is required")
    severity = (body.get("severity") or "").strip()
    if severity and severity not in _SEVERITIES:
        raise HTTPException(400, f"Severity must be one of {sorted(_SEVERITIES)}")
    issue = FirmwareIssue(firmware_version_id=fv.id, title=title,
                          description=(body.get("description") or "").strip(),
                          severity=severity,
                          remediation=(body.get("remediation") or "").strip())
    db.add(issue)
    db.commit()
    db.refresh(issue)
    return {"id": issue.id, "title": issue.title, "description": issue.description,
            "severity": issue.severity, "remediation": issue.remediation}


@router.delete("/firmware-issues/{issue_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_firmware_issue(
    issue_id: str, user=Depends(require_superadmin),
    db: Session = Depends(get_db),
):
    issue = db.get(FirmwareIssue, issue_id)
    if not issue:
        raise HTTPException(404, "Issue not found")
    db.delete(issue)
    db.commit()
    return None

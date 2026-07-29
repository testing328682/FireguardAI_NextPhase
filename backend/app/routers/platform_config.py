"""Product & Platform Configuration router (superadmin-only).

Manage device generations, per-generation device models, and recommended
firmware versions.  Used by the TSR pipeline to detect device generation
and flag outdated firmware.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import DeviceGeneration, GenerationDevice, FirmwareRecommendation
from ..security import current_user, require_superadmin
from .. import audit
from sqlalchemy import func

router = APIRouter(prefix="/api/v1/platform", tags=["platform-config"])


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


# ── Firmware recommendation ────────────────────────────────────────────

@router.put("/generations/{gen_id}/firmware")
def set_firmware(
    gen_id: str, body: dict, request: Request,
    user=Depends(require_superadmin),
    db: Session = Depends(get_db),
):
    g = db.get(DeviceGeneration, gen_id)
    if not g:
        raise HTTPException(404, "Generation not found")
    version = (body.get("version") or "").strip()
    # Strip product branding prefixes so only the version number is stored.
    import re
    version = re.sub(r"^SonicOS\s*(?:Enhanced\s*)?", "", version).strip()
    existing = g.firmware[0] if g.firmware else None
    if existing:
        existing.version = version
    else:
        db.add(FirmwareRecommendation(generation_id=gen_id, version=version))
    db.commit()
    return {"generation_id": gen_id, "version": version}

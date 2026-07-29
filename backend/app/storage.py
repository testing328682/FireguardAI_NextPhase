"""Storage abstraction for raw TSRs and rendered reports.

Two backends are supported, selected by ``FGAI_STORAGE_BACKEND``:
    * ``s3``    - production; objects live in region-specific S3 buckets.
    * ``local`` - development; objects live under ``FGAI_LOCAL_STORAGE_DIR``.

For data residency (Phase 4) the storage key is prefixed with the organization's
region (``<region>/orgs/<org>/devices/<device>/...``) and the S3 bucket is chosen
per region from ``settings.region_buckets``. Because the region is embedded in
the key, ``load_tsr``/``delete_object`` can resolve the correct bucket from the
key alone.
"""

from __future__ import annotations

import time
import uuid
from pathlib import Path

from .config import get_settings

settings = get_settings()


def _bucket_for_region(region: str) -> str:
    return settings.region_buckets.get(region, settings.s3_bucket)


def _region_of_key(key: str) -> str:
    head = key.split("/", 1)[0]
    return head if head in settings.region_buckets else settings.default_region


def _key(org_id: str, device_id: str, filename: str, region: str) -> str:
    stamp = time.strftime("%Y%m%dT%H%M%S")
    safe = filename.replace("/", "_").replace("\\", "_")
    return f"{region}/orgs/{org_id}/devices/{device_id}/{stamp}-{uuid.uuid4().hex[:8]}-{safe}"


def save_tsr(org_id: str, device_id: str, filename: str, data: bytes,
             region: str | None = None) -> str:
    region = region or settings.default_region
    key = _key(org_id, device_id, filename, region)
    if settings.storage_backend == "s3":
        import boto3  # imported lazily so local dev needs no AWS SDK
        boto3.client("s3").put_object(Bucket=_bucket_for_region(region), Key=key, Body=data)
    else:
        path = Path(settings.local_storage_dir) / key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return key


def load_tsr(key: str) -> bytes:
    if settings.storage_backend == "s3":
        import boto3
        obj = boto3.client("s3").get_object(Bucket=_bucket_for_region(_region_of_key(key)), Key=key)
        return obj["Body"].read()
    return (Path(settings.local_storage_dir) / key).read_bytes()


def delete_object(key: str) -> None:
    """Best-effort deletion of a stored object (used by retention purge)."""
    if settings.storage_backend == "s3":
        import boto3
        boto3.client("s3").delete_object(Bucket=_bucket_for_region(_region_of_key(key)), Key=key)
    else:
        p = Path(settings.local_storage_dir) / key
        if p.exists():
            p.unlink()

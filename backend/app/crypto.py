"""Symmetric encryption for stored secrets (device passwords, webhook URLs).

Uses Fernet (AES-128-CBC + HMAC). The key comes from
``Settings.credential_encryption_key`` when set; otherwise it is deterministically
derived from ``jwt_secret`` so local development works without extra setup. In
production, set ``FGAI_CREDENTIAL_ENCRYPTION_KEY`` to a stable secret value — a
random key per process would make existing ciphertext undecryptable on restart.
"""

from __future__ import annotations

import base64
import hashlib
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken

from .config import get_settings


@lru_cache
def _fernet() -> Fernet:
    settings = get_settings()
    key = settings.credential_encryption_key
    if key:
        # Accept either a urlsafe base64 Fernet key or any string (derive then).
        try:
            return Fernet(key.encode() if isinstance(key, str) else key)
        except (ValueError, TypeError):
            pass
    # Derive a 32-byte key from the JWT secret as a dev fallback.
    digest = hashlib.sha256(settings.jwt_secret.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt(plaintext: str) -> str:
    if plaintext is None:
        plaintext = ""
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt(token: str) -> str:
    if not token:
        return ""
    try:
        return _fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError):
        return ""

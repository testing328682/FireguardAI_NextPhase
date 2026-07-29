"""Multi-factor authentication: TOTP and backup codes.

TOTP (RFC 6238) is implemented on the standard library — HMAC-SHA1 over a
30-second time step, truncated to six digits — so no extra dependency is
required. Secrets are base32 strings compatible with Google Authenticator,
Authy, 1Password and the like.

Backup codes are random single-use strings; only their bcrypt hashes are
persisted (reusing the application password hasher), so a database read never
reveals a usable code.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

from .security import hash_password, verify_password

_STEP = 30          # seconds per TOTP window
_DIGITS = 6
_B32_LEN = 32       # characters of base32 secret (~160 bits)


def generate_secret() -> str:
    """Return a fresh base32 TOTP secret (no padding, upper-case)."""
    raw = secrets.token_bytes(20)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def _hotp(secret: str, counter: int) -> str:
    # base32 decode requires correct padding.
    pad = "=" * (-len(secret) % 8)
    key = base64.b32decode(secret.upper() + pad)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code_int % (10 ** _DIGITS)).zfill(_DIGITS)


def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    """Validate a TOTP code, tolerating +/- ``window`` steps of clock skew."""
    if not secret or not code:
        return False
    code = code.strip().replace(" ", "")
    if not code.isdigit():
        return False
    counter = int(time.time()) // _STEP
    for drift in range(-window, window + 1):
        if hmac.compare_digest(_hotp(secret, counter + drift), code):
            return True
    return False


def provisioning_uri(secret: str, account_email: str, issuer: str) -> str:
    """Build the ``otpauth://`` URI used to render an enrollment QR code."""
    label = quote(f"{issuer}:{account_email}")
    params = f"secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits={_DIGITS}&period={_STEP}"
    return f"otpauth://totp/{label}?{params}"


# ---- backup codes --------------------------------------------------------
def generate_backup_codes(count: int) -> tuple[list[str], list[str]]:
    """Return ``(plaintext_codes, hashed_codes)``.

    Plaintext is shown to the user exactly once; only the hashes are stored.
    """
    plaintext = [f"{secrets.token_hex(4)}-{secrets.token_hex(4)}" for _ in range(count)]
    hashed = [hash_password(code) for code in plaintext]
    return plaintext, hashed


def consume_backup_code(code: str, hashed_codes: list[str]) -> list[str] | None:
    """If ``code`` matches a stored hash, return the remaining hashes (with the
    used one removed); otherwise return ``None``.
    """
    code = (code or "").strip().lower()
    for h in hashed_codes:
        if verify_password(code, h):
            return [x for x in hashed_codes if x != h]
    return None

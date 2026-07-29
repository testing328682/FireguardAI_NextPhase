"""Authentication, authorisation and tenant scoping.

Provides password hashing, JWT issue/verify, the ``current_user`` dependency
and a ``require_role`` factory. Every data-access dependency derives the
tenant (``organization_id``) from the authenticated user, never from a request
parameter, which is what keeps tenants isolated.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Callable

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .database import get_db
from .models import User, Role, ApiToken

API_TOKEN_PREFIX = "fgat_"   # FirewallGuard API token marker

settings = get_settings()
_pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

# Role hierarchy: a higher-privilege role satisfies any lower requirement.
_ROLE_RANK = {
    Role.viewer: 0,
    Role.analyst: 1,
    Role.msp_operator: 2,
    Role.admin: 3,
    Role.owner: 4,
}


def hash_password(raw: str) -> str:
    return _pwd.hash(raw)


def verify_password(raw: str, hashed: str) -> bool:
    return _pwd.verify(raw, hashed)


def _create_token(subject: str, org_id: str, role: str, ttl: timedelta, kind: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {"sub": subject, "org": org_id, "role": role, "kind": kind,
               "iat": now, "exp": now + ttl}
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def create_access_token(user: User) -> str:
    return _create_token(user.id, user.organization_id, user.role.value,
                         timedelta(minutes=settings.access_token_ttl_minutes), "access")


def create_refresh_token(user: User) -> str:
    return _create_token(user.id, user.organization_id, user.role.value,
                         timedelta(days=settings.refresh_token_ttl_days), "refresh")


def create_mfa_token(user: User) -> str:
    """Short-lived token issued after a correct password when MFA is enabled.

    It only authorises the second-factor step; it is not accepted as an access
    token by ``current_user``.
    """
    return _create_token(user.id, user.organization_id, user.role.value,
                         timedelta(minutes=settings.mfa_token_ttl_minutes), "mfa")


def decode_mfa_token(token: str) -> str:
    """Return the user id from a valid interim MFA token, or raise 401."""
    exc = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid or expired MFA session")
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
        if payload.get("kind") != "mfa":
            raise exc
        return payload["sub"]
    except (jwt.PyJWTError, KeyError):
        raise exc


# ---- account lockout -----------------------------------------------------
def is_locked(user: User) -> bool:
    if user.locked_until is None:
        return False
    locked_until = user.locked_until
    # Some backends (e.g. SQLite) return naive datetimes; assume UTC so the
    # comparison against an aware "now" never raises.
    if locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=timezone.utc)
    return locked_until > datetime.now(timezone.utc)


def register_failed_login(db: Session, user: User) -> None:
    """Increment the failure counter and lock the account at the threshold."""
    user.failed_login_count = (user.failed_login_count or 0) + 1
    if user.failed_login_count >= settings.lockout_threshold:
        user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=settings.lockout_minutes)
        user.failed_login_count = 0
    db.commit()


def register_successful_login(db: Session, user: User) -> None:
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = datetime.now(timezone.utc)
    db.commit()


def generate_api_token() -> tuple[str, str, str]:
    """Return ``(full_token, prefix, hashed_token)`` for a new API token.

    The full token is shown to the user once; only the hash is stored. The
    prefix is a short non-secret fragment used to locate the record at auth time.
    """
    prefix = secrets.token_hex(4)            # 8 hex chars
    secret = secrets.token_urlsafe(32)
    full = f"{API_TOKEN_PREFIX}{prefix}_{secret}"
    return full, prefix, hash_password(full)


def authenticate_api_token(db: Session, token: str) -> User | None:
    """Resolve a valid API token to a transient service-principal User.

    The returned User is not persisted; it carries the token's organization and a
    role derived from its scopes (``admin`` scope -> admin, otherwise analyst).
    """
    body = token[len(API_TOKEN_PREFIX):]
    prefix = body.split("_", 1)[0]
    rec = db.scalar(select(ApiToken).where(
        ApiToken.prefix == prefix, ApiToken.revoked.is_(False)))
    if rec is None or not verify_password(token, rec.hashed_token):
        return None
    if rec.expires_at is not None:
        exp = rec.expires_at if rec.expires_at.tzinfo else rec.expires_at.replace(tzinfo=timezone.utc)
        if exp < datetime.now(timezone.utc):
            return None
    rec.last_used_at = datetime.now(timezone.utc)
    db.commit()
    role = Role.admin if "admin" in (rec.scopes or []) else Role.analyst
    return User(id=rec.id, organization_id=rec.organization_id,
                email=f"token:{rec.name}", role=role, is_active=True)


def current_user(token: str = Depends(oauth2_scheme),
                 db: Session = Depends(get_db)) -> User:
    cred_exc = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                             detail="Could not validate credentials",
                             headers={"WWW-Authenticate": "Bearer"})
    # API token path (programmatic access) is an alternative to a JWT.
    if token.startswith(API_TOKEN_PREFIX):
        user = authenticate_api_token(db, token)
        if user is None:
            raise cred_exc
        return user
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
        if payload.get("kind") != "access":
            raise cred_exc
        user_id = payload.get("sub")
    except jwt.PyJWTError:
        raise cred_exc
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise cred_exc
    return user


def require_role(minimum: Role) -> Callable[[User], User]:
    def _dep(user: User = Depends(current_user)) -> User:
        if _ROLE_RANK[user.role] < _ROLE_RANK[minimum]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="Insufficient role for this action")
        return user
    return _dep


def require_superadmin(user: User = Depends(current_user)) -> User:
    """Platform-operator gate for cross-tenant endpoints.

    Only a persisted user with ``is_superadmin`` passes. API-token principals are
    transient and never carry the flag, so tokens cannot reach platform routes.
    """
    if not getattr(user, "is_superadmin", False):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Platform operator access required")
    return user

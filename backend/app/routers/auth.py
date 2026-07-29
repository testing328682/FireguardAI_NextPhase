"""Authentication, MFA and user-management endpoints.

The login flow is two-step when MFA is enabled: a correct password returns a
short-lived ``mfa_token`` and ``mfa_required=True``; the client then posts that
token plus a TOTP (or backup) code to ``/auth/mfa/verify`` for real tokens.
Account lockout and audit logging are applied around the password check.
"""

from __future__ import annotations

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..database import get_db
from ..models import User, Role, Organization, Customer, PlanTier
from ..schemas import (
    LoginRequest, LoginResult, Token, UserCreate, UserOut, ProfileUpdate, RegisterRequest,
    MfaVerifyRequest, MfaEnrollResponse, MfaActivateRequest, MfaActivateResponse,
    MfaDisableRequest,
)
from ..security import (
    hash_password, verify_password, create_access_token, create_refresh_token,
    create_mfa_token, decode_mfa_token, current_user, require_role,
    is_locked, register_failed_login, register_successful_login,
)
from .. import mfa as mfa_mod
from .. import audit

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])
settings = get_settings()

_LOCKED_MSG = "Account temporarily locked due to repeated failed logins. Try again later."


@router.post("/register", response_model=Token, status_code=status.HTTP_201_CREATED)
def register(body: RegisterRequest, request: Request, db: Session = Depends(get_db)) -> Token:
    """Public self-service sign-up.

    Creates a new organization (named after the company), an owner user, and a
    default customer so uploads work immediately, then returns access/refresh
    tokens to log the user straight in.
    """
    if db.scalar(select(User).where(User.email == body.email)):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="An account with this email already exists")
    org = Organization(name=body.company_name, is_msp=body.is_msp,
                       plan=PlanTier.free, subscription_status="none",
                       region=body.region if body.region in settings.regions else "us")
    db.add(org)
    db.flush()
    user = User(organization_id=org.id, email=body.email, full_name=body.full_name,
                phone=body.phone, address=body.address, role=Role.owner,
                hashed_password=hash_password(body.password))
    # A default customer lets the owner upload TSRs right away.
    db.add_all([user, Customer(organization_id=org.id, name=f"{body.company_name} (default)")])
    db.commit()
    db.refresh(user)
    # Grant the starter free license at registration (1 device, 30 days). Never
    # block sign-up on a licensing hiccup — the bundles endpoint re-ensures it.
    try:
        from .plans import ensure_free_license
        ensure_free_license(db, org)
    except Exception:  # noqa: BLE001
        db.rollback()
    register_successful_login(db, user)
    audit.log_action(db, organization_id=org.id, action="auth.registered",
                     resource_type="organization", resource_id=org.id, user=user, request=request,
                     after={"company": body.company_name, "email": body.email})
    return Token(access_token=create_access_token(user),
                 refresh_token=create_refresh_token(user))


@router.post("/login", response_model=LoginResult)
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)) -> LoginResult:
    user = db.scalar(select(User).where(User.email == body.email))
    bad = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid email or password")
    if user is None or not user.is_active:
        raise bad
    if is_locked(user):
        raise HTTPException(status_code=status.HTTP_423_LOCKED, detail=_LOCKED_MSG)
    if not verify_password(body.password, user.hashed_password):
        register_failed_login(db, user)
        audit.log_action(db, organization_id=user.organization_id,
                         action=audit.LOGIN_FAILED, resource_type="user",
                         resource_id=user.id, user_email=user.email, request=request)
        if is_locked(user):
            raise HTTPException(status_code=status.HTTP_423_LOCKED, detail=_LOCKED_MSG)
        raise bad

    if user.mfa_enabled:
        return LoginResult(mfa_required=True, mfa_token=create_mfa_token(user))

    register_successful_login(db, user)
    audit.log_action(db, organization_id=user.organization_id, action=audit.LOGIN,
                     resource_type="user", resource_id=user.id, user=user, request=request)
    return LoginResult(access_token=create_access_token(user),
                       refresh_token=create_refresh_token(user))


@router.post("/mfa/verify", response_model=Token)
def mfa_verify(body: MfaVerifyRequest, request: Request,
               db: Session = Depends(get_db)) -> Token:
    """Complete login by validating a TOTP or backup code."""
    user_id = decode_mfa_token(body.mfa_token)
    user = db.get(User, user_id)
    if user is None or not user.is_active or not user.mfa_enabled:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA session")
    if is_locked(user):
        raise HTTPException(status_code=status.HTTP_423_LOCKED, detail=_LOCKED_MSG)

    if mfa_mod.verify_totp(user.totp_secret, body.code):
        ok = True
    else:
        remaining = mfa_mod.consume_backup_code(body.code, user.backup_codes or [])
        ok = remaining is not None
        if ok:
            user.backup_codes = remaining
            db.commit()
    if not ok:
        register_failed_login(db, user)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA code")

    register_successful_login(db, user)
    audit.log_action(db, organization_id=user.organization_id, action=audit.LOGIN,
                     resource_type="user", resource_id=user.id, user=user, request=request)
    return Token(access_token=create_access_token(user),
                 refresh_token=create_refresh_token(user))


@router.post("/refresh", response_model=Token)
def refresh(refresh_token: str, db: Session = Depends(get_db)) -> Token:
    exc = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid refresh token")
    try:
        payload = jwt.decode(refresh_token, settings.jwt_secret,
                             algorithms=[settings.jwt_algorithm])
        if payload.get("kind") != "refresh":
            raise exc
    except jwt.PyJWTError:
        raise exc
    user = db.get(User, payload.get("sub"))
    if user is None or not user.is_active:
        raise exc
    return Token(access_token=create_access_token(user),
                 refresh_token=create_refresh_token(user))


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)) -> User:
    return user


@router.patch("/me", response_model=UserOut)
def update_me(body: ProfileUpdate, user: User = Depends(current_user),
              db: Session = Depends(get_db)) -> User:
    if body.full_name is not None:
        user.full_name = body.full_name
    if body.phone is not None:
        user.phone = body.phone
    if body.address is not None:
        user.address = body.address
    if body.notify_new_critical is not None:
        user.notify_new_critical = body.notify_new_critical
    if body.notify_scan_failed is not None:
        user.notify_scan_failed = body.notify_scan_failed
    db.commit()
    db.refresh(user)
    return user


# ---- MFA enrollment ------------------------------------------------------
@router.post("/mfa/enroll", response_model=MfaEnrollResponse)
def mfa_enroll(user: User = Depends(current_user), db: Session = Depends(get_db)) -> MfaEnrollResponse:
    """Begin MFA setup: issue a secret and the otpauth URI for a QR code.

    The secret is stored but MFA is not enforced until ``/mfa/activate``
    confirms the user can generate a valid code.
    """
    if user.mfa_enabled:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="MFA is already enabled")
    secret = mfa_mod.generate_secret()
    user.totp_secret = secret
    db.commit()
    return MfaEnrollResponse(
        secret=secret,
        otpauth_uri=mfa_mod.provisioning_uri(secret, user.email, settings.mfa_issuer))


@router.post("/mfa/activate", response_model=MfaActivateResponse)
def mfa_activate(body: MfaActivateRequest, request: Request,
                 user: User = Depends(current_user), db: Session = Depends(get_db)) -> MfaActivateResponse:
    """Confirm enrollment with a valid code; enable MFA and return backup codes."""
    if user.mfa_enabled:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="MFA is already enabled")
    if not user.totp_secret or not mfa_mod.verify_totp(user.totp_secret, body.code):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid code")
    plaintext, hashed = mfa_mod.generate_backup_codes(settings.mfa_backup_code_count)
    user.backup_codes = hashed
    user.mfa_enabled = True
    db.commit()
    audit.log_action(db, organization_id=user.organization_id, action=audit.MFA_ENABLED,
                     resource_type="user", resource_id=user.id, user=user, request=request)
    return MfaActivateResponse(backup_codes=plaintext)


@router.post("/mfa/disable", status_code=status.HTTP_204_NO_CONTENT)
def mfa_disable(body: MfaDisableRequest, request: Request,
                user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Disable MFA after validating a current code (or backup code)."""
    if not user.mfa_enabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA is not enabled")
    valid = mfa_mod.verify_totp(user.totp_secret, body.code) or \
        mfa_mod.consume_backup_code(body.code, user.backup_codes or []) is not None
    if not valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid code")
    user.mfa_enabled = False
    user.totp_secret = ""
    user.backup_codes = []
    db.commit()
    audit.log_action(db, organization_id=user.organization_id, action=audit.MFA_DISABLED,
                     resource_type="user", resource_id=user.id, user=user, request=request)
    from fastapi import Response
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(body: UserCreate, request: Request,
                actor: User = Depends(require_role(Role.admin)),
                db: Session = Depends(get_db)) -> User:
    """Create a user inside the actor's organization (admin or owner only)."""
    if db.scalar(select(User).where(User.email == body.email)):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="A user with this email already exists")
    user = User(organization_id=actor.organization_id, email=body.email,
                full_name=body.full_name, role=body.role,
                hashed_password=hash_password(body.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    audit.log_action(db, organization_id=actor.organization_id, action=audit.USER_CREATED,
                     resource_type="user", resource_id=user.id, user=actor, request=request,
                     after={"email": user.email, "role": user.role.value})
    return user

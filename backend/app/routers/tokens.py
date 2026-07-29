"""Programmatic API token management.

Tokens authenticate API clients as an alternative to a JWT (see
``security.authenticate_api_token``). The plaintext token is returned exactly
once, at creation; only its bcrypt hash is stored thereafter.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User, Role, ApiToken
from ..schemas import ApiTokenCreate, ApiTokenOut, ApiTokenCreated
from ..security import current_user, require_role, generate_api_token
from .. import audit

router = APIRouter(prefix="/api/v1/settings", tags=["api-tokens"])


@router.get("/api-tokens", response_model=list[ApiTokenOut])
def list_tokens(user: User = Depends(current_user),
                db: Session = Depends(get_db)) -> list[ApiToken]:
    return list(db.scalars(select(ApiToken).where(
        ApiToken.organization_id == user.organization_id)
        .order_by(ApiToken.created_at.desc())))


@router.post("/api-tokens", response_model=ApiTokenCreated, status_code=status.HTTP_201_CREATED)
def create_token(body: ApiTokenCreate, request: Request,
                 user: User = Depends(require_role(Role.admin)),
                 db: Session = Depends(get_db)) -> ApiTokenCreated:
    """Create an API token. The plaintext is returned once and never stored."""
    full, prefix, hashed = generate_api_token()
    token = ApiToken(
        organization_id=user.organization_id, name=body.name, prefix=prefix,
        hashed_token=hashed, scopes=body.scopes, expires_at=body.expires_at,
        created_by=user.id)
    db.add(token)
    db.commit()
    db.refresh(token)
    audit.log_action(db, organization_id=user.organization_id, action=audit.API_TOKEN_CREATED,
                     resource_type="api_token", resource_id=token.id, user=user, request=request,
                     after={"name": token.name, "scopes": body.scopes})
    return ApiTokenCreated(
        id=token.id, name=token.name, prefix=token.prefix, scopes=token.scopes,
        last_used_at=token.last_used_at, expires_at=token.expires_at,
        revoked=token.revoked, created_at=token.created_at, token=full)


@router.delete("/api-tokens/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_token(token_id: str, request: Request,
                 user: User = Depends(require_role(Role.admin)),
                 db: Session = Depends(get_db)):
    """Revoke a token (soft delete so it can never be reactivated)."""
    token = db.get(ApiToken, token_id)
    if token is None or token.organization_id != user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Token not found")
    token.revoked = True
    db.commit()
    audit.log_action(db, organization_id=user.organization_id, action=audit.API_TOKEN_REVOKED,
                     resource_type="api_token", resource_id=token.id, user=user, request=request)
    return Response(status_code=status.HTTP_204_NO_CONTENT)

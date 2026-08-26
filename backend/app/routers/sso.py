"""Single sign-on endpoints (OIDC and SAML).

Login is initiated per organization. OIDC returns the user to ``/sso/callback``;
SAML posts to ``/sso/saml/acs``. Both finish by redirecting the browser to the
frontend with freshly minted app tokens in the URL fragment.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import page_control as page_control_mod
from ..config import get_settings
from ..database import get_db
from ..models import User, Role, SSOConfig, SSOProtocol
from ..schemas import SSOConfigIn, SSOConfigOut, SSOStatus
from ..security import require_role
from ..crypto import encrypt
from .. import sso as sso_mod
from .. import audit
from .. import page_control as page_control_mod

router = APIRouter(prefix="/api/v1/sso", tags=["sso"])
settings = get_settings()


def _config(db: Session, organization_id: str) -> SSOConfig | None:
    return db.scalar(select(SSOConfig).where(SSOConfig.organization_id == organization_id))


@router.get("/{organization_id}/status", response_model=SSOStatus)
def sso_status(organization_id: str, db: Session = Depends(get_db)) -> SSOStatus:
    """Public: lets the login page show an SSO button for an organization."""
    cfg = _config(db, organization_id)
    if cfg is None or not cfg.enabled:
        return SSOStatus(enabled=False)
    return SSOStatus(enabled=True, protocol=cfg.protocol)


@router.get("/{organization_id}/login")
def sso_login(organization_id: str, db: Session = Depends(get_db)) -> RedirectResponse:
    cfg = _config(db, organization_id)
    if cfg is None or not cfg.enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SSO is not enabled")
    state = sso_mod.encode_state(organization_id)
    try:
        if cfg.protocol == SSOProtocol.oidc:
            url = sso_mod.oidc_authorize_url(
                cfg, state, f"{settings.public_api_url}/api/v1/sso/callback")
        else:
            url = sso_mod.saml_authn_request_url(
                cfg, state, f"{settings.public_api_url}/api/v1/sso/saml/acs")
    except sso_mod.SSOError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return RedirectResponse(url, status_code=302)


@router.get("/callback")
def oidc_callback(code: str, state: str, db: Session = Depends(get_db)) -> RedirectResponse:
    try:
        org_id = sso_mod.decode_state(state)
        cfg = _config(db, org_id)
        if cfg is None or not cfg.enabled:
            raise sso_mod.SSOError("SSO is not enabled")
        user = sso_mod.oidc_complete(
            db, cfg, code, f"{settings.public_api_url}/api/v1/sso/callback")
    except sso_mod.SSOError as exc:
        return RedirectResponse(f"{settings.public_app_url}/#/sso?error={exc}", status_code=302)
    audit.log_action(db, organization_id=user.organization_id, action=audit.LOGIN,
                     resource_type="user", resource_id=user.id, user=user)
    return RedirectResponse(sso_mod.redirect_with_tokens(sso_mod.issue_tokens(user)), status_code=302)


@router.post("/saml/acs")
def saml_acs(SAMLResponse: str = Form(...), RelayState: str = Form(""),
             db: Session = Depends(get_db)) -> RedirectResponse:
    try:
        org_id = sso_mod.decode_state(RelayState)
        cfg = _config(db, org_id)
        if cfg is None or not cfg.enabled:
            raise sso_mod.SSOError("SSO is not enabled")
        user = sso_mod.saml_complete(db, cfg, SAMLResponse)
    except sso_mod.SSOError as exc:
        return RedirectResponse(f"{settings.public_app_url}/#/sso?error={exc}", status_code=302)
    audit.log_action(db, organization_id=user.organization_id, action=audit.LOGIN,
                     resource_type="user", resource_id=user.id, user=user)
    return RedirectResponse(sso_mod.redirect_with_tokens(sso_mod.issue_tokens(user)), status_code=302)


# ---- configuration (admin) ----------------------------------------------
def _require_sso_config_enabled(db: Session, user: User) -> None:
    """Page Control gate: configuration APIs are off for customers while the
    SAML/OIDC/SSO page is disabled. Server Admins bypass (they manage the flag).
    """
    if not getattr(user, "is_superadmin", False) and not page_control_mod.is_page_enabled(db, "sso"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="SSO configuration is disabled by your service provider")


@router.get("/config", response_model=SSOConfigOut)
def get_config(user: User = Depends(require_role(Role.admin)),
               db: Session = Depends(get_db)) -> SSOConfigOut:
    _require_sso_config_enabled(db, user)
    cfg = _config(db, user.organization_id)
    if cfg is None:
        return SSOConfigOut(
            enabled=False, protocol=SSOProtocol.oidc, oidc_discovery_url="",
            oidc_client_id="", has_client_secret=False, saml_idp_entity_id="",
            saml_idp_sso_url="", saml_idp_x509_cert="", groups_attribute="groups",
            group_role_map={}, default_role="viewer")
    return SSOConfigOut(
        enabled=cfg.enabled, protocol=cfg.protocol,
        oidc_discovery_url=cfg.oidc_discovery_url, oidc_client_id=cfg.oidc_client_id,
        has_client_secret=bool(cfg.oidc_encrypted_client_secret),
        saml_idp_entity_id=cfg.saml_idp_entity_id, saml_idp_sso_url=cfg.saml_idp_sso_url,
        saml_idp_x509_cert=cfg.saml_idp_x509_cert, groups_attribute=cfg.groups_attribute,
        group_role_map=cfg.group_role_map or {}, default_role=cfg.default_role)


@router.put("/config", response_model=SSOConfigOut)
def put_config(body: SSOConfigIn, request: Request,
               user: User = Depends(require_role(Role.admin)),
               db: Session = Depends(get_db)) -> SSOConfigOut:
    _require_sso_config_enabled(db, user)
    cfg = _config(db, user.organization_id)
    if cfg is None:
        cfg = SSOConfig(organization_id=user.organization_id)
        db.add(cfg)
    cfg.enabled = body.enabled
    cfg.protocol = body.protocol
    cfg.oidc_discovery_url = body.oidc_discovery_url
    cfg.oidc_client_id = body.oidc_client_id
    if body.oidc_client_secret:
        cfg.oidc_encrypted_client_secret = encrypt(body.oidc_client_secret)
    cfg.saml_idp_entity_id = body.saml_idp_entity_id
    cfg.saml_idp_sso_url = body.saml_idp_sso_url
    cfg.saml_idp_x509_cert = body.saml_idp_x509_cert
    cfg.groups_attribute = body.groups_attribute
    cfg.group_role_map = body.group_role_map
    cfg.default_role = body.default_role
    db.commit()
    audit.log_action(db, organization_id=user.organization_id, action="sso.config_updated",
                     resource_type="sso_config", resource_id=cfg.id, user=user, request=request,
                     after={"enabled": body.enabled, "protocol": body.protocol.value})
    return get_config(user, db)
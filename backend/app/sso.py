"""Single sign-on: OIDC (verifiable) and SAML 2.0 (assertion parsing).

OIDC uses the authorization-code flow. The interim ``state`` is a short-lived
signed JWT (no server-side session store needed). The returned ``id_token`` is
verified against the IdP's JWKS, issuer and audience via PyJWT. Group claims are
mapped to application roles and users are provisioned just-in-time.

SAML support builds an AuthnRequest and parses the assertion at the ACS
endpoint. **Signature validation requires xmlsec/python3-saml**, which are not
wired here; assertions are therefore accepted only when
``settings.saml_verify_signature`` is False (the default for non-production). Do
not enable SAML against an untrusted IdP until signature validation is added.
"""

from __future__ import annotations

import base64
import json
import urllib.parse
import urllib.request
import zlib
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from xml.etree import ElementTree as ET

import jwt
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .crypto import decrypt
from .models import SSOConfig, SSOProtocol, User, Role
from .security import _ROLE_RANK, create_access_token, create_refresh_token, hash_password

settings = get_settings()


class SSOError(Exception):
    """Raised on any SSO configuration or protocol error."""


# ---- shared helpers ------------------------------------------------------
def _get_json(url: str, timeout: int = 15) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310
        return json.loads(resp.read())


def encode_state(organization_id: str) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode({"org": organization_id, "kind": "sso_state", "iat": now,
                       "exp": now + timedelta(minutes=settings.sso_state_ttl_minutes)},
                      settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_state(token: str) -> str:
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except jwt.PyJWTError as exc:
        raise SSOError("Invalid or expired SSO state") from exc
    if payload.get("kind") != "sso_state":
        raise SSOError("Invalid SSO state")
    return payload["org"]


def map_role(config: SSOConfig, groups: list[str]) -> str:
    """Map IdP groups to the highest-privilege matching application role."""
    best: str | None = None
    best_rank = -1
    for g in groups or []:
        role_value = (config.group_role_map or {}).get(g)
        if not role_value:
            continue
        try:
            rank = _ROLE_RANK[Role(role_value)]
        except (ValueError, KeyError):
            continue
        if rank > best_rank:
            best, best_rank = role_value, rank
    return best or config.default_role or "viewer"


def provision_user(db: Session, organization_id: str, email: str, role_value: str) -> User:
    """Find-or-create an SSO user and align their role with the IdP mapping."""
    email = email.lower().strip()
    if not email:
        raise SSOError("IdP did not return an email address")
    user = db.scalar(select(User).where(User.email == email))
    try:
        role = Role(role_value)
    except ValueError:
        role = Role.viewer
    if user is not None:
        if user.organization_id != organization_id:
            raise SSOError("This email belongs to a different organization")
        user.role = role
        user.is_active = True
        db.commit()
        return user
    import secrets
    user = User(organization_id=organization_id, email=email, full_name=email.split("@")[0],
                role=role, hashed_password=hash_password(secrets.token_urlsafe(32)))
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def issue_tokens(user: User) -> dict:
    return {"access_token": create_access_token(user),
            "refresh_token": create_refresh_token(user)}


def redirect_with_tokens(tokens: dict) -> str:
    """Frontend SSO landing URL carrying tokens in the fragment."""
    frag = urllib.parse.urlencode({"access": tokens["access_token"],
                                   "refresh": tokens["refresh_token"]})
    return f"{settings.public_app_url}/#/sso?{frag}"


# ---- OIDC ----------------------------------------------------------------
@lru_cache(maxsize=32)
def _oidc_metadata(discovery_url: str) -> dict:
    return _get_json(discovery_url)


def oidc_authorize_url(config: SSOConfig, state: str, redirect_uri: str) -> str:
    if not config.oidc_discovery_url or not config.oidc_client_id:
        raise SSOError("OIDC is not fully configured")
    meta = _oidc_metadata(config.oidc_discovery_url)
    params = {
        "response_type": "code", "client_id": config.oidc_client_id,
        "redirect_uri": redirect_uri, "scope": "openid email profile",
        "state": state,
    }
    return f"{meta['authorization_endpoint']}?{urllib.parse.urlencode(params)}"


def oidc_complete(db: Session, config: SSOConfig, code: str, redirect_uri: str) -> User:
    meta = _oidc_metadata(config.oidc_discovery_url)
    secret = decrypt(config.oidc_encrypted_client_secret)
    data = urllib.parse.urlencode({
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": redirect_uri, "client_id": config.oidc_client_id,
        "client_secret": secret,
    }).encode()
    req = urllib.request.Request(meta["token_endpoint"], data=data,
                                 headers={"Content-Type": "application/x-www-form-urlencoded",
                                          "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
            token_resp = json.loads(resp.read())
    except Exception as exc:  # noqa: BLE001
        raise SSOError(f"Token exchange failed: {exc}") from exc

    id_token = token_resp.get("id_token")
    if not id_token:
        raise SSOError("IdP did not return an id_token")
    claims = verify_id_token(meta, config, id_token)
    email = claims.get("email") or claims.get("preferred_username", "")
    groups = claims.get(config.groups_attribute) or claims.get("groups") or []
    if isinstance(groups, str):
        groups = [groups]
    role = map_role(config, groups)
    return provision_user(db, config.organization_id, email, role)


def verify_id_token(meta: dict, config: SSOConfig, id_token: str) -> dict:
    """Verify the id_token signature (JWKS), issuer and audience."""
    try:
        jwk_client = jwt.PyJWKClient(meta["jwks_uri"])
        signing_key = jwk_client.get_signing_key_from_jwt(id_token)
        return jwt.decode(id_token, signing_key.key,
                          algorithms=["RS256", "ES256"],
                          audience=config.oidc_client_id,
                          issuer=meta.get("issuer"))
    except Exception as exc:  # noqa: BLE001
        raise SSOError(f"id_token verification failed: {exc}") from exc


# ---- SAML ----------------------------------------------------------------
_SAML_NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
}


def saml_authn_request_url(config: SSOConfig, relay_state: str, acs_url: str) -> str:
    if not config.saml_idp_sso_url:
        raise SSOError("SAML is not fully configured")
    issue_instant = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    request_id = "_" + base64.b16encode(issue_instant.encode()).decode()[:32]
    xml = (
        f'<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        f'ID="{request_id}" Version="2.0" IssueInstant="{issue_instant}" '
        f'AssertionConsumerServiceURL="{acs_url}" '
        f'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">'
        f'<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
        f'{settings.public_api_url}</saml:Issuer></samlp:AuthnRequest>'
    )
    # HTTP-Redirect binding: deflate, base64, urlencode.
    deflated = zlib.compress(xml.encode())[2:-4]
    saml_request = base64.b64encode(deflated).decode()
    params = urllib.parse.urlencode({"SAMLRequest": saml_request, "RelayState": relay_state})
    sep = "&" if "?" in config.saml_idp_sso_url else "?"
    return f"{config.saml_idp_sso_url}{sep}{params}"


def parse_saml_response(config: SSOConfig, saml_response_b64: str) -> tuple[str, list[str]]:
    """Extract (email, groups) from a base64 SAMLResponse.

    Signature validation is gated by ``settings.saml_verify_signature`` and is not
    implemented here (requires xmlsec); when that flag is on, this raises.
    """
    if settings.saml_verify_signature:
        raise SSOError("SAML signature validation is enabled but not implemented in this build")
    try:
        xml = base64.b64decode(saml_response_b64)
        root = ET.fromstring(xml)
    except Exception as exc:  # noqa: BLE001
        raise SSOError(f"Malformed SAMLResponse: {exc}") from exc

    nameid_el = root.find(".//saml:Subject/saml:NameID", _SAML_NS)
    email = (nameid_el.text or "").strip() if nameid_el is not None else ""

    groups: list[str] = []
    for attr in root.findall(".//saml:Attribute", _SAML_NS):
        name = attr.get("Name", "")
        if name in (config.groups_attribute, "groups", "Groups",
                    "http://schemas.xmlsoap.org/claims/Group"):
            for val in attr.findall("saml:AttributeValue", _SAML_NS):
                if val.text:
                    groups.append(val.text.strip())
        if name in ("email", "Email",
                    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress") and not email:
            v = attr.find("saml:AttributeValue", _SAML_NS)
            if v is not None and v.text:
                email = v.text.strip()
    return email, groups


def saml_complete(db: Session, config: SSOConfig, saml_response_b64: str) -> User:
    email, groups = parse_saml_response(config, saml_response_b64)
    role = map_role(config, groups)
    return provision_user(db, config.organization_id, email, role)

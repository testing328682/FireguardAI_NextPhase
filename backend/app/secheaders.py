"""Security response headers middleware.

Adds the standard hardening headers (HSTS, CSP, X-Frame-Options, etc.) to every
response. Values come from Settings so they can be tuned per environment. HSTS
is only meaningful over HTTPS but is harmless on plain HTTP in development.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from .config import get_settings

settings = get_settings()


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        if not settings.security_headers_enabled:
            return response
        h = response.headers
        h.setdefault("Strict-Transport-Security",
                     f"max-age={settings.hsts_max_age}; includeSubDomains; preload")
        h.setdefault("Content-Security-Policy", settings.content_security_policy)
        h.setdefault("X-Frame-Options", "DENY")
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        h.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        return response

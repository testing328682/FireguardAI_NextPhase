"""Custom rate-limiting middleware.

A fixed one-minute window counter keyed by client IP. Authentication endpoints
(``/api/v1/auth/*``) get a stricter budget than the general API, which blunts
password-guessing and token-refresh abuse. Counters are held in process memory;
a multi-process deployment would back this with Redis, but the algorithm and
response contract are identical.

Exceeding a budget yields ``429 Too Many Requests`` with a ``Retry-After``
header pointing at the next window boundary.
"""

from __future__ import annotations

import time
from collections import defaultdict

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from .config import get_settings

settings = get_settings()

_WINDOW = 60  # seconds


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        # key -> (window_start_epoch, count)
        self._buckets: dict[str, list] = defaultdict(lambda: [0.0, 0])

    def _limit_for(self, path: str) -> int:
        if path.startswith("/api/v1/auth"):
            return settings.auth_rate_limit_per_minute
        return settings.rate_limit_per_minute

    async def dispatch(self, request: Request, call_next):
        if not settings.rate_limit_enabled:
            return await call_next(request)

        path = request.url.path
        # Health/root probes are never limited.
        if path in ("/health", "/"):
            return await call_next(request)

        ip = request.client.host if request.client else "unknown"
        limit = self._limit_for(path)
        scope = "auth" if path.startswith("/api/v1/auth") else "api"
        key = f"{scope}:{ip}"

        now = time.time()
        window_start, count = self._buckets[key]
        if now - window_start >= _WINDOW:
            window_start, count = now, 0

        count += 1
        self._buckets[key] = [window_start, count]

        if count > limit:
            retry_after = int(_WINDOW - (now - window_start)) + 1
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Slow down and retry shortly."},
                headers={"Retry-After": str(max(1, retry_after))})

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(max(0, limit - count))
        return response

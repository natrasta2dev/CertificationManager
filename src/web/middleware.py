"""Middleware de rate limiting et CSRF."""

import time
from collections import defaultdict
from typing import Callable, DefaultDict, List

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from ..config import get_settings
from ..core.auth import decode_access_token


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Limite le nombre de requêtes par IP sur les endpoints API."""

    def __init__(self, app, requests_per_minute: int = 120):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self._hits: DefaultDict[str, List[float]] = defaultdict(list)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        settings = get_settings()
        if not settings.rate_limit_enabled:
            return await call_next(request)

        if not request.url.path.startswith("/api/"):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        window_start = now - 60
        self._hits[client_ip] = [t for t in self._hits[client_ip] if t > window_start]

        if len(self._hits[client_ip]) >= self.requests_per_minute:
            remaining = 0
            return JSONResponse(
                status_code=429,
                content={"detail": "Trop de requêtes. Réessayez dans une minute."},
                headers={
                    "X-RateLimit-Limit": str(self.requests_per_minute),
                    "X-RateLimit-Remaining": str(remaining),
                    "X-RateLimit-Reset": str(int(now + 60)),
                },
            )

        self._hits[client_ip].append(now)
        remaining = self.requests_per_minute - len(self._hits[client_ip])
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(self.requests_per_minute)
        response.headers["X-RateLimit-Remaining"] = str(max(0, remaining))
        response.headers["X-RateLimit-Reset"] = str(int(now + 60))
        return response


class CsrfMiddleware(BaseHTTPMiddleware):
    """Vérifie le token CSRF sur les requêtes mutantes authentifiées."""

    SAFE_PATHS = {"/api/auth/login", "/api/auth/refresh", "/api/auth/status"}

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        settings = get_settings()
        if not settings.auth_enabled:
            return await call_next(request)
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return await call_next(request)
        if not request.url.path.startswith("/api/"):
            return await call_next(request)
        if request.url.path in self.SAFE_PATHS:
            return await call_next(request)

        auth_header = request.headers.get("Authorization", "")
        csrf_header = request.headers.get("X-CSRF-Token", "")
        if not auth_header.startswith("Bearer ") or not csrf_header:
            return JSONResponse(
                status_code=403,
                content={"detail": "Token CSRF requis pour cette opération"},
            )

        try:
            payload = decode_access_token(auth_header[7:])
            if payload.get("csrf") != csrf_header:
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Token CSRF invalide"},
                )
        except Exception:
            return JSONResponse(status_code=403, content={"detail": "Token invalide"})

        return await call_next(request)

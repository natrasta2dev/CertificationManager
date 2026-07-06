"""Gestion des clés d'idempotence pour requêtes POST critiques."""

import hashlib
import json
import time
from typing import Any, Dict, Optional, Tuple

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

_IDEMPOTENCY_STORE: Dict[str, Tuple[float, int, Dict[str, Any]]] = {}
_TTL_SECONDS = 3600
_IDEMPOTENT_SUFFIXES = (
    "/certificates",
    "/certificates/bulk-delete",
    "/certificates/bulk-renew",
)


def _store_key(method: str, path: str, idem_key: str, body: bytes) -> str:
    digest = hashlib.sha256(body).hexdigest()[:16] if body else ""
    return f"{method}:{path}:{idem_key}:{digest}"


class IdempotencyMiddleware(BaseHTTPMiddleware):
    """Cache les réponses pour Idempotency-Key sur POST critiques."""

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.method != "POST":
            return await call_next(request)

        path = request.url.path.rstrip("/")
        if not any(path.endswith(suffix) for suffix in _IDEMPOTENT_SUFFIXES):
            return await call_next(request)

        idem_key = request.headers.get("Idempotency-Key") or request.headers.get(
            "X-Idempotency-Key"
        )
        if not idem_key:
            return await call_next(request)

        body = await request.body()

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        request._receive = receive  # noqa: SLF001

        store_key = _store_key(request.method, path, idem_key, body)
        now = time.time()
        _purge_expired(now)

        if store_key in _IDEMPOTENCY_STORE:
            _, status, payload = _IDEMPOTENCY_STORE[store_key]
            return JSONResponse(status_code=status, content=payload)

        response = await call_next(request)
        if response.status_code < 500:
            body_bytes = b""
            async for chunk in response.body_iterator:
                body_bytes += chunk
            try:
                payload = json.loads(body_bytes.decode())
            except (json.JSONDecodeError, UnicodeDecodeError):
                return Response(
                    content=body_bytes,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    media_type=response.media_type,
                )
            _IDEMPOTENCY_STORE[store_key] = (now, response.status_code, payload)
            return JSONResponse(status_code=response.status_code, content=payload)
        return response


def _purge_expired(now: float) -> None:
    expired = [k for k, (ts, _, _) in _IDEMPOTENCY_STORE.items() if now - ts > _TTL_SECONDS]
    for k in expired:
        del _IDEMPOTENCY_STORE[k]

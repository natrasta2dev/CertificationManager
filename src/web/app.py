"""Application web FastAPI pour CertificationManager."""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from ..config import get_settings
from ..core.users import UserManager
from ..core.version import get_version
from .middleware import CsrfMiddleware, RateLimitMiddleware
from .idempotency import IdempotencyMiddleware
from .routers import (
    alerts,
    app_config,
    audit,
    auth,
    automation,
    backup,
    bulk,
    ca,
    certificates,
    client_certificates,
    compliance,
    csr,
    letsencrypt,
    metrics,
    pages,
    statistics,
    ws,
)

API_ROUTERS = [
    (auth.router, "auth"),
    (audit.router, "audit"),
    (statistics.router, "statistics"),
    (alerts.router, "alerts"),
    (certificates.router, "certificates"),
    (csr.router, "csr"),
    (ca.router, "ca"),
    (letsencrypt.router, "letsencrypt"),
    (client_certificates.router, "client-certificates"),
    (backup.router, "backup"),
    (automation.router, "automation"),
    (compliance.router, "compliance"),
    (app_config.router, "config"),
    (metrics.router, "metrics"),
    (bulk.router, "bulk"),
    (ws.router, "realtime"),
]


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialisation au démarrage."""
    settings = get_settings()
    if settings.auth_enabled:
        if not settings.admin_password:
            raise RuntimeError(
                "CERTMANAGER_ADMIN_PASSWORD est requis lorsque "
                "CERTMANAGER_AUTH_ENABLED=true"
            )
        user_manager = UserManager(storage_path=settings.storage_path)
        user_manager.ensure_default_admin(settings.admin_password)
    yield


def create_app() -> FastAPI:
    """Crée et configure l'application FastAPI."""
    get_settings()

    app = FastAPI(
        title="CertificationManager",
        description="Gestionnaire de certificats cryptographiques",
        version=get_version(),
        lifespan=lifespan,
    )

    settings = get_settings()

    if settings.cors_origins:
        origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    app.add_middleware(IdempotencyMiddleware)
    app.add_middleware(
        RateLimitMiddleware,
        requests_per_minute=settings.rate_limit_per_minute,
    )
    app.add_middleware(CsrfMiddleware)

    base_dir = Path(__file__).parent
    static_dir = base_dir / "static"
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    app.include_router(pages.router)
    for router, tag in API_ROUTERS:
        app.include_router(router, prefix="/api", tags=[tag])
        app.include_router(router, prefix="/api/v1", tags=[f"v1-{tag}"])

    return app

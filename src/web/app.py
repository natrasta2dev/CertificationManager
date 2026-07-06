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
from .routers import (
    alerts,
    app_config,
    audit,
    auth,
    automation,
    backup,
    ca,
    certificates,
    client_certificates,
    compliance,
    csr,
    letsencrypt,
    metrics,
    pages,
    statistics,
)


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

    app.add_middleware(
        RateLimitMiddleware,
        requests_per_minute=settings.rate_limit_per_minute,
    )
    app.add_middleware(CsrfMiddleware)

    base_dir = Path(__file__).parent
    static_dir = base_dir / "static"
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    app.include_router(pages.router)
    app.include_router(auth.router, prefix="/api", tags=["auth"])
    app.include_router(audit.router, prefix="/api", tags=["audit"])
    app.include_router(statistics.router, prefix="/api", tags=["statistics"])
    app.include_router(alerts.router, prefix="/api", tags=["alerts"])
    app.include_router(certificates.router, prefix="/api", tags=["certificates"])
    app.include_router(csr.router, prefix="/api", tags=["csr"])
    app.include_router(ca.router, prefix="/api", tags=["ca"])
    app.include_router(letsencrypt.router, prefix="/api", tags=["letsencrypt"])
    app.include_router(client_certificates.router, prefix="/api", tags=["client-certificates"])
    app.include_router(backup.router, prefix="/api", tags=["backup"])
    app.include_router(automation.router, prefix="/api", tags=["automation"])
    app.include_router(compliance.router, prefix="/api", tags=["compliance"])
    app.include_router(app_config.router, prefix="/api", tags=["config"])
    app.include_router(metrics.router, prefix="/api", tags=["metrics"])

    return app

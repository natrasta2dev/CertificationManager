"""Chargement de la configuration via variables d'environnement."""

import os
import secrets
from functools import lru_cache

from dotenv import load_dotenv

load_dotenv()


class Settings:
    """Paramètres applicatifs."""

    def __init__(self) -> None:
        self.storage_path: str = os.getenv(
            "CERTMANAGER_STORAGE_PATH",
            os.path.expanduser("~/.certmanager"),
        )
        self.host: str = os.getenv("CERTMANAGER_HOST", "127.0.0.1")
        self.port: int = int(os.getenv("CERTMANAGER_PORT", "8000"))
        self.debug: bool = os.getenv("CERTMANAGER_DEBUG", "false").lower() in (
            "1",
            "true",
            "yes",
        )

        # Authentification
        self.auth_enabled: bool = os.getenv(
            "CERTMANAGER_AUTH_ENABLED", "false"
        ).lower() in ("1", "true", "yes")
        self.jwt_secret: str = os.getenv(
            "CERTMANAGER_JWT_SECRET",
            secrets.token_hex(32),
        )
        self.jwt_expire_minutes: int = int(
            os.getenv("CERTMANAGER_JWT_EXPIRE_MINUTES", "1440")
        )
        self.admin_password: str = os.getenv("CERTMANAGER_ADMIN_PASSWORD", "")

        # Sécurité
        self.rate_limit_enabled: bool = os.getenv(
            "CERTMANAGER_RATE_LIMIT_ENABLED", "true"
        ).lower() in ("1", "true", "yes")
        self.rate_limit_per_minute: int = int(
            os.getenv("CERTMANAGER_RATE_LIMIT_PER_MINUTE", "120")
        )
        self.max_upload_size_mb: int = int(
            os.getenv("CERTMANAGER_MAX_UPLOAD_SIZE_MB", "10")
        )
        self.cors_origins: str = os.getenv(
            "CERTMANAGER_CORS_ORIGINS",
            "http://127.0.0.1:8000,http://localhost:8000",
        )

        # Chiffrement des clés privées
        self.encrypt_keys: bool = os.getenv(
            "CERTMANAGER_ENCRYPT_KEYS", "false"
        ).lower() in ("1", "true", "yes")
        self.storage_password: str = os.getenv("CERTMANAGER_STORAGE_PASSWORD", "")

        # JWT refresh
        self.jwt_refresh_expire_days: int = int(
            os.getenv("CERTMANAGER_JWT_REFRESH_EXPIRE_DAYS", "7")
        )

        # Audit
        self.audit_retention_days: int = int(
            os.getenv("CERTMANAGER_AUDIT_RETENTION_DAYS", "90")
        )


@lru_cache
def get_settings() -> Settings:
    """Retourne les paramètres (mis en cache)."""
    return Settings()

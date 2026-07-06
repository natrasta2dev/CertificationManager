"""Authentification JWT et gestion des mots de passe."""

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import bcrypt
import jwt

from ..config import get_settings

ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    """Hash un mot de passe avec bcrypt."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Vérifie un mot de passe contre son hash."""
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def generate_csrf_token() -> str:
    """Génère un token CSRF."""
    return secrets.token_urlsafe(32)


def create_access_token(
    data: Dict[str, Any],
    expires_minutes: Optional[int] = None,
    csrf_token: Optional[str] = None,
) -> str:
    """Crée un token JWT d'accès."""
    settings = get_settings()
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=expires_minutes or settings.jwt_expire_minutes
    )
    payload = {**data, "type": "access", "exp": expire}
    if csrf_token:
        payload["csrf"] = csrf_token
    return jwt.encode(payload, settings.jwt_secret, algorithm=ALGORITHM)


def create_refresh_token(
    data: Dict[str, Any],
    expires_days: Optional[int] = None,
) -> str:
    """Crée un token JWT de rafraîchissement."""
    settings = get_settings()
    expire = datetime.now(timezone.utc) + timedelta(
        days=expires_days or settings.jwt_refresh_expire_days
    )
    payload = {**data, "type": "refresh", "exp": expire}
    return jwt.encode(payload, settings.jwt_secret, algorithm=ALGORITHM)


def decode_token(token: str) -> Dict[str, Any]:
    """Décode et valide un token JWT."""
    settings = get_settings()
    return jwt.decode(token, settings.jwt_secret, algorithms=[ALGORITHM])


def decode_access_token(token: str) -> Dict[str, Any]:
    """Décode un token d'accès."""
    payload = decode_token(token)
    if payload.get("type") == "refresh":
        raise jwt.InvalidTokenError("Token de rafraîchissement utilisé comme accès")
    return payload


def decode_refresh_token(token: str) -> Dict[str, Any]:
    """Décode un token de rafraîchissement."""
    payload = decode_token(token)
    if payload.get("type") != "refresh":
        raise jwt.InvalidTokenError("Token d'accès utilisé comme rafraîchissement")
    return payload

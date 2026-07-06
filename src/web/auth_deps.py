"""Dépendances d'authentification FastAPI."""

from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from ..config import get_settings
from ..core.auth import decode_access_token
from ..core.users import User, UserManager, UserRole

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)

# Utilisateur synthétique quand l'auth est désactivée (mode dev)
_GUEST_ADMIN = User(
    id="guest",
    username="guest",
    role=UserRole.ADMIN,
    created_at="",
)


def get_user_manager() -> UserManager:
    """Retourne le gestionnaire d'utilisateurs."""
    settings = get_settings()
    return UserManager(storage_path=settings.storage_path)


async def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    user_manager: UserManager = Depends(get_user_manager),
) -> User:
    """Retourne l'utilisateur courant ou lève 401."""
    settings = get_settings()
    if not settings.auth_enabled:
        return _GUEST_ADMIN

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentification requise",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_access_token(token)
        user = user_manager.get_by_id(payload.get("sub", ""))
        if not user:
            raise HTTPException(status_code=401, detail="Utilisateur invalide")
        return user
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Token invalide ou expiré")


def require_roles(*roles: UserRole):
    """Fabrique une dépendance qui exige un rôle."""

    async def _checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Permissions insuffisantes",
            )
        return user

    return _checker


RequireAdmin = require_roles(UserRole.ADMIN)
RequireOperator = require_roles(UserRole.ADMIN, UserRole.OPERATOR)
RequireViewer = require_roles(UserRole.ADMIN, UserRole.OPERATOR, UserRole.VIEWER)

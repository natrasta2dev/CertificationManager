"""Routes d'authentification."""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from pathlib import Path
from pydantic import BaseModel
from starlette.templating import Jinja2Templates

from ...config import get_settings
from ...core.auth import (
    create_access_token,
    create_refresh_token,
    decode_refresh_token,
    generate_csrf_token,
)
from ...core.users import User, UserManager, UserRole
from ..audit_hooks import audit_action
from ..auth_deps import RequireAdmin, get_current_user, get_user_manager

from ..template_utils import render_template

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


class RefreshRequest(BaseModel):
    refresh_token: str


class UserCreateRequest(BaseModel):
    username: str
    password: str
    role: str = "viewer"


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Page de connexion."""
    return render_template(templates, "login.html", {"request": request})


@router.post("/auth/login", response_class=JSONResponse)
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    user_manager: UserManager = Depends(get_user_manager),
):
    """Authentification et émission de tokens JWT."""
    settings = get_settings()
    if not settings.auth_enabled:
        raise HTTPException(status_code=400, detail="L'authentification est désactivée")

    user = user_manager.authenticate(form_data.username, form_data.password)
    if not user:
        audit_action(
            "auth.login_failed",
            None,
            request,
            details={"username": form_data.username},
            success=False,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Identifiants incorrects",
            headers={"WWW-Authenticate": "Bearer"},
        )

    csrf = generate_csrf_token()
    access_token = create_access_token(
        {"sub": user.id, "role": user.role.value},
        csrf_token=csrf,
    )
    refresh_token = create_refresh_token({"sub": user.id, "role": user.role.value})

    audit_action("auth.login", user, request, "user", user.id)

    return {
        "success": True,
        "data": {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "csrf_token": csrf,
            "token_type": "bearer",
            "expires_minutes": settings.jwt_expire_minutes,
            "user": user.to_dict(),
        },
    }


@router.post("/auth/refresh", response_class=JSONResponse)
async def refresh_token(body: RefreshRequest):
    """Rafraîchit le token d'accès."""
    settings = get_settings()
    if not settings.auth_enabled:
        raise HTTPException(status_code=400, detail="L'authentification est désactivée")

    try:
        payload = decode_refresh_token(body.refresh_token)
        user_manager = UserManager(storage_path=settings.storage_path)
        user = user_manager.get_by_id(payload.get("sub", ""))
        if not user:
            raise HTTPException(status_code=401, detail="Utilisateur invalide")

        csrf = generate_csrf_token()
        access_token = create_access_token(
            {"sub": user.id, "role": user.role.value},
            csrf_token=csrf,
        )
        new_refresh = create_refresh_token({"sub": user.id, "role": user.role.value})

        return {
            "success": True,
            "data": {
                "access_token": access_token,
                "refresh_token": new_refresh,
                "csrf_token": csrf,
                "token_type": "bearer",
            },
        }
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Refresh token invalide ou expiré")


@router.get("/auth/me", response_class=JSONResponse)
async def get_me(user: User = Depends(get_current_user)):
    """Retourne l'utilisateur connecté."""
    return {"success": True, "data": user.to_dict()}


@router.get("/auth/status", response_class=JSONResponse)
async def auth_status():
    """Indique si l'authentification est activée."""
    settings = get_settings()
    return {
        "success": True,
        "data": {
            "auth_enabled": settings.auth_enabled,
            "encrypt_keys": settings.encrypt_keys,
        },
    }


@router.get("/auth/users", response_class=JSONResponse)
async def list_users(
    _: User = Depends(RequireAdmin),
    user_manager: UserManager = Depends(get_user_manager),
):
    """Liste les utilisateurs (admin uniquement)."""
    return {"success": True, "data": user_manager.list_users()}


@router.post("/auth/users", response_class=JSONResponse)
async def create_user(
    body: UserCreateRequest,
    request: Request,
    admin: User = Depends(RequireAdmin),
    user_manager: UserManager = Depends(get_user_manager),
):
    """Crée un utilisateur (admin uniquement)."""
    try:
        role = UserRole(body.role)
        user = user_manager.create_user(body.username, body.password, role)
        audit_action(
            "user.create",
            admin,
            request,
            "user",
            user.id,
            {"username": body.username, "role": role.value},
        )
        return {"success": True, "data": user.to_dict()}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/auth/users/{user_id}", response_class=JSONResponse)
async def delete_user(
    user_id: str,
    request: Request,
    admin: User = Depends(RequireAdmin),
    user_manager: UserManager = Depends(get_user_manager),
):
    """Supprime un utilisateur (admin uniquement)."""
    if admin.id == user_id:
        raise HTTPException(status_code=400, detail="Impossible de supprimer votre propre compte")
    try:
        user_manager.delete_user(user_id)
        audit_action("user.delete", admin, request, "user", user_id)
        return {"success": True, "message": "Utilisateur supprimé"}
    except KeyError:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")

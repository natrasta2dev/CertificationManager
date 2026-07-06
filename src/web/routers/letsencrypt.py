"""Routes Let's Encrypt."""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse

from ...core.users import User
from ..auth_deps import RequireOperator, RequireViewer
from ..dependencies import get_managers
from ..schemas import LetsEncryptObtain

router = APIRouter()


@router.get("/letsencrypt", response_class=JSONResponse)
async def list_letsencrypt_certificates(_: User = Depends(RequireViewer)):
    """Liste tous les certificats Let's Encrypt."""
    managers = get_managers()
    try:
        certs = managers.letsencrypt_manager.list_letsencrypt_certificates()
        return {"success": True, "data": certs}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/letsencrypt/obtain", response_class=JSONResponse)
async def obtain_letsencrypt_certificate(
    request: LetsEncryptObtain,
    _: User = Depends(RequireOperator),
):
    """Obtient un certificat Let's Encrypt."""
    managers = get_managers()
    try:
        if not managers.letsencrypt_manager.check_certbot_available():
            raise HTTPException(
                status_code=503,
                detail="certbot n'est pas installé. Installez-le pour utiliser Let's Encrypt.",
            )

        cert_id = managers.letsencrypt_manager.obtain_certificate(
            domains=request.domains,
            email=request.email,
            staging=request.staging,
            webroot=request.webroot,
            standalone=request.standalone,
        )

        _, metadata = managers.storage.load_certificate(cert_id)

        return {
            "success": True,
            "data": {
                "id": cert_id,
                **metadata,
            },
        }
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/letsencrypt/{cert_id}/renew", response_class=JSONResponse)
async def renew_letsencrypt_certificate(cert_id: str, _: User = Depends(RequireOperator)):
    """Renouvelle un certificat Let's Encrypt."""
    managers = get_managers()
    try:
        if not managers.letsencrypt_manager.check_certbot_available():
            raise HTTPException(
                status_code=503,
                detail="certbot n'est pas installé",
            )

        new_cert_id = managers.letsencrypt_manager.renew_certificate(cert_id)

        return {
            "success": True,
            "data": {
                "old_cert_id": cert_id,
                "new_cert_id": new_cert_id,
            },
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/letsencrypt/renew-all", response_class=JSONResponse)
async def renew_all_letsencrypt_certificates(
    days: int = 30,
    _: User = Depends(RequireOperator),
):
    """Renouvelle tous les certificats Let's Encrypt expirant bientôt."""
    managers = get_managers()
    try:
        if not managers.letsencrypt_manager.check_certbot_available():
            raise HTTPException(
                status_code=503,
                detail="certbot n'est pas installé",
            )

        renewed = managers.letsencrypt_manager.renew_all_expiring(days_threshold=days)

        return {
            "success": True,
            "data": {
                "renewed_count": len(renewed),
                "renewed": [{"old_id": old, "new_id": new} for old, new in renewed],
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/letsencrypt/check-certbot", response_class=JSONResponse)
async def check_certbot_available(_: User = Depends(RequireViewer)):
    """Vérifie si certbot est disponible."""
    managers = get_managers()
    try:
        available = managers.letsencrypt_manager.check_certbot_available()
        return {
            "success": True,
            "data": {
                "available": available,
                "message": "certbot est installé" if available else "certbot n'est pas installé",
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

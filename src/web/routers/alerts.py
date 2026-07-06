"""Routes alertes."""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse

from ...core.users import User
from ..auth_deps import RequireViewer
from ..dependencies import get_managers

router = APIRouter()


@router.get("/alerts", response_class=JSONResponse)
async def get_alerts(include_expired: bool = True, _: User = Depends(RequireViewer)):
    """Récupère toutes les alertes."""
    managers = get_managers()
    try:
        alerts = managers.alert_manager.check_certificates(include_expired=include_expired)
        return {"success": True, "data": [alert.to_dict() for alert in alerts]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/alerts/{cert_id}", response_class=JSONResponse)
async def get_certificate_alerts(cert_id: str, _: User = Depends(RequireViewer)):
    """Récupère les alertes pour un certificat spécifique."""
    managers = get_managers()
    try:
        alerts = managers.alert_manager.get_alerts_for_certificate(cert_id)
        return {"success": True, "data": [alert.to_dict() for alert in alerts]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

"""Routes statistiques."""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse

from ...core.users import User
from ..auth_deps import RequireViewer
from ..dependencies import get_managers

router = APIRouter()


@router.get("/statistics", response_class=JSONResponse)
async def get_statistics(_: User = Depends(RequireViewer)):
    """Récupère les statistiques globales."""
    managers = get_managers()
    try:
        stats = managers.lifecycle.get_statistics()
        return {"success": True, "data": stats}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

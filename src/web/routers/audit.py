"""Routes journal d'audit."""

from typing import Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse, PlainTextResponse

from ...core.users import User
from ..audit_hooks import get_audit_logger
from ..auth_deps import RequireAdmin, RequireViewer

router = APIRouter()


@router.get("/audit", response_class=JSONResponse)
async def list_audit_logs(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    action: Optional[str] = None,
    username: Optional[str] = None,
    _: User = Depends(RequireViewer),
):
    """Liste les entrées du journal d'audit."""
    logger = get_audit_logger()
    logs = logger.list_logs(limit=limit, offset=offset, action=action, username=username)
    return {"success": True, "data": logs}


@router.get("/audit/export", response_class=PlainTextResponse)
async def export_audit_logs(
    format: str = Query("json", pattern="^(json|csv)$"),
    limit: int = Query(1000, ge=1, le=10000),
    _: User = Depends(RequireAdmin),
):
    """Exporte le journal d'audit."""
    logger = get_audit_logger()
    if format == "csv":
        content = logger.export_csv(limit=limit)
        return PlainTextResponse(content, media_type="text/csv")
    return PlainTextResponse(logger.export_json(limit=limit), media_type="application/json")


@router.post("/audit/rotate", response_class=JSONResponse)
async def rotate_audit_logs(_: User = Depends(RequireAdmin)):
    """Purge les entrées d'audit expirées."""
    logger = get_audit_logger()
    removed = logger.rotate()
    return {"success": True, "data": {"removed": removed}}

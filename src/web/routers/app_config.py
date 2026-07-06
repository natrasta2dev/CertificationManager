"""Routes configuration applicative."""

import json
import tempfile
from pathlib import Path
from typing import Dict

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ...core.app_config import (
    export_app_config,
    get_app_config_summary,
    import_app_config,
    load_alert_thresholds,
    save_alert_thresholds,
)
from ...core.alerts import AlertLevel
from ...core.users import User
from ..auth_deps import RequireAdmin, RequireViewer
from ..dependencies import get_managers

router = APIRouter()


class AlertThresholdsUpdate(BaseModel):
    thresholds: Dict[str, str] = Field(
        ...,
        description="Seuils {jours: niveau} ex. {'7': 'critical', '30': 'warning'}",
    )


@router.get("/config", response_class=JSONResponse)
async def get_config(_: User = Depends(RequireViewer)):
    """Résumé de la configuration."""
    managers = get_managers()
    return {
        "success": True,
        "data": get_app_config_summary(str(managers.storage.storage_path)),
    }


@router.put("/config/alerts", response_class=JSONResponse)
async def update_alert_thresholds(
    body: AlertThresholdsUpdate,
    _: User = Depends(RequireAdmin),
):
    """Met à jour les seuils d'alerte."""
    managers = get_managers()
    try:
        thresholds = {
            int(days): AlertLevel(level)
            for days, level in body.thresholds.items()
        }
        save_alert_thresholds(str(managers.storage.storage_path), thresholds)
        get_managers.cache_clear()
        return {"success": True, "data": body.thresholds}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/config/export", response_class=JSONResponse)
async def export_config(_: User = Depends(RequireAdmin)):
    """Exporte la configuration en JSON (réponse inline)."""
    managers = get_managers()
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        tmp_path = tmp.name
    try:
        result = export_app_config(str(managers.storage.storage_path), tmp_path)
        content = json.loads(Path(tmp_path).read_text(encoding="utf-8"))
        return {"success": True, "data": content, "meta": result}
    finally:
        Path(tmp_path).unlink(missing_ok=True)


@router.post("/config/import", response_class=JSONResponse)
async def import_config(file: UploadFile = File(...), _: User = Depends(RequireAdmin)):
    """Importe une configuration depuis un fichier JSON."""
    managers = get_managers()
    data = await file.read()
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        tmp.write(data)
        tmp_path = tmp.name
    try:
        result = import_app_config(str(managers.storage.storage_path), tmp_path)
        get_managers.cache_clear()
        return {"success": True, "data": result}
    except (json.JSONDecodeError, OSError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        Path(tmp_path).unlink(missing_ok=True)

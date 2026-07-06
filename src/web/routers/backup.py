"""Routes backup/restore."""

import os
import tempfile
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from ...core.backup import BackupManager
from ...core.users import User
from ..auth_deps import RequireOperator
from ..dependencies import get_managers

router = APIRouter()


class BackupCreate(BaseModel):
    password: Optional[str] = None


@router.post("/backup", response_class=JSONResponse)
async def create_backup(
    body: BackupCreate,
    _: User = Depends(RequireOperator),
):
    """Crée une sauvegarde et retourne le chemin temporaire pour téléchargement."""
    managers = get_managers()
    try:
        suffix = ".enc" if body.password else ".tar.gz"
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
        tmp.close()
        backup = BackupManager(str(managers.storage.storage_path))
        meta = backup.create_backup(tmp.name, password=body.password)
        return {
            "success": True,
            "data": {
                **meta,
                "download_token": os.path.basename(tmp.name),
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/restore", response_class=JSONResponse)
async def restore_backup(
    archive: UploadFile = File(...),
    password: Optional[str] = None,
    overwrite: bool = False,
    _: User = Depends(RequireOperator),
):
    """Restaure une sauvegarde."""
    managers = get_managers()
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".backup") as tmp:
            content = await archive.read()
            tmp.write(content)
            tmp_path = tmp.name

        try:
            backup = BackupManager(str(managers.storage.storage_path))
            result = backup.restore_backup(
                tmp_path,
                password=password,
                overwrite=overwrite,
            )
            get_managers.cache_clear()
            return {"success": True, "data": result}
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

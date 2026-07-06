"""Endpoints bulk officiels."""

from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ...core.users import User
from ..audit_hooks import audit_action
from ..auth_deps import RequireOperator
from ..dependencies import get_managers
from ..webhook_hooks import emit_webhook

router = APIRouter()


class BulkIdsRequest(BaseModel):
    cert_ids: List[str] = Field(..., min_length=1, description="IDs des certificats")


class BulkRenewRequest(BaseModel):
    cert_ids: List[str] = Field(..., min_length=1)
    days: int = Field(30, ge=1, le=3650)


@router.post("/certificates/bulk-delete", response_class=JSONResponse)
async def bulk_delete_certificates(
    body: BulkIdsRequest,
    request: Request,
    user: User = Depends(RequireOperator),
):
    """Supprime plusieurs certificats."""
    managers = get_managers()
    deleted = []
    errors = []
    for cert_id in body.cert_ids:
        try:
            _, meta = managers.storage.load_certificate(cert_id)
            managers.storage.delete_certificate(cert_id)
            audit_action("certificate.delete", user, request, "certificate", cert_id)
            emit_webhook(
                "certificate.deleted",
                {"id": cert_id, "common_name": meta.get("common_name")},
                str(managers.storage.storage_path),
            )
            deleted.append(cert_id)
        except FileNotFoundError:
            errors.append({"cert_id": cert_id, "error": "introuvable"})
        except Exception as e:
            errors.append({"cert_id": cert_id, "error": str(e)})
    return {
        "success": len(errors) == 0,
        "data": {"deleted": deleted, "errors": errors},
    }


@router.post("/certificates/bulk-renew", response_class=JSONResponse)
async def bulk_renew_certificates(
    body: BulkRenewRequest,
    request: Request,
    user: User = Depends(RequireOperator),
):
    """Renouvelle plusieurs certificats."""
    managers = get_managers()
    renewed = []
    errors = []
    for cert_id in body.cert_ids:
        try:
            new_id, _ = managers.renewal.renew_certificate(cert_id)
            audit_action(
                "certificate.renew",
                user,
                request,
                "certificate",
                new_id,
                {"old_cert_id": cert_id},
            )
            emit_webhook(
                "certificate.renewed",
                {"old_id": cert_id, "new_id": new_id},
                str(managers.storage.storage_path),
            )
            renewed.append({"old_id": cert_id, "new_id": new_id})
        except Exception as e:
            errors.append({"cert_id": cert_id, "error": str(e)})
    return {
        "success": len(errors) == 0,
        "data": {"renewed": renewed, "errors": errors},
    }

"""Routes certificats."""

import math
import os
import tempfile
from typing import List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse

from ...config import get_settings
from ...core.users import User
from ..audit_hooks import audit_action
from ..auth_deps import RequireOperator, RequireViewer
from ..dependencies import get_managers
from ..export_utils import encode_file_payload, encode_named_file
from ..schemas import CertificateCreate
from ..webhook_hooks import emit_webhook

router = APIRouter()


def _filter_and_sort_certificates(
    certificates: List[dict],
    status: Optional[str] = None,
    search: Optional[str] = None,
    sort: str = "common_name",
    order: str = "asc",
) -> List[dict]:
    """Filtre et trie une liste de certificats."""
    result = certificates

    if status == "valid":
        result = [c for c in result if not c.get("is_expired") and (c.get("days_until_expiry") or 0) > 30]
    elif status == "expiring":
        result = [
            c for c in result
            if not c.get("is_expired") and 0 < (c.get("days_until_expiry") or 0) <= 30
        ]
    elif status == "critical":
        result = [
            c for c in result
            if not c.get("is_expired") and 0 < (c.get("days_until_expiry") or 0) <= 7
        ]
    elif status == "expired":
        result = [c for c in result if c.get("is_expired")]

    if search:
        q = search.lower()
        result = [
            c for c in result
            if q in (c.get("common_name") or "").lower()
            or q in (c.get("organization") or "").lower()
            or q in (c.get("id") or "").lower()
        ]

    reverse = order.lower() == "desc"

    def sort_key(c: dict):
        if sort == "expires_at":
            return c.get("not_valid_after") or ""
        if sort == "status":
            return c.get("days_until_expiry") if not c.get("is_expired") else -1
        if sort == "key_type":
            return c.get("key_type") or ""
        return (c.get("common_name") or "").lower()

    return sorted(result, key=sort_key, reverse=reverse)


@router.get("/certificates", response_class=JSONResponse)
async def list_certificates(
    page: int = 1,
    limit: int = 50,
    sort: str = "common_name",
    order: str = "asc",
    status: Optional[str] = None,
    search: Optional[str] = None,
    _: User = Depends(RequireViewer),
):
    """Liste les certificats avec pagination."""
    managers = get_managers()
    try:
        all_certs = managers.storage.list_certificates()
        filtered = _filter_and_sort_certificates(all_certs, status, search, sort, order)
        total = len(filtered)
        limit = max(1, min(limit, 200))
        page = max(1, page)
        start = (page - 1) * limit
        items = filtered[start : start + limit]
        pages = math.ceil(total / limit) if total else 1
        return {
            "success": True,
            "data": items,
            "pagination": {
                "page": page,
                "limit": limit,
                "total": total,
                "pages": pages,
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/archives", response_class=JSONResponse)
async def list_archives(_: User = Depends(RequireViewer)):
    """Liste les certificats archivés."""
    managers = get_managers()
    try:
        archives = managers.storage.list_archived_certificates()
        archives.sort(key=lambda x: x.get("archived_at", ""), reverse=True)
        return {"success": True, "data": archives}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/certificates/expiring", response_class=JSONResponse)
async def get_expiring_certificates(
    days: int = 30,
    include_expired: bool = False,
    _: User = Depends(RequireViewer),
):
    """Récupère les certificats expirant bientôt."""
    managers = get_managers()
    try:
        expiring = managers.lifecycle.get_expiring_certificates(
            days_threshold=days,
            include_expired=include_expired,
        )
        return {"success": True, "data": expiring}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/certificates", response_class=JSONResponse)
async def create_certificate(
    cert_data: CertificateCreate,
    request: Request,
    user: User = Depends(RequireOperator),
):
    """Crée un nouveau certificat."""
    managers = get_managers()
    try:
        cert, private_key, metadata = managers.cert_manager.generate_self_signed_cert(
            common_name=cert_data.common_name,
            key_type=cert_data.key_type,
            key_size=cert_data.key_size,
            validity_days=cert_data.validity_days,
            country=cert_data.country,
            state=cert_data.state,
            locality=cert_data.locality,
            organization=cert_data.organization,
            organizational_unit=cert_data.organizational_unit,
            email=cert_data.email,
            san_dns=cert_data.san_dns,
            san_ip=cert_data.san_ip,
        )

        cert_id = managers.storage.save_certificate(cert, private_key, metadata)
        audit_action(
            "certificate.create",
            user,
            request,
            "certificate",
            cert_id,
            {"common_name": cert_data.common_name},
        )
        emit_webhook(
            "certificate.created",
            {"id": cert_id, **metadata},
            str(managers.storage.storage_path),
        )
        return {"success": True, "data": {"id": cert_id, **metadata}}
    except Exception as e:
        audit_action(
            "certificate.create",
            user,
            request,
            success=False,
            details={"error": str(e)},
        )
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/certificates/{cert_id}/verify", response_class=JSONResponse)
async def verify_certificate(cert_id: str, _: User = Depends(RequireViewer)):
    """Vérifie un certificat."""
    managers = get_managers()
    try:
        cert, _ = managers.storage.load_certificate(cert_id)
        is_valid, errors = managers.validator.validate_certificate(cert)
        return {"success": True, "data": {"valid": is_valid, "errors": errors}}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/certificates/status/{cert_id}", response_class=JSONResponse)
async def get_certificate_status(cert_id: str, _: User = Depends(RequireViewer)):
    """Récupère le statut détaillé d'un certificat."""
    managers = get_managers()
    try:
        status = managers.lifecycle.get_certificate_status(cert_id)
        return {"success": True, "data": status}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/certificates/{cert_id}", response_class=JSONResponse)
async def get_certificate(cert_id: str, _: User = Depends(RequireViewer)):
    """Récupère les détails d'un certificat."""
    managers = get_managers()
    try:
        cert, metadata = managers.storage.load_certificate(cert_id)
        info = managers.validator.get_certificate_info(cert)
        return {"success": True, "data": {**metadata, **info}}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Certificat non trouvé")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/certificates/{cert_id}", response_class=JSONResponse)
async def delete_certificate(
    cert_id: str,
    request: Request,
    user: User = Depends(RequireOperator),
):
    """Supprime un certificat."""
    managers = get_managers()
    try:
        _, meta = managers.storage.load_certificate(cert_id)
        managers.storage.delete_certificate(cert_id)
        audit_action("certificate.delete", user, request, "certificate", cert_id)
        emit_webhook(
            "certificate.deleted",
            {"id": cert_id, "common_name": meta.get("common_name")},
            str(managers.storage.storage_path),
        )
        return {"success": True, "message": "Certificat supprimé"}
    except Exception as e:
        audit_action("certificate.delete", user, request, "certificate", cert_id, success=False)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/certificates/{cert_id}/renew", response_class=JSONResponse)
async def renew_certificate(
    cert_id: str,
    request: Request,
    validity_days: Optional[int] = None,
    user: User = Depends(RequireOperator),
):
    """Renouvelle un certificat."""
    managers = get_managers()
    try:
        can_renew, error_msg = managers.renewal.can_renew(cert_id)
        if not can_renew:
            raise HTTPException(status_code=400, detail=error_msg)

        new_cert_id, new_metadata = managers.renewal.renew_certificate(
            cert_id,
            validity_days=validity_days,
            archive_old=True,
        )

        audit_action(
            "certificate.renew",
            user,
            request,
            "certificate",
            new_cert_id,
            {"old_cert_id": cert_id},
        )
        emit_webhook(
            "certificate.renewed",
            {"old_id": cert_id, "new_id": new_cert_id, **new_metadata},
            str(managers.storage.storage_path),
        )
        return {
            "success": True,
            "data": {
                "old_cert_id": cert_id,
                "new_cert_id": new_cert_id,
                **new_metadata,
            },
        }
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Certificat non trouvé")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        audit_action("certificate.renew", user, request, "certificate", cert_id, success=False)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/certificates/{cert_id}/export", response_class=JSONResponse)
async def export_certificate(
    cert_id: str,
    request: Request,
    format: str = "pem",
    include_key: bool = False,
    password: Optional[str] = None,
    user: User = Depends(RequireOperator),
):
    """Exporte un certificat."""
    managers = get_managers()

    def _respond(data):
        audit_action(
            "certificate.export",
            user,
            request,
            "certificate",
            cert_id,
            {"format": format, "include_key": include_key},
        )
        return {"success": True, "data": data}

    try:
        password_bytes = password.encode("utf-8") if password else None

        with tempfile.NamedTemporaryFile(delete=False, suffix=f".{format}") as tmp_file:
            tmp_path = tmp_file.name

        if format.lower() in ["p12", "pfx"]:
            output_path = managers.exporter.export_to_pkcs12(
                cert_id,
                tmp_path,
                password=password_bytes,
            )
            with open(output_path, "rb") as f:
                file_data = f.read()
            os.unlink(output_path)

            return _respond(
                encode_file_payload(
                    file_data,
                    f"{cert_id}.p12",
                    "application/x-pkcs12",
                    "pkcs12",
                )
            )

        if format.lower() == "der":
            cert_path, key_path = managers.exporter.export_to_der(
                cert_id,
                tmp_path,
                include_key=include_key,
                key_password=password_bytes,
            )
            with open(cert_path, "rb") as f:
                cert_data = f.read()
            os.unlink(cert_path)

            result = {
                "format": "der",
                "certificate": encode_named_file(
                    cert_data,
                    f"{cert_id}.der",
                    "application/x-x509-ca-cert",
                ),
            }

            if key_path:
                with open(key_path, "rb") as f:
                    key_data = f.read()
                os.unlink(key_path)
                result["private_key"] = encode_named_file(
                    key_data,
                    f"{cert_id}.key",
                    "application/x-pem-file",
                )
                result["file_data"] = result["certificate"]["file_data"]

            return _respond(result)

        cert_path, key_path = managers.exporter.export_to_pem(
            cert_id,
            tmp_path,
            include_key=include_key,
            key_password=password_bytes,
        )
        with open(cert_path, "rb") as f:
            cert_data = f.read()
        os.unlink(cert_path)

        result = {
            "format": "pem",
            "certificate": encode_named_file(
                cert_data,
                f"{cert_id}.pem",
                "application/x-pem-file",
            ),
        }

        key_data = b""
        if key_path:
            with open(key_path, "rb") as f:
                key_data = f.read()
            os.unlink(key_path)
            result["private_key"] = encode_named_file(
                key_data,
                f"{cert_id}.key",
                "application/x-pem-file",
            )

        combined = cert_data + key_data
        result["file_data"] = encode_file_payload(
            combined,
            f"{cert_id}.pem",
            "application/x-pem-file",
            "pem",
        )["file_data"]

        return _respond(result)

    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Certificat non trouvé")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/certificates/import", response_class=JSONResponse)
async def import_certificate(
    request: Request,
    cert_file: UploadFile = File(...),
    key_file: Optional[UploadFile] = None,
    format: str = "pem",
    password: Optional[str] = None,
    validate: bool = True,
    user: User = Depends(RequireOperator),
):
    """Importe un certificat depuis un fichier."""
    managers = get_managers()
    settings = get_settings()
    max_size = settings.max_upload_size_mb * 1024 * 1024
    try:
        password_bytes = password.encode("utf-8") if password else None

        with tempfile.NamedTemporaryFile(delete=False, suffix=f".{format}") as tmp_cert:
            cert_content = await cert_file.read()
            if len(cert_content) > max_size:
                raise HTTPException(status_code=413, detail="Fichier trop volumineux")
            tmp_cert.write(cert_content)
            tmp_cert_path = tmp_cert.name

        tmp_key_path = None
        if key_file:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".key") as tmp_key:
                key_content = await key_file.read()
                tmp_key.write(key_content)
                tmp_key_path = tmp_key.name

        try:
            if format.lower() in ["p12", "pfx"]:
                cert_id = managers.importer.import_from_pkcs12(
                    tmp_cert_path,
                    password=password_bytes,
                    validate=validate,
                )
            elif format.lower() == "der":
                cert_id = managers.importer.import_from_der(
                    tmp_cert_path,
                    key_path=tmp_key_path,
                    password=password_bytes,
                    validate=validate,
                )
            else:
                cert_id = managers.importer.import_from_pem(
                    tmp_cert_path,
                    key_path=tmp_key_path,
                    password=password_bytes,
                    validate=validate,
                )

            audit_action("certificate.import", user, request, "certificate", cert_id, {"format": format})
            return {
                "success": True,
                "data": {
                    "id": cert_id,
                    "message": "Certificat importé avec succès",
                },
            }
        finally:
            if os.path.exists(tmp_cert_path):
                os.unlink(tmp_cert_path)
            if tmp_key_path and os.path.exists(tmp_key_path):
                os.unlink(tmp_key_path)

    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/certificates/{cert_id}/verify-chain", response_class=JSONResponse)
async def verify_certificate_chain(
    cert_id: str,
    ca_ids: Optional[List[str]] = None,
    _: User = Depends(RequireViewer),
):
    """Vérifie la chaîne de certificats d'un certificat."""
    managers = get_managers()
    try:
        cert, _ = managers.storage.load_certificate(cert_id)
        is_valid, errors = managers.ca_manager.verify_certificate_chain(
            cert, ca_cert_ids=ca_ids
        )

        return {
            "success": True,
            "data": {
                "valid": is_valid,
                "errors": errors,
            },
        }
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Certificat non trouvé")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

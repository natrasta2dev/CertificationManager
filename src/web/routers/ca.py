"""Routes gestion des CA."""

import os
import tempfile
from typing import List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from cryptography.hazmat.primitives import serialization

from ...core.users import User
from ..auth_deps import RequireOperator, RequireViewer
from ..dependencies import get_managers
from ..schemas import CAGenerate, CASignCSR, CASignServer

router = APIRouter()


@router.get("/ca", response_class=JSONResponse)
async def list_ca_certificates(_: User = Depends(RequireViewer)):
    """Liste toutes les CA stockées."""
    managers = get_managers()
    try:
        cas = managers.ca_manager.list_ca_certificates()
        return {"success": True, "data": cas}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/ca/{ca_id}", response_class=JSONResponse)
async def get_ca_certificate(ca_id: str, _: User = Depends(RequireViewer)):
    """Récupère une CA."""
    managers = get_managers()
    try:
        cert, metadata = managers.ca_manager.get_ca_certificate(ca_id)
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        return {
            "success": True,
            "data": {
                **metadata,
                "certificate_pem": cert_pem,
            },
        }
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="CA non trouvée")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/ca/generate", response_class=JSONResponse)
async def generate_ca_certificate(
    body: CAGenerate,
    _: User = Depends(RequireOperator),
):
    """Génère une CA racine ou intermédiaire."""
    managers = get_managers()
    try:
        ca_id = managers.ca_manager.generate_ca(
            common_name=body.common_name,
            name=body.name,
            is_root=body.is_root,
            parent_ca_id=body.parent_ca_id,
            key_type=body.key_type,
            key_size=body.key_size,
            validity_days=body.validity_days,
            country=body.country,
            state=body.state,
            locality=body.locality,
            organization=body.organization,
            organizational_unit=body.organizational_unit,
            email=body.email,
        )
        _, metadata = managers.ca_manager.get_ca_certificate(ca_id)
        return {"success": True, "data": {"id": ca_id, **metadata}}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/ca/{ca_id}/sign-csr", response_class=JSONResponse)
async def sign_csr_with_ca(
    ca_id: str,
    body: CASignCSR,
    _: User = Depends(RequireOperator),
):
    """Signe une CSR stockée avec une CA locale."""
    managers = get_managers()
    try:
        cert_id = managers.ca_manager.sign_csr_from_storage(
            ca_id, body.csr_id, body.validity_days
        )
        _, metadata = managers.storage.load_certificate(cert_id)
        return {"success": True, "data": {"id": cert_id, **metadata}}
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/ca/{ca_id}/sign", response_class=JSONResponse)
async def sign_server_with_ca(
    ca_id: str,
    body: CASignServer,
    _: User = Depends(RequireOperator),
):
    """Génère un certificat serveur signé par une CA locale."""
    managers = get_managers()
    try:
        cert_id = managers.ca_manager.sign_server_certificate(
            ca_id=ca_id,
            common_name=body.common_name,
            validity_days=body.validity_days,
            key_type=body.key_type,
            key_size=body.key_size,
            country=body.country,
            state=body.state,
            locality=body.locality,
            organization=body.organization,
            organizational_unit=body.organizational_unit,
            email=body.email,
            san_dns=body.san_dns,
            san_ip=body.san_ip,
        )
        _, metadata = managers.storage.load_certificate(cert_id)
        return {"success": True, "data": {"id": cert_id, **metadata}}
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/ca/import", response_class=JSONResponse)
async def import_ca_certificate(
    ca_file: UploadFile = File(...),
    name: Optional[str] = None,
    is_root: bool = True,
    is_trusted: bool = True,
    _: User = Depends(RequireOperator),
):
    """Importe une CA depuis un fichier."""
    managers = get_managers()
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as tmp_file:
            file_content = await ca_file.read()
            tmp_file.write(file_content)
            tmp_path = tmp_file.name

        try:
            ca_id = managers.ca_manager.import_ca_from_file(
                tmp_path,
                name=name,
                is_root=is_root,
                is_trusted=is_trusted,
            )

            _, metadata = managers.ca_manager.get_ca_certificate(ca_id)

            return {
                "success": True,
                "data": {
                    "id": ca_id,
                    **metadata,
                },
            }
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/ca/{ca_id}", response_class=JSONResponse)
async def delete_ca_certificate(ca_id: str, _: User = Depends(RequireOperator)):
    """Supprime une CA."""
    managers = get_managers()
    try:
        managers.ca_manager.delete_ca_certificate(ca_id)
        return {"success": True, "message": "CA supprimée"}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="CA non trouvée")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

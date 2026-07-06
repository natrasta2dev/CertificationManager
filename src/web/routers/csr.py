"""Routes CSR."""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from cryptography.hazmat.primitives import serialization

from ...core.users import User
from ..auth_deps import RequireOperator, RequireViewer
from ..dependencies import get_managers
from ..schemas import CSRCreate

router = APIRouter()


@router.get("/csr", response_class=JSONResponse)
async def list_csrs(_: User = Depends(RequireViewer)):
    """Liste les CSR en attente."""
    managers = get_managers()
    try:
        csrs = managers.storage.list_csrs()
        return {"success": True, "data": csrs}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/csr/{csr_id}", response_class=JSONResponse)
async def get_csr(csr_id: str, _: User = Depends(RequireViewer)):
    """Récupère une CSR."""
    managers = get_managers()
    try:
        csr, metadata = managers.storage.load_csr(csr_id)
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        return {
            "success": True,
            "data": {**metadata, "id": csr_id, "csr_pem": csr_pem},
        }
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="CSR introuvable")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/csr", response_class=JSONResponse)
async def create_csr(csr_data: CSRCreate, _: User = Depends(RequireOperator)):
    """Crée une CSR."""
    managers = get_managers()
    try:
        csr, private_key, metadata = managers.cert_manager.generate_csr(
            common_name=csr_data.common_name,
            key_type=csr_data.key_type,
            key_size=csr_data.key_size,
            country=csr_data.country,
            state=csr_data.state,
            locality=csr_data.locality,
            organization=csr_data.organization,
            organizational_unit=csr_data.organizational_unit,
            email=csr_data.email,
            san_dns=csr_data.san_dns,
            san_ip=csr_data.san_ip,
        )

        csr_id = managers.storage.save_csr(csr, private_key, metadata)
        return {"success": True, "data": {"id": csr_id, **metadata}}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/csr/{csr_id}", response_class=JSONResponse)
async def delete_csr(csr_id: str, _: User = Depends(RequireOperator)):
    """Supprime une CSR."""
    managers = get_managers()
    try:
        managers.storage.delete_csr(csr_id)
        return {"success": True, "message": "CSR supprimée"}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="CSR introuvable")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

"""Routes certificats client."""

from typing import Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import JSONResponse

from ...core.users import User
from ..auth_deps import RequireOperator, RequireViewer
from ..dependencies import get_managers
from ..export_utils import encode_file_payload

router = APIRouter()


@router.get("/client-certificates", response_class=JSONResponse)
async def list_client_certificates(_: User = Depends(RequireViewer)):
    """Liste tous les certificats client."""
    managers = get_managers()
    try:
        certificates = managers.storage.list_certificates()
        client_certs = [c for c in certificates if c.get("certificate_type") == "client"]
        return {"success": True, "data": client_certs}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/client-certificates", response_class=JSONResponse)
async def create_client_certificate(
    common_name: str = Form(...),
    validity_days: int = Form(365),
    key_type: str = Form("RSA"),
    key_size: int = Form(2048),
    country: Optional[str] = Form(None),
    state: Optional[str] = Form(None),
    locality: Optional[str] = Form(None),
    organization: Optional[str] = Form(None),
    organizational_unit: Optional[str] = Form(None),
    email: Optional[str] = Form(None),
    ca_cert_file: Optional[UploadFile] = File(None),
    ca_key_file: Optional[UploadFile] = File(None),
    ca_password: Optional[str] = Form(None),
    _: User = Depends(RequireOperator),
):
    """Crée un nouveau certificat client."""
    managers = get_managers()
    try:
        ca_cert_obj = None
        ca_key_obj = None

        if ca_cert_file and ca_key_file:
            ca_cert_data = await ca_cert_file.read()
            ca_key_data = await ca_key_file.read()

            ca_cert_obj = x509.load_pem_x509_certificate(ca_cert_data, default_backend())

            try:
                ca_key_obj = serialization.load_pem_private_key(
                    ca_key_data,
                    password=None,
                    backend=default_backend(),
                )
            except ValueError:
                if ca_password:
                    ca_key_obj = serialization.load_pem_private_key(
                        ca_key_data,
                        password=ca_password.encode("utf-8"),
                        backend=default_backend(),
                    )
                else:
                    raise HTTPException(
                        status_code=400,
                        detail="La clé CA est chiffrée, un mot de passe est requis",
                    )

        cert, private_key, metadata = managers.client_cert_manager.generate_client_cert(
            common_name=common_name,
            key_type=key_type,
            key_size=key_size,
            validity_days=validity_days,
            country=country,
            state=state,
            locality=locality,
            organization=organization,
            organizational_unit=organizational_unit,
            email=email,
            ca_cert=ca_cert_obj,
            ca_key=ca_key_obj,
        )

        cert_id = managers.storage.save_certificate(cert, private_key, metadata)
        return {"success": True, "data": {"id": cert_id, **metadata}}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/client-certificates/{cert_id}/export-browser", response_class=JSONResponse)
async def export_client_certificate_browser(
    cert_id: str,
    password: Optional[str] = None,
    _: User = Depends(RequireOperator),
):
    """Exporte un certificat client au format PKCS#12 pour navigateur."""
    managers = get_managers()
    try:
        cert, metadata = managers.storage.load_certificate(cert_id)
        private_key = managers.storage.load_private_key(cert_id)

        if metadata.get("certificate_type") != "client":
            raise HTTPException(status_code=400, detail="Ce n'est pas un certificat client")

        p12_data = managers.client_cert_manager.export_for_browser(
            cert,
            private_key,
            password=password,
        )

        return {
            "success": True,
            "data": encode_file_payload(
                p12_data,
                f"{cert_id}.p12",
                "application/x-pkcs12",
                "pkcs12",
            ),
        }
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Certificat non trouvé")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

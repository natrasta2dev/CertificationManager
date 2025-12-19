"""Application web FastAPI pour CertificationManager."""

import os
from pathlib import Path
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Request, File, UploadFile, Form, Form
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates
from pydantic import BaseModel
from cryptography import x509

from ..core import (
    CertificateManager,
    ClientCertificateManager,
    SecureStorage,
    CertificateValidator,
    CertificateLifecycle,
    AlertManager,
    CertificateRenewal,
    CertificateImporter,
    CertificateExporter,
    CAManager,
    LetsEncryptManager,
)


def create_app() -> FastAPI:
    """Crée et configure l'application FastAPI."""
    
    app = FastAPI(
        title="CertificationManager",
        description="Gestionnaire de certificats cryptographiques",
        version="0.1.0"
    )
    
    # Chemins
    base_dir = Path(__file__).parent
    static_dir = base_dir / "static"
    templates_dir = base_dir / "templates"
    
    # Monter les fichiers statiques
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    
    # Templates
    templates = Jinja2Templates(directory=str(templates_dir))
    
    # Instances des gestionnaires
    cert_manager = CertificateManager()
    client_cert_manager = ClientCertificateManager()
    storage = SecureStorage()
    validator = CertificateValidator()
    lifecycle = CertificateLifecycle(storage)
    alert_manager = AlertManager(lifecycle)
    renewal = CertificateRenewal(storage)
    importer = CertificateImporter(storage)
    exporter = CertificateExporter(storage)
    ca_manager = CAManager(storage)
    letsencrypt_manager = LetsEncryptManager(storage)
    
    # Modèles Pydantic
    class CertificateCreate(BaseModel):
        common_name: str
        validity_days: int = 365
        key_type: str = "RSA"
        key_size: int = 2048
        country: Optional[str] = None
        state: Optional[str] = None
        locality: Optional[str] = None
        organization: Optional[str] = None
        organizational_unit: Optional[str] = None
        email: Optional[str] = None
        san_dns: Optional[List[str]] = None
    
    class CSRCreate(BaseModel):
        common_name: str
        key_type: str = "RSA"
        key_size: int = 2048
        country: Optional[str] = None
        state: Optional[str] = None
        locality: Optional[str] = None
        organization: Optional[str] = None
        organizational_unit: Optional[str] = None
        email: Optional[str] = None
        san_dns: Optional[List[str]] = None
    
    # Routes
    @app.get("/", response_class=HTMLResponse)
    async def root(request: Request):
        """Page d'accueil."""
        return templates.TemplateResponse("index.html", {"request": request})
    
    # Routes API - Statistiques et alertes (avant les routes avec paramètres)
    @app.get("/api/statistics", response_class=JSONResponse)
    async def get_statistics():
        """Récupère les statistiques globales."""
        try:
            stats = lifecycle.get_statistics()
            return {"success": True, "data": stats}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/api/alerts", response_class=JSONResponse)
    async def get_alerts(include_expired: bool = True):
        """Récupère toutes les alertes."""
        try:
            alerts = alert_manager.check_certificates(include_expired=include_expired)
            return {"success": True, "data": [alert.to_dict() for alert in alerts]}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    # Routes API - Certificats (routes spécifiques avant routes avec paramètres)
    @app.get("/api/certificates", response_class=JSONResponse)
    async def list_certificates():
        """Liste tous les certificats."""
        try:
            certificates = storage.list_certificates()
            return {"success": True, "data": certificates}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/api/certificates/expiring", response_class=JSONResponse)
    async def get_expiring_certificates(days: int = 30, include_expired: bool = False):
        """Récupère les certificats expirant bientôt."""
        try:
            expiring = lifecycle.get_expiring_certificates(
                days_threshold=days,
                include_expired=include_expired
            )
            return {"success": True, "data": expiring}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/certificates", response_class=JSONResponse)
    async def create_certificate(cert_data: CertificateCreate):
        """Crée un nouveau certificat."""
        try:
            cert, private_key, metadata = cert_manager.generate_self_signed_cert(
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
            )
            
            cert_id = storage.save_certificate(cert, private_key, metadata)
            return {"success": True, "data": {"id": cert_id, **metadata}}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))
    
    @app.get("/api/certificates/{cert_id}/verify", response_class=JSONResponse)
    async def verify_certificate(cert_id: str):
        """Vérifie un certificat."""
        try:
            cert, _ = storage.load_certificate(cert_id)
            is_valid, errors = validator.validate_certificate(cert)
            return {"success": True, "data": {"valid": is_valid, "errors": errors}}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/api/certificates/status/{cert_id}", response_class=JSONResponse)
    async def get_certificate_status(cert_id: str):
        """Récupère le statut détaillé d'un certificat."""
        try:
            status = lifecycle.get_certificate_status(cert_id)
            return {"success": True, "data": status}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/api/certificates/{cert_id}", response_class=JSONResponse)
    async def get_certificate(cert_id: str):
        """Récupère les détails d'un certificat."""
        try:
            cert, metadata = storage.load_certificate(cert_id)
            info = validator.get_certificate_info(cert)
            return {"success": True, "data": {**metadata, **info}}
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="Certificat non trouvé")
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.delete("/api/certificates/{cert_id}", response_class=JSONResponse)
    async def delete_certificate(cert_id: str):
        """Supprime un certificat."""
        try:
            storage.delete_certificate(cert_id)
            return {"success": True, "message": "Certificat supprimé"}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    # Routes API - CSR
    @app.post("/api/csr", response_class=JSONResponse)
    async def create_csr(csr_data: CSRCreate):
        """Crée une CSR."""
        try:
            csr, private_key, metadata = cert_manager.generate_csr(
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
            )
            
            csr_id = storage.save_csr(csr, private_key, metadata)
            return {"success": True, "data": {"id": csr_id, **metadata}}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))
    
    # Routes API - Alertes par certificat
    @app.get("/api/alerts/{cert_id}", response_class=JSONResponse)
    async def get_certificate_alerts(cert_id: str):
        """Récupère les alertes pour un certificat spécifique."""
        try:
            alerts = alert_manager.get_alerts_for_certificate(cert_id)
            return {"success": True, "data": [alert.to_dict() for alert in alerts]}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/certificates/{cert_id}/renew", response_class=JSONResponse)
    async def renew_certificate(cert_id: str, validity_days: Optional[int] = None):
        """Renouvelle un certificat."""
        try:
            # Vérifier si le certificat peut être renouvelé
            can_renew, error_msg = renewal.can_renew(cert_id)
            if not can_renew:
                raise HTTPException(status_code=400, detail=error_msg)
            
            # Renouveler le certificat
            new_cert_id, new_metadata = renewal.renew_certificate(
                cert_id,
                validity_days=validity_days,
                archive_old=True
            )
            
            return {
                "success": True,
                "data": {
                    "old_cert_id": cert_id,
                    "new_cert_id": new_cert_id,
                    **new_metadata
                }
            }
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="Certificat non trouvé")
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/certificates/{cert_id}/export", response_class=JSONResponse)
    async def export_certificate(
        cert_id: str,
        format: str = "pem",
        include_key: bool = False,
        password: Optional[str] = None
    ):
        """Exporte un certificat."""
        try:
            import tempfile
            import base64
            
            password_bytes = password.encode("utf-8") if password else None
            
            # Créer un fichier temporaire
            with tempfile.NamedTemporaryFile(delete=False, suffix=f".{format}") as tmp_file:
                tmp_path = tmp_file.name
            
            if format.lower() in ["p12", "pfx"]:
                output_path = exporter.export_to_pkcs12(
                    cert_id,
                    tmp_path,
                    password=password_bytes
                )
                # Lire le fichier et le convertir en base64
                with open(output_path, "rb") as f:
                    file_data = f.read()
                os.unlink(output_path)
                
                return {
                    "success": True,
                    "data": {
                        "format": "pkcs12",
                        "filename": f"{cert_id}.p12",
                        "content": base64.b64encode(file_data).decode("utf-8"),
                        "mime_type": "application/x-pkcs12"
                    }
                }
            elif format.lower() == "der":
                cert_path, key_path = exporter.export_to_der(
                    cert_id,
                    tmp_path,
                    include_key=include_key,
                    key_password=password_bytes
                )
                # Lire les fichiers
                with open(cert_path, "rb") as f:
                    cert_data = f.read()
                os.unlink(cert_path)
                
                result = {
                    "success": True,
                    "data": {
                        "format": "der",
                        "certificate": {
                            "filename": f"{cert_id}.der",
                            "content": base64.b64encode(cert_data).decode("utf-8"),
                            "mime_type": "application/x-x509-ca-cert"
                        }
                    }
                }
                
                if key_path:
                    with open(key_path, "rb") as f:
                        key_data = f.read()
                    os.unlink(key_path)
                    result["data"]["private_key"] = {
                        "filename": f"{cert_id}.key",
                        "content": base64.b64encode(key_data).decode("utf-8"),
                        "mime_type": "application/x-pem-file"
                    }
                
                return result
            else:  # PEM par défaut
                cert_path, key_path = exporter.export_to_pem(
                    cert_id,
                    tmp_path,
                    include_key=include_key,
                    key_password=password_bytes
                )
                # Lire les fichiers
                with open(cert_path, "rb") as f:
                    cert_data = f.read()
                os.unlink(cert_path)
                
                result = {
                    "success": True,
                    "data": {
                        "format": "pem",
                        "certificate": {
                            "filename": f"{cert_id}.pem",
                            "content": base64.b64encode(cert_data).decode("utf-8"),
                            "mime_type": "application/x-pem-file"
                        }
                    }
                }
                
                if key_path:
                    with open(key_path, "rb") as f:
                        key_data = f.read()
                    os.unlink(key_path)
                    result["data"]["private_key"] = {
                        "filename": f"{cert_id}.key",
                        "content": base64.b64encode(key_data).decode("utf-8"),
                        "mime_type": "application/x-pem-file"
                    }
                
                return result
                
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="Certificat non trouvé")
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/certificates/import", response_class=JSONResponse)
    async def import_certificate(
        cert_file: UploadFile = File(...),
        key_file: Optional[UploadFile] = None,
        format: str = "pem",
        password: Optional[str] = None,
        validate: bool = True
    ):
        """Importe un certificat depuis un fichier."""
        try:
            import tempfile
            import os
            
            password_bytes = password.encode("utf-8") if password else None
            
            # Sauvegarder le fichier certificat temporairement
            with tempfile.NamedTemporaryFile(delete=False, suffix=f".{format}") as tmp_cert:
                cert_content = await cert_file.read()
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
                    cert_id = importer.import_from_pkcs12(
                        tmp_cert_path,
                        password=password_bytes,
                        validate=validate
                    )
                elif format.lower() == "der":
                    cert_id = importer.import_from_der(
                        tmp_cert_path,
                        key_path=tmp_key_path,
                        password=password_bytes,
                        validate=validate
                    )
                else:  # PEM par défaut
                    cert_id = importer.import_from_pem(
                        tmp_cert_path,
                        key_path=tmp_key_path,
                        password=password_bytes,
                        validate=validate
                    )
                
                return {
                    "success": True,
                    "data": {
                        "id": cert_id,
                        "message": "Certificat importé avec succès"
                    }
                }
            finally:
                # Nettoyer les fichiers temporaires
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
    
    # Routes API - CA
    @app.get("/api/ca", response_class=JSONResponse)
    async def list_ca_certificates():
        """Liste toutes les CA stockées."""
        try:
            cas = ca_manager.list_ca_certificates()
            return {"success": True, "data": cas}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/api/ca/{ca_id}", response_class=JSONResponse)
    async def get_ca_certificate(ca_id: str):
        """Récupère une CA."""
        try:
            cert, metadata = ca_manager.get_ca_certificate(ca_id)
            from cryptography.hazmat.primitives import serialization
            cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
            return {
                "success": True,
                "data": {
                    **metadata,
                    "certificate_pem": cert_pem
                }
            }
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="CA non trouvée")
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/ca/import", response_class=JSONResponse)
    async def import_ca_certificate(
        ca_file: UploadFile = File(...),
        name: Optional[str] = None,
        is_root: bool = True,
        is_trusted: bool = True
    ):
        """Importe une CA depuis un fichier."""
        try:
            import tempfile
            import os
            
            # Sauvegarder le fichier temporairement
            with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as tmp_file:
                file_content = await ca_file.read()
                tmp_file.write(file_content)
                tmp_path = tmp_file.name
            
            try:
                ca_id = ca_manager.import_ca_from_file(
                    tmp_path,
                    name=name,
                    is_root=is_root,
                    is_trusted=is_trusted
                )
                
                ca_cert, metadata = ca_manager.get_ca_certificate(ca_id)
                
                return {
                    "success": True,
                    "data": {
                        "id": ca_id,
                        **metadata
                    }
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
    
    @app.delete("/api/ca/{ca_id}", response_class=JSONResponse)
    async def delete_ca_certificate(ca_id: str):
        """Supprime une CA."""
        try:
            ca_manager.delete_ca_certificate(ca_id)
            return {"success": True, "message": "CA supprimée"}
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="CA non trouvée")
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/certificates/{cert_id}/verify-chain", response_class=JSONResponse)
    async def verify_certificate_chain(
        cert_id: str,
        ca_ids: Optional[List[str]] = None
    ):
        """Vérifie la chaîne de certificats d'un certificat."""
        try:
            cert, _ = storage.load_certificate(cert_id)
            is_valid, errors = ca_manager.verify_certificate_chain(cert, ca_cert_ids=ca_ids)
            
            return {
                "success": True,
                "data": {
                    "valid": is_valid,
                    "errors": errors
                }
            }
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="Certificat non trouvé")
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    # Routes API - Let's Encrypt
    @app.get("/api/letsencrypt", response_class=JSONResponse)
    async def list_letsencrypt_certificates():
        """Liste tous les certificats Let's Encrypt."""
        try:
            certs = letsencrypt_manager.list_letsencrypt_certificates()
            return {"success": True, "data": certs}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/letsencrypt/obtain", response_class=JSONResponse)
    async def obtain_letsencrypt_certificate(
        domains: List[str],
        email: Optional[str] = None,
        staging: bool = False,
        webroot: Optional[str] = None,
        standalone: bool = True
    ):
        """Obtient un certificat Let's Encrypt."""
        try:
            if not letsencrypt_manager.check_certbot_available():
                raise HTTPException(
                    status_code=503,
                    detail="certbot n'est pas installé. Installez-le pour utiliser Let's Encrypt."
                )
            
            cert_id = letsencrypt_manager.obtain_certificate(
                domains=domains,
                email=email,
                staging=staging,
                webroot=webroot,
                standalone=standalone
            )
            
            cert, metadata = storage.load_certificate(cert_id)
            
            return {
                "success": True,
                "data": {
                    "id": cert_id,
                    **metadata
                }
            }
        except RuntimeError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/letsencrypt/{cert_id}/renew", response_class=JSONResponse)
    async def renew_letsencrypt_certificate(cert_id: str):
        """Renouvelle un certificat Let's Encrypt."""
        try:
            if not letsencrypt_manager.check_certbot_available():
                raise HTTPException(
                    status_code=503,
                    detail="certbot n'est pas installé"
                )
            
            new_cert_id = letsencrypt_manager.renew_certificate(cert_id)
            
            return {
                "success": True,
                "data": {
                    "old_cert_id": cert_id,
                    "new_cert_id": new_cert_id
                }
            }
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/letsencrypt/renew-all", response_class=JSONResponse)
    async def renew_all_letsencrypt_certificates(days: int = 30):
        """Renouvelle tous les certificats Let's Encrypt expirant bientôt."""
        try:
            if not letsencrypt_manager.check_certbot_available():
                raise HTTPException(
                    status_code=503,
                    detail="certbot n'est pas installé"
                )
            
            renewed = letsencrypt_manager.renew_all_expiring(days_threshold=days)
            
            return {
                "success": True,
                "data": {
                    "renewed_count": len(renewed),
                    "renewed": [{"old_id": old, "new_id": new} for old, new in renewed]
                }
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/api/letsencrypt/check-certbot", response_class=JSONResponse)
    async def check_certbot_available():
        """Vérifie si certbot est disponible."""
        try:
            available = letsencrypt_manager.check_certbot_available()
            return {
                "success": True,
                "data": {
                    "available": available,
                    "message": "certbot est installé" if available else "certbot n'est pas installé"
                }
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    # Routes API - Certificats Client
    @app.get("/api/client-certificates", response_class=JSONResponse)
    async def list_client_certificates():
        """Liste tous les certificats client."""
        try:
            certificates = storage.list_certificates()
            # Filtrer les certificats client
            client_certs = [c for c in certificates if c.get('certificate_type') == 'client']
            return {"success": True, "data": client_certs}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/client-certificates", response_class=JSONResponse)
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
    ):
        """Crée un nouveau certificat client."""
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.backends import default_backend
            
            ca_cert_obj = None
            ca_key_obj = None
            
            # Charger CA si fournie
            if ca_cert_file and ca_key_file:
                ca_cert_data = await ca_cert_file.read()
                ca_key_data = await ca_key_file.read()
                
                ca_cert_obj = x509.load_pem_x509_certificate(ca_cert_data, default_backend())
                
                # Essayer de charger la clé sans mot de passe
                try:
                    ca_key_obj = serialization.load_pem_private_key(
                        ca_key_data, 
                        password=None, 
                        backend=default_backend()
                    )
                except ValueError:
                    # Essayer avec mot de passe
                    if ca_password:
                        ca_key_obj = serialization.load_pem_private_key(
                            ca_key_data,
                            password=ca_password.encode('utf-8'),
                            backend=default_backend()
                        )
                    else:
                        raise HTTPException(
                            status_code=400, 
                            detail="La clé CA est chiffrée, un mot de passe est requis"
                        )
            
            cert, private_key, metadata = client_cert_manager.generate_client_cert(
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
            
            cert_id = storage.save_certificate(cert, private_key, metadata)
            return {"success": True, "data": {"id": cert_id, **metadata}}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))
    
    @app.post("/api/client-certificates/{cert_id}/export-browser", response_class=JSONResponse)
    async def export_client_certificate_browser(
        cert_id: str,
        password: Optional[str] = None
    ):
        """Exporte un certificat client au format PKCS#12 pour navigateur."""
        try:
            import base64
            
            cert, metadata = storage.load_certificate(cert_id)
            private_key = storage.load_private_key(cert_id)
            
            # Vérifier que c'est un certificat client
            if metadata.get('certificate_type') != 'client':
                raise HTTPException(status_code=400, detail="Ce n'est pas un certificat client")
            
            p12_data = client_cert_manager.export_for_browser(
                cert,
                private_key,
                password=password
            )
            
            return {
                "success": True,
                "data": {
                    "format": "pkcs12",
                    "filename": f"{cert_id}.p12",
                    "file_data": base64.b64encode(p12_data).decode("utf-8"),
                    "mime_type": "application/x-pkcs12"
                }
            }
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="Certificat non trouvé")
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    return app


"""Gestionnaire d'autorités de certification (CA)."""

import os
import json
import uuid
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, NameOID

from .storage import SecureStorage
from .validation import CertificateValidator
from .validation.certificate import verify_certificate_signature
from .import_export import CertificateImporter
from .certificate.ca import CAGenerator
from .key import KeyManager


class CAManager:
    """Gestionnaire d'autorités de certification."""

    def __init__(self, storage: Optional[SecureStorage] = None):
        """
        Initialise le gestionnaire de CA.

        Args:
            storage: Instance de SecureStorage. Si None, crée une nouvelle instance.
        """
        self.storage = storage or SecureStorage()
        self.validator = CertificateValidator()
        self.importer = CertificateImporter(self.storage)
        self.ca_generator = CAGenerator()
        self.key_manager = KeyManager()
        
        # Répertoire spécifique pour les CA
        self.ca_dir = self.storage.storage_path / "ca"
        self.ca_certs_dir = self.ca_dir / "certificates"
        self.ca_keys_dir = self.ca_dir / "keys"
        self.ca_metadata_file = self.ca_dir / "metadata.json"
        
        # Créer les répertoires
        self._create_directories()

    def _create_directories(self):
        """Crée les répertoires pour les CA."""
        self.ca_dir.mkdir(parents=True, exist_ok=True)
        self.ca_certs_dir.mkdir(parents=True, exist_ok=True)
        self.ca_keys_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.ca_dir, 0o700)
        os.chmod(self.ca_certs_dir, 0o700)
        os.chmod(self.ca_keys_dir, 0o700)

    def _load_ca_metadata(self) -> Dict:
        """Charge les métadonnées des CA."""
        if not self.ca_metadata_file.exists():
            return {}
        
        try:
            with open(self.ca_metadata_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}

    def _save_ca_metadata(self, metadata: Dict):
        """Sauvegarde les métadonnées des CA."""
        with open(self.ca_metadata_file, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)
        os.chmod(self.ca_metadata_file, 0o600)

    def add_ca_certificate(
        self,
        cert: x509.Certificate,
        name: Optional[str] = None,
        is_root: bool = False,
        is_trusted: bool = True
    ) -> str:
        """
        Ajoute un certificat CA au stockage.

        Args:
            cert: Certificat CA
            name: Nom personnalisé pour la CA (optionnel)
            is_root: Indique si c'est une CA racine
            is_trusted: Indique si la CA est de confiance

        Returns:
            ID de la CA
        """
        # Vérifier que c'est bien un certificat CA
        if not self._is_ca_certificate(cert):
            raise ValueError("Le certificat n'est pas une autorité de certification")

        # Générer un ID
        ca_id = str(uuid.uuid4())

        # Extraire les métadonnées
        common_name = None
        for attr in cert.subject:
            if attr.oid._name == "commonName":
                common_name = attr.value
                break

        metadata = {
            "id": ca_id,
            "name": name or common_name or "CA",
            "common_name": common_name or "Unknown",
            "is_root": is_root,
            "is_trusted": is_trusted,
            "has_private_key": False,
            "not_valid_before": cert.not_valid_before_utc.isoformat(),
            "not_valid_after": cert.not_valid_after_utc.isoformat(),
            "created": datetime.now(timezone.utc).isoformat(),
        }

        # Extraire le sujet complet
        subject_dict = {}
        for attr in cert.subject:
            subject_dict[attr.oid._name] = attr.value
        metadata["subject"] = subject_dict

        # Sauvegarder le certificat
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        cert_file = self.ca_certs_dir / f"{ca_id}.pem"
        cert_file.write_bytes(cert_pem)
        os.chmod(cert_file, 0o644)

        # Sauvegarder les métadonnées
        all_metadata = self._load_ca_metadata()
        all_metadata[ca_id] = metadata
        self._save_ca_metadata(all_metadata)

        return ca_id

    def _is_ca_certificate(self, cert: x509.Certificate) -> bool:
        """
        Vérifie si un certificat est une autorité de certification.

        Args:
            cert: Certificat à vérifier

        Returns:
            True si c'est une CA
        """
        try:
            # Vérifier l'extension Basic Constraints
            bc_ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            return bc_ext.value.ca
        except x509.ExtensionNotFound:
            # Si pas d'extension, vérifier le Key Usage
            try:
                ku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
                return ku_ext.value.key_cert_sign
            except x509.ExtensionNotFound:
                # Par défaut, considérer comme CA si le sujet = émetteur (auto-signé)
                return cert.subject == cert.issuer

    def list_ca_certificates(self) -> List[Dict]:
        """
        Liste toutes les CA stockées.

        Returns:
            Liste des métadonnées des CA
        """
        metadata = self._load_ca_metadata()
        return list(metadata.values())

    def get_ca_certificate(self, ca_id: str) -> Tuple[x509.Certificate, Dict]:
        """
        Récupère un certificat CA.

        Args:
            ca_id: ID de la CA

        Returns:
            Tuple (certificat, métadonnées)
        """
        metadata = self._load_ca_metadata()
        if ca_id not in metadata:
            raise FileNotFoundError(f"CA non trouvée: {ca_id}")

        cert_file = self.ca_certs_dir / f"{ca_id}.pem"
        if not cert_file.exists():
            raise FileNotFoundError(f"Fichier certificat CA non trouvé: {ca_id}")

        cert_data = cert_file.read_bytes()
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())

        return cert, metadata[ca_id]

    def delete_ca_certificate(self, ca_id: str):
        """
        Supprime une CA.

        Args:
            ca_id: ID de la CA
        """
        metadata = self._load_ca_metadata()
        if ca_id not in metadata:
            raise FileNotFoundError(f"CA non trouvée: {ca_id}")

        # Supprimer le fichier certificat
        cert_file = self.ca_certs_dir / f"{ca_id}.pem"
        if cert_file.exists():
            cert_file.unlink()

        key_file = self.ca_keys_dir / f"{ca_id}.key"
        if key_file.exists():
            key_file.unlink()

        # Supprimer les métadonnées
        del metadata[ca_id]
        self._save_ca_metadata(metadata)

    def verify_certificate_chain(
        self,
        cert: x509.Certificate,
        ca_cert_ids: Optional[List[str]] = None
    ) -> Tuple[bool, List[str]]:
        """
        Vérifie la chaîne de certificats avec les CA stockées.

        Args:
            cert: Certificat à vérifier
            ca_cert_ids: Liste d'IDs de CA à utiliser (None = toutes les CA de confiance)

        Returns:
            Tuple (est_valide, liste_d_erreurs)
        """
        errors = []
        
        # Si aucune CA spécifiée, utiliser toutes les CA de confiance
        if ca_cert_ids is None:
            all_cas = self.list_ca_certificates()
            trusted_cas = [ca for ca in all_cas if ca.get("is_trusted", True)]
            ca_cert_ids = [ca["id"] for ca in trusted_cas]

        if not ca_cert_ids:
            errors.append("Aucune CA de confiance disponible")
            return False, errors

        # Charger les certificats CA
        ca_certs = []
        for ca_id in ca_cert_ids:
            try:
                ca_cert, _ = self.get_ca_certificate(ca_id)
                ca_certs.append(ca_cert)
            except FileNotFoundError:
                errors.append(f"CA non trouvée: {ca_id}")
                continue

        if not ca_certs:
            errors.append("Aucune CA valide disponible")
            return False, errors

        # Vérifier si le certificat est signé par une des CA
        cert_issuer = cert.issuer
        verified = False

        for ca_cert in ca_certs:
            # Vérifier si l'émetteur du certificat correspond au sujet de la CA
            if cert_issuer == ca_cert.subject:
                # Vérifier la signature
                try:
                    verify_certificate_signature(cert, ca_cert)
                    verified = True
                    break
                except Exception as e:
                    from cryptography.x509.oid import NameOID
                    try:
                        cn_attr = ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                        ca_name = cn_attr[0].value if cn_attr else "Unknown"
                    except:
                        ca_name = "Unknown"
                    errors.append(f"Échec de vérification de signature avec CA {ca_name}: {e}")
                    continue

        if not verified:
            errors.append("Le certificat n'est pas signé par une CA de confiance")
            return False, errors

        # Vérifier la validité du certificat
        now = datetime.now(timezone.utc)
        if cert.not_valid_before_utc > now:
            errors.append("Le certificat n'est pas encore valide")
        if cert.not_valid_after_utc < now:
            errors.append("Le certificat a expiré")

        return len(errors) == 0, errors

    def _save_ca_private_key(self, ca_id: str, private_key) -> None:
        """Sauvegarde la clé privée d'une CA."""
        from ..config import get_settings
        settings = get_settings()
        password = settings.storage_password.encode() if settings.encrypt_keys and settings.storage_password else None

        key_pem = self.key_manager.key_to_pem(private_key, password)
        key_file = self.ca_keys_dir / f"{ca_id}.key"
        key_file.write_bytes(key_pem)
        os.chmod(key_file, 0o600)

    def get_ca_private_key(self, ca_id: str):
        """Charge la clé privée d'une CA si disponible localement."""
        key_file = self.ca_keys_dir / f"{ca_id}.key"
        if not key_file.exists():
            return None

        from ..config import get_settings
        settings = get_settings()
        password = settings.storage_password.encode() if settings.encrypt_keys and settings.storage_password else None
        return self.key_manager.pem_to_key(key_file.read_bytes(), password)

    def generate_ca(
        self,
        common_name: str,
        name: Optional[str] = None,
        is_root: bool = True,
        parent_ca_id: Optional[str] = None,
        key_type: str = "RSA",
        key_size: int = 2048,
        validity_days: int = 3650,
        country: Optional[str] = None,
        state: Optional[str] = None,
        locality: Optional[str] = None,
        organization: Optional[str] = None,
        organizational_unit: Optional[str] = None,
        email: Optional[str] = None,
        is_trusted: bool = True,
    ) -> str:
        """
        Génère et stocke une CA racine ou intermédiaire avec sa clé privée.

        Returns:
            ID de la CA générée
        """
        parent_cert = None
        parent_key = None
        if not is_root:
            if not parent_ca_id:
                raise ValueError("parent_ca_id est requis pour une CA intermédiaire")
            parent_cert, _ = self.get_ca_certificate(parent_ca_id)
            parent_key = self.get_ca_private_key(parent_ca_id)
            if parent_key is None:
                raise ValueError(
                    f"La CA parent '{parent_ca_id}' n'a pas de clé privée locale"
                )

        cert, private_key, gen_meta = self.ca_generator.generate_ca(
            common_name=common_name,
            key_type=key_type,
            key_size=key_size,
            validity_days=validity_days,
            is_root=is_root,
            parent_cert=parent_cert,
            parent_key=parent_key,
            country=country,
            state=state,
            locality=locality,
            organization=organization,
            organizational_unit=organizational_unit,
            email=email,
        )

        ca_id = gen_meta["id"]

        metadata = {
            "id": ca_id,
            "name": name or common_name,
            "common_name": common_name,
            "is_root": is_root,
            "is_trusted": is_trusted,
            "has_private_key": True,
            "not_valid_before": cert.not_valid_before_utc.isoformat(),
            "not_valid_after": cert.not_valid_after_utc.isoformat(),
            "created": datetime.now(timezone.utc).isoformat(),
            "key_type": gen_meta.get("key_type"),
            "key_size": gen_meta.get("key_size"),
        }
        if parent_ca_id:
            metadata["parent_ca_id"] = parent_ca_id

        subject_dict = {attr.oid._name: attr.value for attr in cert.subject}
        metadata["subject"] = subject_dict

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        cert_file = self.ca_certs_dir / f"{ca_id}.pem"
        cert_file.write_bytes(cert_pem)
        os.chmod(cert_file, 0o644)

        self._save_ca_private_key(ca_id, private_key)

        all_metadata = self._load_ca_metadata()
        all_metadata[ca_id] = metadata
        self._save_ca_metadata(all_metadata)

        return ca_id

    def sign_csr(
        self,
        ca_id: str,
        csr: x509.CertificateSigningRequest,
        validity_days: int = 365,
    ) -> Tuple[x509.Certificate, Dict]:
        """Signe une CSR avec une CA locale."""
        ca_cert, ca_meta = self.get_ca_certificate(ca_id)
        ca_key = self.get_ca_private_key(ca_id)
        if ca_key is None:
            raise ValueError(f"La CA '{ca_id}' n'a pas de clé privée locale")

        cert = self.ca_generator.sign_csr(csr, ca_cert, ca_key, validity_days)

        common_name = "Unknown"
        try:
            common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except IndexError:
            pass

        metadata = {
            "id": str(uuid.uuid4()),
            "common_name": common_name,
            "certificate_type": "server",
            "signed_by_ca": True,
            "ca_id": ca_id,
            "ca_common_name": ca_meta.get("common_name"),
            "not_valid_before": cert.not_valid_before_utc.isoformat(),
            "not_valid_after": cert.not_valid_after_utc.isoformat(),
            "created": datetime.now(timezone.utc).isoformat(),
        }
        return cert, metadata

    def sign_csr_from_storage(
        self,
        ca_id: str,
        csr_id: str,
        validity_days: int = 365,
    ) -> str:
        """Signe une CSR stockée et enregistre le certificat."""
        csr, csr_meta = self.storage.load_csr(csr_id)
        private_key = self.storage.load_private_key(csr_id)
        cert, metadata = self.sign_csr(ca_id, csr, validity_days)
        cert_id = self.storage.save_certificate(cert, private_key, metadata)
        return cert_id

    def sign_server_certificate(
        self,
        ca_id: str,
        common_name: str,
        validity_days: int = 365,
        key_type: str = "RSA",
        key_size: int = 2048,
        country: Optional[str] = None,
        state: Optional[str] = None,
        locality: Optional[str] = None,
        organization: Optional[str] = None,
        organizational_unit: Optional[str] = None,
        email: Optional[str] = None,
        san_dns: Optional[List[str]] = None,
        san_ip: Optional[List[str]] = None,
    ) -> str:
        """Génère un certificat serveur signé par une CA locale."""
        ca_cert, ca_meta = self.get_ca_certificate(ca_id)
        ca_key = self.get_ca_private_key(ca_id)
        if ca_key is None:
            raise ValueError(f"La CA '{ca_id}' n'a pas de clé privée locale")

        cert, private_key, metadata = self.ca_generator.generate_signed_server_certificate(
            common_name=common_name,
            ca_cert=ca_cert,
            ca_key=ca_key,
            key_type=key_type,
            key_size=key_size,
            validity_days=validity_days,
            country=country,
            state=state,
            locality=locality,
            organization=organization,
            organizational_unit=organizational_unit,
            email=email,
            san_dns=san_dns,
            san_ip=san_ip,
        )
        metadata["ca_id"] = ca_id
        metadata["ca_common_name"] = ca_meta.get("common_name")
        return self.storage.save_certificate(cert, private_key, metadata)

    def import_ca_from_file(
        self,
        cert_path: str,
        name: Optional[str] = None,
        is_root: bool = True,
        is_trusted: bool = True
    ) -> str:
        """
        Importe une CA depuis un fichier.

        Args:
            cert_path: Chemin vers le fichier certificat CA
            name: Nom personnalisé pour la CA
            is_root: Indique si c'est une CA racine
            is_trusted: Indique si la CA est de confiance

        Returns:
            ID de la CA importée
        """
        cert_file = Path(cert_path)
        if not cert_file.exists():
            raise FileNotFoundError(f"Fichier CA non trouvé: {cert_path}")

        # Détecter le format
        cert_data = cert_file.read_bytes()
        
        # Essayer PEM d'abord
        try:
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        except ValueError:
            # Essayer DER
            try:
                cert = x509.load_der_x509_certificate(cert_data, default_backend())
            except ValueError:
                raise ValueError("Format de certificat non reconnu (PEM ou DER attendu)")

        return self.add_ca_certificate(cert, name=name, is_root=is_root, is_trusted=is_trusted)


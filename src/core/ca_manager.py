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
from cryptography.x509.oid import ExtensionOID

from .storage import SecureStorage
from .validation import CertificateValidator
from .import_export import CertificateImporter


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
        
        # Répertoire spécifique pour les CA
        self.ca_dir = self.storage.storage_path / "ca"
        self.ca_certs_dir = self.ca_dir / "certificates"
        self.ca_metadata_file = self.ca_dir / "metadata.json"
        
        # Créer les répertoires
        self._create_directories()

    def _create_directories(self):
        """Crée les répertoires pour les CA."""
        self.ca_dir.mkdir(parents=True, exist_ok=True)
        self.ca_certs_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.ca_dir, 0o700)
        os.chmod(self.ca_certs_dir, 0o700)

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
                    public_key = ca_cert.public_key()
                    public_key.verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        cert.signature_algorithm,
                        default_backend()
                    )
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


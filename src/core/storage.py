"""Système de stockage sécurisé pour les certificats et clés."""

import os
import json
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from .certificate import CertificateManager


class SecureStorage:
    """Gestionnaire de stockage sécurisé pour certificats et clés."""

    def __init__(self, storage_path: Optional[str] = None):
        """
        Initialise le stockage sécurisé.

        Args:
            storage_path: Chemin du répertoire de stockage.
                         Par défaut: ~/.certmanager
        """
        if storage_path is None:
            storage_path = os.path.expanduser("~/.certmanager")

        self.storage_path = Path(storage_path)
        self.certs_dir = self.storage_path / "certificates"
        self.keys_dir = self.storage_path / "keys"
        self.csr_dir = self.storage_path / "csr"
        self.metadata_file = self.storage_path / "metadata.json"

        # Créer les répertoires avec permissions sécurisées
        self._create_directories()

    def _create_directories(self):
        """Crée les répertoires de stockage avec permissions sécurisées."""
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.certs_dir.mkdir(parents=True, exist_ok=True)
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self.csr_dir.mkdir(parents=True, exist_ok=True)

        # Permissions sécurisées (700 pour répertoires, 600 pour fichiers)
        os.chmod(self.storage_path, 0o700)
        os.chmod(self.certs_dir, 0o700)
        os.chmod(self.keys_dir, 0o700)
        os.chmod(self.csr_dir, 0o700)

    def _load_metadata(self) -> Dict:
        """Charge les métadonnées depuis le fichier JSON."""
        if not self.metadata_file.exists():
            return {}

        try:
            with open(self.metadata_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}

    def _save_metadata(self, metadata: Dict):
        """Sauvegarde les métadonnées dans le fichier JSON."""
        with open(self.metadata_file, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)
        os.chmod(self.metadata_file, 0o600)

    def save_certificate(
        self,
        cert: x509.Certificate,
        private_key,
        metadata: Dict,
        password: Optional[bytes] = None
    ) -> str:
        """
        Sauvegarde un certificat et sa clé privée.

        Args:
            cert: Certificat X.509
            private_key: Clé privée
            metadata: Métadonnées du certificat
            password: Mot de passe optionnel pour chiffrer la clé

        Returns:
            ID du certificat sauvegardé
        """
        cert_id = metadata.get("id")
        if not cert_id:
            raise ValueError("Les métadonnées doivent contenir un 'id'")

        # Sauvegarder le certificat en PEM
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        cert_file = self.certs_dir / f"{cert_id}.pem"
        cert_file.write_bytes(cert_pem)
        os.chmod(cert_file, 0o644)

        # Sauvegarder la clé privée
        from .key import KeyManager
        key_manager = KeyManager()
        key_pem = key_manager.key_to_pem(private_key, password)
        key_file = self.keys_dir / f"{cert_id}.key"
        key_file.write_bytes(key_pem)
        os.chmod(key_file, 0o600)

        # Mettre à jour les métadonnées
        all_metadata = self._load_metadata()
        all_metadata[cert_id] = metadata
        self._save_metadata(all_metadata)

        return cert_id

    def save_csr(
        self,
        csr: x509.CertificateSigningRequest,
        private_key,
        metadata: Dict,
        password: Optional[bytes] = None
    ) -> str:
        """
        Sauvegarde une CSR et sa clé privée.

        Args:
            csr: Certificate Signing Request
            private_key: Clé privée
            metadata: Métadonnées de la CSR
            password: Mot de passe optionnel pour chiffrer la clé

        Returns:
            ID de la CSR sauvegardée
        """
        csr_id = metadata.get("id")
        if not csr_id:
            raise ValueError("Les métadonnées doivent contenir un 'id'")

        # Sauvegarder la CSR en PEM
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        csr_file = self.csr_dir / f"{csr_id}.csr"
        csr_file.write_bytes(csr_pem)
        os.chmod(csr_file, 0o644)

        # Sauvegarder la clé privée
        from .key import KeyManager
        key_manager = KeyManager()
        key_pem = key_manager.key_to_pem(private_key, password)
        key_file = self.keys_dir / f"{csr_id}.key"
        key_file.write_bytes(key_pem)
        os.chmod(key_file, 0o600)

        # Mettre à jour les métadonnées
        all_metadata = self._load_metadata()
        all_metadata[csr_id] = {**metadata, "type": "csr"}
        self._save_metadata(all_metadata)

        return csr_id

    def load_certificate(self, cert_id: str) -> tuple[x509.Certificate, Dict]:
        """
        Charge un certificat et ses métadonnées.

        Args:
            cert_id: ID du certificat

        Returns:
            Tuple (certificat, métadonnées)
        """
        cert_file = self.certs_dir / f"{cert_id}.pem"
        if not cert_file.exists():
            raise FileNotFoundError(f"Certificat {cert_id} introuvable")

        cert_pem = cert_file.read_bytes()
        cert = x509.load_pem_x509_certificate(cert_pem, default_backend())

        metadata = self._load_metadata().get(cert_id, {})
        return cert, metadata

    def load_private_key(self, cert_id: str, password: Optional[bytes] = None):
        """
        Charge la clé privée associée à un certificat.

        Args:
            cert_id: ID du certificat
            password: Mot de passe si la clé est chiffrée

        Returns:
            Clé privée
        """
        key_file = self.keys_dir / f"{cert_id}.key"
        if not key_file.exists():
            raise FileNotFoundError(f"Clé privée {cert_id} introuvable")

        key_pem = key_file.read_bytes()
        from .key import KeyManager
        key_manager = KeyManager()
        return key_manager.pem_to_key(key_pem, password)

    def list_certificates(self) -> List[Dict]:
        """
        Liste tous les certificats stockés.

        Returns:
            Liste des métadonnées des certificats
        """
        metadata = self._load_metadata()
        certificates = []

        for cert_id, meta in metadata.items():
            if meta.get("type") == "csr":
                continue  # Ignorer les CSR dans la liste des certificats

            # Charger le certificat pour obtenir les dates
            try:
                cert, _ = self.load_certificate(cert_id)
                meta["not_valid_before"] = cert.not_valid_before_utc.isoformat()
                meta["not_valid_after"] = cert.not_valid_after_utc.isoformat()
                meta["is_expired"] = cert.not_valid_after_utc < datetime.utcnow()
                meta["days_until_expiry"] = (
                    cert.not_valid_after_utc - datetime.utcnow()
                ).days if not meta["is_expired"] else 0
            except Exception:
                # Si le certificat ne peut pas être chargé, continuer
                pass

            certificates.append(meta)

        return certificates

    def delete_certificate(self, cert_id: str):
        """
        Supprime un certificat et sa clé privée.

        Args:
            cert_id: ID du certificat à supprimer
        """
        # Supprimer les fichiers
        cert_file = self.certs_dir / f"{cert_id}.pem"
        key_file = self.keys_dir / f"{cert_id}.key"

        if cert_file.exists():
            cert_file.unlink()
        if key_file.exists():
            key_file.unlink()

        # Supprimer des métadonnées
        metadata = self._load_metadata()
        if cert_id in metadata:
            del metadata[cert_id]
            self._save_metadata(metadata)


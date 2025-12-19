"""Gestion du renouvellement de certificats."""

import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Tuple
from cryptography import x509

from .certificate import CertificateManager
from .storage import SecureStorage
from .validation import CertificateValidator


class CertificateRenewal:
    """Gestionnaire de renouvellement de certificats."""

    def __init__(self, storage: Optional[SecureStorage] = None):
        """
        Initialise le gestionnaire de renouvellement.

        Args:
            storage: Instance de SecureStorage. Si None, crée une nouvelle instance.
        """
        self.storage = storage or SecureStorage()
        self.cert_manager = CertificateManager()
        self.validator = CertificateValidator()

    def renew_certificate(
        self,
        cert_id: str,
        validity_days: Optional[int] = None,
        archive_old: bool = True
    ) -> Tuple[str, Dict]:
        """
        Renouvelle un certificat.

        Args:
            cert_id: ID du certificat à renouveler
            validity_days: Nombre de jours de validité pour le nouveau certificat.
                          Si None, utilise la même durée que l'original
            archive_old: Archiver l'ancien certificat. Défaut: True

        Returns:
            Tuple (nouveau_cert_id, métadonnées)
        """
        # Charger le certificat existant
        old_cert, old_metadata = self.storage.load_certificate(cert_id)
        old_private_key = self.storage.load_private_key(cert_id)

        # Extraire les informations de l'ancien certificat
        subject_dict = {attr.oid._name: attr.value for attr in old_cert.subject}
        
        # Déterminer la durée de validité
        if validity_days is None:
            # Calculer la durée originale
            validity_delta = old_cert.not_valid_after_utc - old_cert.not_valid_before_utc
            validity_days = validity_delta.days

        # Extraire les SAN si présents
        san_dns = []
        try:
            san_ext = old_cert.extensions.get_extension_for_oid(
                x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    san_dns.append(name.value)
        except x509.ExtensionNotFound:
            pass

        # Si pas de SAN, utiliser le CN
        if not san_dns and 'commonName' in subject_dict:
            san_dns = [subject_dict['commonName']]

        # Générer le nouveau certificat avec les mêmes paramètres
        new_cert, new_private_key, new_metadata = self.cert_manager.generate_self_signed_cert(
            common_name=subject_dict.get('commonName', old_metadata.get('common_name', 'unknown')),
            validity_days=validity_days,
            key_type=old_metadata.get('key_type', 'RSA'),
            key_size=old_metadata.get('key_size', 2048),
            country=subject_dict.get('countryName'),
            state=subject_dict.get('stateOrProvinceName'),
            locality=subject_dict.get('localityName'),
            organization=subject_dict.get('organizationName'),
            organizational_unit=subject_dict.get('organizationalUnitName'),
            email=subject_dict.get('emailAddress'),
            san_dns=san_dns if san_dns else None,
        )

        # Mettre à jour les métadonnées avec l'info de renouvellement avant sauvegarde
        new_metadata['renewed_from'] = cert_id
        new_metadata['renewed_at'] = datetime.utcnow().isoformat()
        
        # Sauvegarder le nouveau certificat
        new_cert_id = self.storage.save_certificate(new_cert, new_private_key, new_metadata)

        # Archiver et supprimer l'ancien certificat si demandé
        if archive_old:
            self._archive_certificate(cert_id, old_cert, old_private_key, old_metadata)
            # Supprimer l'ancien certificat de la liste active
            self.storage.delete_certificate(cert_id)

        return new_cert_id, new_metadata

    def _archive_certificate(
        self,
        cert_id: str,
        cert: x509.Certificate,
        private_key,
        metadata: Dict
    ):
        """
        Archive un certificat dans un répertoire d'archive.

        Args:
            cert_id: ID du certificat
            cert: Certificat à archiver
            private_key: Clé privée à archiver
            metadata: Métadonnées du certificat
        """
        # Créer le répertoire d'archive
        archive_dir = self.storage.storage_path / "archive"
        archive_dir.mkdir(parents=True, exist_ok=True)
        
        archive_certs_dir = archive_dir / "certificates"
        archive_keys_dir = archive_dir / "keys"
        archive_certs_dir.mkdir(parents=True, exist_ok=True)
        archive_keys_dir.mkdir(parents=True, exist_ok=True)

        # Sauvegarder le certificat
        from cryptography.hazmat.primitives import serialization
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        archive_cert_file = archive_certs_dir / f"{cert_id}.pem"
        archive_cert_file.write_bytes(cert_pem)

        # Sauvegarder la clé privée
        from .key import KeyManager
        key_manager = KeyManager()
        key_pem = key_manager.key_to_pem(private_key)
        archive_key_file = archive_keys_dir / f"{cert_id}.key"
        archive_key_file.write_bytes(key_pem)
        archive_key_file.chmod(0o600)

        # Sauvegarder les métadonnées
        metadata['archived_at'] = datetime.utcnow().isoformat()
        metadata['archived'] = True
        
        archive_metadata_file = archive_dir / "metadata.json"
        import json
        if archive_metadata_file.exists():
            archive_metadata = json.loads(archive_metadata_file.read_text())
        else:
            archive_metadata = {}
        
        archive_metadata[cert_id] = metadata
        archive_metadata_file.write_text(
            json.dumps(archive_metadata, indent=2),
            encoding='utf-8'
        )

    def can_renew(self, cert_id: str) -> Tuple[bool, Optional[str]]:
        """
        Vérifie si un certificat peut être renouvelé.

        Args:
            cert_id: ID du certificat

        Returns:
            Tuple (peut_être_renouvelé, message_erreur)
        """
        try:
            cert, metadata = self.storage.load_certificate(cert_id)
            
            # Vérifier que le certificat n'est pas déjà archivé
            if metadata.get('archived'):
                return False, "Le certificat est déjà archivé"
            
            # Vérifier que le certificat existe
            return True, None
        except FileNotFoundError:
            return False, "Certificat non trouvé"
        except Exception as e:
            return False, f"Erreur: {str(e)}"


"""Gestion du renouvellement de certificats."""

import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Tuple, List
from cryptography import x509

from .certificate import CertificateManager
from .certificate.client import ClientCertificateManager
from .letsencrypt import LetsEncryptManager
from .ca_manager import CAManager
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
        self.client_cert_manager = ClientCertificateManager()
        self.letsencrypt_manager = LetsEncryptManager(self.storage)
        self.ca_manager = CAManager(self.storage)
        self.validator = CertificateValidator()

    def renew_certificate(
        self,
        cert_id: str,
        validity_days: Optional[int] = None,
        archive_old: bool = True
    ) -> Tuple[str, Dict]:
        """
        Renouvelle un certificat en préservant son type d'émetteur.

        Args:
            cert_id: ID du certificat à renouveler
            validity_days: Nombre de jours de validité pour le nouveau certificat.
                          Si None, utilise la même durée que l'original
            archive_old: Archiver l'ancien certificat. Défaut: True

        Returns:
            Tuple (nouveau_cert_id, métadonnées)
        """
        old_cert, old_metadata = self.storage.load_certificate(cert_id)
        old_private_key = self.storage.load_private_key(cert_id)

        if old_metadata.get("letsencrypt"):
            new_cert_id = self._renew_letsencrypt(cert_id)
        elif old_metadata.get("signed_by_ca") and old_metadata.get("ca_id"):
            new_cert_id, new_metadata = self._renew_ca_signed(
                old_cert, old_metadata, old_private_key, validity_days
            )
            self._finalize_renewal(cert_id, old_cert, old_private_key, old_metadata, new_cert_id, new_metadata, archive_old)
            return new_cert_id, new_metadata
        elif old_metadata.get("certificate_type") == "client":
            new_cert_id, new_metadata = self._renew_client_certificate(
                old_cert, old_metadata, validity_days
            )
            self._finalize_renewal(cert_id, old_cert, old_private_key, old_metadata, new_cert_id, new_metadata, archive_old)
            return new_cert_id, new_metadata
        elif old_cert.issuer != old_cert.subject:
            raise ValueError(
                "Ce certificat est signé par une autorité externe. "
                "Le renouvellement automatique nécessite la clé privée de l'émetteur."
            )
        else:
            new_cert_id, new_metadata = self._renew_self_signed(
                old_cert, old_metadata, validity_days
            )
            self._finalize_renewal(cert_id, old_cert, old_private_key, old_metadata, new_cert_id, new_metadata, archive_old)
            return new_cert_id, new_metadata

        new_metadata = self.storage._load_metadata().get(new_cert_id, {})
        self._finalize_renewal(cert_id, old_cert, old_private_key, old_metadata, new_cert_id, new_metadata, archive_old)
        return new_cert_id, new_metadata

    def _renew_letsencrypt(self, cert_id: str) -> str:
        """Renouvelle un certificat Let's Encrypt via certbot."""
        return self.letsencrypt_manager.renew_certificate(cert_id)

    def _renew_self_signed(
        self,
        old_cert: x509.Certificate,
        old_metadata: Dict,
        validity_days: Optional[int],
    ) -> Tuple[str, Dict]:
        """Renouvelle un certificat auto-signé."""
        subject_dict = {attr.oid._name: attr.value for attr in old_cert.subject}

        if validity_days is None:
            validity_delta = old_cert.not_valid_after_utc - old_cert.not_valid_before_utc
            validity_days = validity_delta.days

        san_dns = self._extract_san_dns(old_cert)
        if not san_dns and "commonName" in subject_dict:
            san_dns = [subject_dict["commonName"]]

        new_cert, new_private_key, new_metadata = self.cert_manager.generate_self_signed_cert(
            common_name=subject_dict.get("commonName", old_metadata.get("common_name", "unknown")),
            validity_days=validity_days,
            key_type=old_metadata.get("key_type", "RSA"),
            key_size=old_metadata.get("key_size", 2048),
            country=subject_dict.get("countryName"),
            state=subject_dict.get("stateOrProvinceName"),
            locality=subject_dict.get("localityName"),
            organization=subject_dict.get("organizationName"),
            organizational_unit=subject_dict.get("organizationalUnitName"),
            email=subject_dict.get("emailAddress"),
            san_dns=san_dns if san_dns else None,
        )

        new_cert_id = self.storage.save_certificate(new_cert, new_private_key, new_metadata)
        return new_cert_id, new_metadata

    def _renew_ca_signed(
        self,
        old_cert: x509.Certificate,
        old_metadata: Dict,
        old_private_key,
        validity_days: Optional[int],
    ) -> Tuple[str, Dict]:
        """Renouvelle un certificat signé par une CA locale."""
        ca_id = old_metadata.get("ca_id")
        if not ca_id:
            raise ValueError("Métadonnées CA manquantes (ca_id)")

        subject_dict = {attr.oid._name: attr.value for attr in old_cert.subject}
        if validity_days is None:
            validity_delta = old_cert.not_valid_after_utc - old_cert.not_valid_before_utc
            validity_days = validity_delta.days

        san_dns = self._extract_san_dns(old_cert)

        ca_cert, ca_meta = self.ca_manager.get_ca_certificate(ca_id)
        ca_key = self.ca_manager.get_ca_private_key(ca_id)
        if ca_key is None:
            raise ValueError(f"La CA '{ca_id}' n'a pas de clé privée locale")

        new_cert, _, new_metadata = self.ca_manager.ca_generator.generate_signed_server_certificate(
            common_name=subject_dict.get("commonName", old_metadata.get("common_name", "unknown")),
            ca_cert=ca_cert,
            ca_key=ca_key,
            key_type=old_metadata.get("key_type", "RSA"),
            key_size=old_metadata.get("key_size", 2048),
            validity_days=validity_days,
            country=subject_dict.get("countryName"),
            state=subject_dict.get("stateOrProvinceName"),
            locality=subject_dict.get("localityName"),
            organization=subject_dict.get("organizationName"),
            organizational_unit=subject_dict.get("organizationalUnitName"),
            email=subject_dict.get("emailAddress"),
            san_dns=san_dns if san_dns else None,
            private_key=old_private_key,
        )
        new_metadata["ca_id"] = ca_id
        new_metadata["ca_common_name"] = ca_meta.get("common_name")

        new_cert_id = self.storage.save_certificate(new_cert, old_private_key, new_metadata)
        return new_cert_id, new_metadata

    def _renew_client_certificate(
        self,
        old_cert: x509.Certificate,
        old_metadata: Dict,
        validity_days: Optional[int],
    ) -> Tuple[str, Dict]:
        """Renouvelle un certificat client (auto-signé uniquement)."""
        if old_cert.issuer != old_cert.subject:
            raise ValueError(
                "Impossible de renouveler un certificat client signé par une CA externe "
                "sans la clé privée de la CA."
            )

        subject_dict = {attr.oid._name: attr.value for attr in old_cert.subject}

        if validity_days is None:
            validity_delta = old_cert.not_valid_after_utc - old_cert.not_valid_before_utc
            validity_days = validity_delta.days

        new_cert, new_private_key, new_metadata = self.client_cert_manager.generate_client_cert(
            common_name=subject_dict.get("commonName", old_metadata.get("common_name", "unknown")),
            validity_days=validity_days,
            key_type=old_metadata.get("key_type", "RSA"),
            key_size=old_metadata.get("key_size", 2048),
            country=subject_dict.get("countryName"),
            state=subject_dict.get("stateOrProvinceName"),
            locality=subject_dict.get("localityName"),
            organization=subject_dict.get("organizationName"),
            organizational_unit=subject_dict.get("organizationalUnitName"),
            email=subject_dict.get("emailAddress"),
        )

        new_cert_id = self.storage.save_certificate(new_cert, new_private_key, new_metadata)
        return new_cert_id, new_metadata

    def _finalize_renewal(
        self,
        old_cert_id: str,
        old_cert: x509.Certificate,
        old_private_key,
        old_metadata: Dict,
        new_cert_id: str,
        new_metadata: Dict,
        archive_old: bool,
    ) -> None:
        """Enregistre les métadonnées de renouvellement et archive l'ancien certificat."""
        renewal_info = {
            "renewed_from": old_cert_id,
            "renewed_at": datetime.now(timezone.utc).isoformat(),
        }
        self.storage.update_metadata(new_cert_id, renewal_info)
        new_metadata.update(renewal_info)

        if archive_old:
            self._archive_certificate(old_cert_id, old_cert, old_private_key, old_metadata)
            self.storage.delete_certificate(old_cert_id)

    @staticmethod
    def _extract_san_dns(cert: x509.Certificate) -> list:
        """Extrait les noms DNS du SAN."""
        san_dns = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    san_dns.append(name.value)
        except x509.ExtensionNotFound:
            pass
        return san_dns

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
        archive_dir = self.storage.storage_path / "archive"
        archive_dir.mkdir(parents=True, exist_ok=True)

        archive_certs_dir = archive_dir / "certificates"
        archive_keys_dir = archive_dir / "keys"
        archive_certs_dir.mkdir(parents=True, exist_ok=True)
        archive_keys_dir.mkdir(parents=True, exist_ok=True)

        from cryptography.hazmat.primitives import serialization
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        archive_cert_file = archive_certs_dir / f"{cert_id}.pem"
        archive_cert_file.write_bytes(cert_pem)

        from .key import KeyManager
        key_manager = KeyManager()
        key_pem = key_manager.key_to_pem(private_key)
        archive_key_file = archive_keys_dir / f"{cert_id}.key"
        archive_key_file.write_bytes(key_pem)
        archive_key_file.chmod(0o600)

        metadata['archived_at'] = datetime.now(timezone.utc).isoformat()
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

            if metadata.get('archived'):
                return False, "Le certificat est déjà archivé"

            if metadata.get("letsencrypt"):
                if not self.letsencrypt_manager.check_certbot_available():
                    return False, "certbot n'est pas installé pour renouveler Let's Encrypt"
                return True, None

            if metadata.get("signed_by_ca") and metadata.get("ca_id"):
                ca_key = self.ca_manager.get_ca_private_key(metadata["ca_id"])
                if ca_key is None:
                    return False, (
                        "Certificat signé par une CA sans clé locale : "
                        "renouvellement automatique non disponible"
                    )
                return True, None

            if metadata.get("certificate_type") == "client" and cert.issuer != cert.subject:
                return False, (
                    "Certificat client signé par une CA externe : "
                    "fournissez la clé CA pour renouveler"
                )

            if cert.issuer != cert.subject and not metadata.get("letsencrypt"):
                return False, (
                    "Certificat signé par une CA externe : "
                    "renouvellement automatique non disponible"
                )

            return True, None
        except FileNotFoundError:
            return False, "Certificat non trouvé"
        except Exception as e:
            return False, f"Erreur: {str(e)}"

    def renew_all_expiring(
        self,
        days_threshold: int = 30,
        dry_run: bool = False,
        archive_old: bool = True,
        validity_days: Optional[int] = None,
    ) -> List[Tuple[str, Optional[str], Optional[str]]]:
        """
        Renouvelle tous les certificats expirant dans le seuil.

        Returns:
            Liste de tuples (ancien_id, nouveau_id_ou_None, erreur_ou_None)
        """
        from .lifecycle import CertificateLifecycle

        lifecycle = CertificateLifecycle(self.storage)
        expiring = lifecycle.get_expiring_certificates(
            days_threshold=days_threshold,
            include_expired=False,
        )

        results: List[Tuple[str, Optional[str], Optional[str]]] = []
        for cert_data in expiring:
            cert_id = cert_data.get("id")
            if not cert_id:
                continue

            can_renew, error_msg = self.can_renew(cert_id)
            if not can_renew:
                results.append((cert_id, None, error_msg))
                continue

            if dry_run:
                results.append((cert_id, "dry-run", None))
                continue

            try:
                new_id, _ = self.renew_certificate(
                    cert_id,
                    validity_days=validity_days,
                    archive_old=archive_old,
                )
                results.append((cert_id, new_id, None))
            except Exception as e:
                results.append((cert_id, None, str(e)))

        return results

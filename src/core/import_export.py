"""Module d'import et d'export de certificats."""

import os
import uuid
from pathlib import Path
from typing import Optional, Tuple, Dict
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from .storage import SecureStorage
from .validation import CertificateValidator
from .key import KeyManager


class CertificateImporter:
    """Gestionnaire d'import de certificats."""

    def __init__(self, storage: Optional[SecureStorage] = None):
        """
        Initialise l'importeur de certificats.

        Args:
            storage: Instance de SecureStorage. Si None, crée une nouvelle instance.
        """
        self.storage = storage or SecureStorage()
        self.validator = CertificateValidator()
        self.key_manager = KeyManager()

    def import_from_pem(
        self,
        cert_path: str,
        key_path: Optional[str] = None,
        password: Optional[bytes] = None,
        validate: bool = True
    ) -> str:
        """
        Importe un certificat depuis un fichier PEM.

        Args:
            cert_path: Chemin vers le fichier certificat PEM
            key_path: Chemin vers le fichier clé privée PEM (optionnel)
            password: Mot de passe pour déchiffrer la clé privée (optionnel)
            validate: Valider le certificat après import. Défaut: True

        Returns:
            ID du certificat importé
        """
        cert_file = Path(cert_path)
        if not cert_file.exists():
            raise FileNotFoundError(f"Fichier certificat non trouvé: {cert_path}")

        # Charger le certificat
        cert_data = cert_file.read_bytes()
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())

        # Charger la clé privée si fournie
        private_key = None
        if key_path:
            key_file = Path(key_path)
            if not key_file.exists():
                raise FileNotFoundError(f"Fichier clé non trouvé: {key_path}")
            
            key_data = key_file.read_bytes()
            try:
                private_key = serialization.load_pem_private_key(
                    key_data,
                    password=password,
                    backend=default_backend()
                )
            except ValueError as e:
                raise ValueError(f"Impossible de charger la clé privée: {e}")

        # Valider le certificat si demandé
        if validate:
            is_valid, errors = self.validator.validate_certificate(cert)
            if not is_valid:
                raise ValueError(f"Certificat invalide: {', '.join(errors)}")

        # Extraire les métadonnées
        metadata = self._extract_metadata(cert, imported=True)

        # Sauvegarder
        if private_key:
            cert_id = self.storage.save_certificate(cert, private_key, metadata)
        else:
            # Si pas de clé, sauvegarder seulement le certificat
            cert_id = metadata["id"]
            cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            cert_file_path = self.storage.certs_dir / f"{cert_id}.pem"
            cert_file_path.write_bytes(cert_pem)
            os.chmod(cert_file_path, 0o644)
            
            # Mettre à jour les métadonnées
            all_metadata = self.storage._load_metadata()
            all_metadata[cert_id] = metadata
            self.storage._save_metadata(all_metadata)

        return cert_id

    def import_from_der(
        self,
        cert_path: str,
        key_path: Optional[str] = None,
        password: Optional[bytes] = None,
        validate: bool = True
    ) -> str:
        """
        Importe un certificat depuis un fichier DER.

        Args:
            cert_path: Chemin vers le fichier certificat DER
            key_path: Chemin vers le fichier clé privée DER (optionnel)
            password: Mot de passe pour déchiffrer la clé privée (optionnel)
            validate: Valider le certificat après import. Défaut: True

        Returns:
            ID du certificat importé
        """
        cert_file = Path(cert_path)
        if not cert_file.exists():
            raise FileNotFoundError(f"Fichier certificat non trouvé: {cert_path}")

        # Charger le certificat
        cert_data = cert_file.read_bytes()
        cert = x509.load_der_x509_certificate(cert_data, default_backend())

        # Charger la clé privée si fournie
        private_key = None
        if key_path:
            key_file = Path(key_path)
            if not key_file.exists():
                raise FileNotFoundError(f"Fichier clé non trouvé: {key_path}")
            
            key_data = key_file.read_bytes()
            try:
                private_key = serialization.load_der_private_key(
                    key_data,
                    password=password,
                    backend=default_backend()
                )
            except ValueError as e:
                raise ValueError(f"Impossible de charger la clé privée: {e}")

        # Valider le certificat si demandé
        if validate:
            is_valid, errors = self.validator.validate_certificate(cert)
            if not is_valid:
                raise ValueError(f"Certificat invalide: {', '.join(errors)}")

        # Extraire les métadonnées
        metadata = self._extract_metadata(cert, imported=True)

        # Sauvegarder
        if private_key:
            cert_id = self.storage.save_certificate(cert, private_key, metadata)
        else:
            # Si pas de clé, sauvegarder seulement le certificat
            cert_id = metadata["id"]
            cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            cert_file_path = self.storage.certs_dir / f"{cert_id}.pem"
            cert_file_path.write_bytes(cert_pem)
            os.chmod(cert_file_path, 0o644)
            
            # Mettre à jour les métadonnées
            all_metadata = self.storage._load_metadata()
            all_metadata[cert_id] = metadata
            self.storage._save_metadata(all_metadata)

        return cert_id

    def import_from_pkcs12(
        self,
        p12_path: str,
        password: Optional[bytes] = None,
        validate: bool = True
    ) -> str:
        """
        Importe un certificat depuis un fichier PKCS#12 (.p12, .pfx).

        Args:
            p12_path: Chemin vers le fichier PKCS#12
            password: Mot de passe pour déchiffrer le fichier PKCS#12
            validate: Valider le certificat après import. Défaut: True

        Returns:
            ID du certificat importé
        """
        p12_file = Path(p12_path)
        if not p12_file.exists():
            raise FileNotFoundError(f"Fichier PKCS#12 non trouvé: {p12_path}")

        # Charger le fichier PKCS#12
        p12_data = p12_file.read_bytes()
        
        try:
            from cryptography.hazmat.primitives.serialization import pkcs12
            private_key, cert, additional_certs = pkcs12.load_key_and_certificates(
                p12_data,
                password=password,
                backend=default_backend()
            )
        except ValueError as e:
            raise ValueError(f"Impossible de charger le fichier PKCS#12: {e}. Vérifiez le mot de passe.")

        if cert is None:
            raise ValueError("Aucun certificat trouvé dans le fichier PKCS#12")

        if private_key is None:
            raise ValueError("Aucune clé privée trouvée dans le fichier PKCS#12")

        # Valider le certificat si demandé
        if validate:
            is_valid, errors = self.validator.validate_certificate(cert)
            if not is_valid:
                raise ValueError(f"Certificat invalide: {', '.join(errors)}")

        # Extraire les métadonnées
        metadata = self._extract_metadata(cert, imported=True)

        # Sauvegarder
        cert_id = self.storage.save_certificate(cert, private_key, metadata)

        return cert_id

    def _extract_metadata(self, cert: x509.Certificate, imported: bool = False) -> Dict:
        """
        Extrait les métadonnées d'un certificat.

        Args:
            cert: Certificat X.509
            imported: Indique si le certificat a été importé

        Returns:
            Dictionnaire de métadonnées
        """
        # Extraire le CN
        common_name = None
        for attr in cert.subject:
            if attr.oid._name == "commonName":
                common_name = attr.value
                break

        # Extraire les autres champs
        subject_dict = {}
        for attr in cert.subject:
            subject_dict[attr.oid._name] = attr.value

        # Extraire les SAN
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

        # Déterminer le type de clé
        from cryptography.hazmat.primitives.asymmetric import rsa, ec
        public_key = cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            key_type = "RSA"
            key_size = public_key.key_size
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            key_type = "ECDSA"
            key_size = public_key.curve.key_size
        else:
            key_type = "UNKNOWN"
            key_size = None

        metadata = {
            "id": str(uuid.uuid4()),
            "common_name": common_name or "Unknown",
            "key_type": key_type,
            "key_size": key_size,
            "not_valid_before": cert.not_valid_before_utc.isoformat(),
            "not_valid_after": cert.not_valid_after_utc.isoformat(),
            "created": datetime.now(timezone.utc).isoformat(),
            "imported": imported,
            "imported_at": datetime.now(timezone.utc).isoformat() if imported else None,
        }

        # Ajouter les champs du sujet
        if "organizationName" in subject_dict:
            metadata["organization"] = subject_dict["organizationName"]
        if "organizationalUnitName" in subject_dict:
            metadata["organizational_unit"] = subject_dict["organizationalUnitName"]
        if "countryName" in subject_dict:
            metadata["country"] = subject_dict["countryName"]
        if "stateOrProvinceName" in subject_dict:
            metadata["state"] = subject_dict["stateOrProvinceName"]
        if "localityName" in subject_dict:
            metadata["locality"] = subject_dict["localityName"]
        if "emailAddress" in subject_dict:
            metadata["email"] = subject_dict["emailAddress"]

        if san_dns:
            metadata["san_dns"] = san_dns

        return metadata


class CertificateExporter:
    """Gestionnaire d'export de certificats."""

    def __init__(self, storage: Optional[SecureStorage] = None):
        """
        Initialise l'exporteur de certificats.

        Args:
            storage: Instance de SecureStorage. Si None, crée une nouvelle instance.
        """
        self.storage = storage or SecureStorage()
        self.key_manager = KeyManager()

    def export_to_pem(
        self,
        cert_id: str,
        output_path: str,
        include_key: bool = False,
        key_password: Optional[bytes] = None
    ) -> Tuple[str, Optional[str]]:
        """
        Exporte un certificat en format PEM.

        Args:
            cert_id: ID du certificat
            output_path: Chemin de sortie pour le certificat
            include_key: Inclure la clé privée. Défaut: False
            key_password: Mot de passe pour chiffrer la clé privée (optionnel)

        Returns:
            Tuple (chemin_certificat, chemin_clé_ou_None)
        """
        cert, metadata = self.storage.load_certificate(cert_id)
        private_key = self.storage.load_private_key(cert_id) if include_key else None

        # Exporter le certificat
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        cert_path = Path(output_path)
        cert_path.write_bytes(cert_pem)
        os.chmod(cert_path, 0o644)

        # Exporter la clé si demandée
        key_path = None
        if include_key and private_key:
            key_pem = self.key_manager.key_to_pem(private_key, key_password)
            key_path = cert_path.parent / f"{cert_path.stem}.key"
            key_path.write_bytes(key_pem)
            os.chmod(key_path, 0o600)

        return str(cert_path), str(key_path) if key_path else None

    def export_to_der(
        self,
        cert_id: str,
        output_path: str,
        include_key: bool = False,
        key_password: Optional[bytes] = None
    ) -> Tuple[str, Optional[str]]:
        """
        Exporte un certificat en format DER.

        Args:
            cert_id: ID du certificat
            output_path: Chemin de sortie pour le certificat
            include_key: Inclure la clé privée. Défaut: False
            key_password: Mot de passe pour chiffrer la clé privée (optionnel)

        Returns:
            Tuple (chemin_certificat, chemin_clé_ou_None)
        """
        cert, metadata = self.storage.load_certificate(cert_id)
        private_key = self.storage.load_private_key(cert_id) if include_key else None

        # Exporter le certificat
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        cert_path = Path(output_path)
        cert_path.write_bytes(cert_der)
        os.chmod(cert_path, 0o644)

        # Exporter la clé si demandée
        key_path = None
        if include_key and private_key:
            # La clé en DER nécessite un format spécifique
            key_der = private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(key_password) if key_password
                else serialization.NoEncryption()
            )
            key_path = cert_path.parent / f"{cert_path.stem}.key"
            key_path.write_bytes(key_der)
            os.chmod(key_path, 0o600)

        return str(cert_path), str(key_path) if key_path else None

    def export_to_pkcs12(
        self,
        cert_id: str,
        output_path: str,
        password: Optional[bytes] = None
    ) -> str:
        """
        Exporte un certificat en format PKCS#12.

        Args:
            cert_id: ID du certificat
            output_path: Chemin de sortie pour le fichier PKCS#12
            password: Mot de passe pour protéger le fichier PKCS#12

        Returns:
            Chemin du fichier exporté
        """
        cert, metadata = self.storage.load_certificate(cert_id)
        private_key = self.storage.load_private_key(cert_id)

        if private_key is None:
            raise ValueError("Aucune clé privée trouvée pour ce certificat")

        # Créer le fichier PKCS#12
        from cryptography.hazmat.primitives.serialization import pkcs12
        p12_data = pkcs12.serialize_key_and_certificates(
            name=metadata.get("common_name", "certificate").encode("utf-8"),
            key=private_key,
            cert=cert,
            cas=None,  # Pas de CA pour l'instant
            encryption_algorithm=serialization.BestAvailableEncryption(password) if password
            else serialization.NoEncryption()
        )

        p12_path = Path(output_path)
        p12_path.write_bytes(p12_data)
        os.chmod(p12_path, 0o600)

        return str(p12_path)


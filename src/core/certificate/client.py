"""Génération de certificats client pour mutual TLS (mTLS)."""

import uuid
from datetime import datetime, timedelta
from typing import Optional, List, Dict
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

from ..key import KeyManager
from ..validation.domain import DomainValidator


class ClientCertificateManager:
    """Gestionnaire de certificats client pour mutual TLS."""

    def __init__(self):
        self.key_manager = KeyManager()

    def generate_client_cert(
        self,
        common_name: str,
        key_type: str = "RSA",
        key_size: int = 2048,
        validity_days: int = 365,
        country: Optional[str] = None,
        state: Optional[str] = None,
        locality: Optional[str] = None,
        organization: Optional[str] = None,
        organizational_unit: Optional[str] = None,
        email: Optional[str] = None,
        ca_cert: Optional[x509.Certificate] = None,
        ca_key: Optional[rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey] = None,
    ) -> tuple[x509.Certificate, rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey, Dict]:
        """
        Génère un certificat client pour mutual TLS.

        Args:
            common_name: Nom commun (CN) du certificat client
            key_type: Type de clé ("RSA" ou "ECDSA"). Défaut: RSA
            key_size: Taille de la clé (pour RSA: 2048, 3072, 4096). Défaut: 2048
            validity_days: Nombre de jours de validité. Défaut: 365
            country: Code pays (ex: "FR")
            state: État ou province
            locality: Ville
            organization: Organisation
            organizational_unit: Unité organisationnelle
            email: Adresse email
            ca_cert: Certificat CA pour signer le certificat client (optionnel)
            ca_key: Clé privée CA pour signer le certificat client (optionnel)

        Returns:
            Tuple (certificat, clé privée, métadonnées)
        """
        # Générer la clé privée du client
        if key_type.upper() == "RSA":
            private_key = self.key_manager.generate_rsa_key(key_size)
        elif key_type.upper() == "ECDSA":
            private_key = self.key_manager.generate_ec_key()
        else:
            raise ValueError(f"Type de clé invalide: {key_type}. Utilisez RSA ou ECDSA")

        # Construire le nom du sujet
        name_attributes = []
        if country:
            name_attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
        if state:
            name_attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
        if locality:
            name_attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))
        if organization:
            name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
        if organizational_unit:
            name_attributes.append(
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit)
            )
        name_attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
        if email:
            name_attributes.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))

        subject = x509.Name(name_attributes)

        # Déterminer l'émetteur (CA ou auto-signé)
        if ca_cert and ca_key:
            issuer = ca_cert.subject
            signing_key = ca_key
        else:
            # Auto-signé si pas de CA fournie
            issuer = subject
            signing_key = private_key

        # Construire le certificat
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow().replace(tzinfo=None))
            .not_valid_after((datetime.utcnow() + timedelta(days=validity_days)).replace(tzinfo=None))
        )

        # Ajouter les extensions spécifiques aux certificats client
        extensions = []

        # Key Usage - Certificats client ont besoin de digitalSignature et keyEncipherment
        extensions.append(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False,
            )
        )

        # Extended Key Usage - CLIENT_AUTH est essentiel pour les certificats client
        extensions.append(
            x509.ExtendedKeyUsage([
                x509.ExtendedKeyUsageOID.CLIENT_AUTH,
            ])
        )

        # Basic Constraints - Les certificats client ne sont pas des CA
        extensions.append(
            x509.BasicConstraints(ca=False, path_length=None)
        )

        # Ajouter toutes les extensions
        for ext in extensions:
            builder = builder.add_extension(ext, critical=False)

        # Signer le certificat
        cert = builder.sign(signing_key, hashes.SHA256(), default_backend())

        # Métadonnées
        metadata = {
            "id": str(uuid.uuid4()),
            "common_name": common_name,
            "key_type": key_type,
            "key_size": key_size if key_type.upper() == "RSA" else None,
            "validity_days": validity_days,
            "created": datetime.utcnow().isoformat(),
            "not_valid_before": cert.not_valid_before_utc.isoformat(),
            "not_valid_after": cert.not_valid_after_utc.isoformat(),
            "serial_number": str(cert.serial_number),
            "certificate_type": "client",
            "signed_by_ca": ca_cert is not None,
        }

        return cert, private_key, metadata

    def export_for_browser(
        self,
        cert: x509.Certificate,
        private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
        password: Optional[str] = None,
    ) -> bytes:
        """
        Exporte un certificat client au format PKCS#12 pour import dans les navigateurs.

        Args:
            cert: Certificat client
            private_key: Clé privée du client
            password: Mot de passe pour protéger le fichier PKCS#12 (optionnel)

        Returns:
            Données PKCS#12 encodées
        """
        from cryptography.hazmat.primitives.serialization import pkcs12

        # Générer un nom pour le certificat (utiliser le CN)
        try:
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except (IndexError, AttributeError):
            cn = "client-certificate"

        # Créer le fichier PKCS#12
        if password:
            encryption = serialization.BestAvailableEncryption(password.encode('utf-8'))
        else:
            # Pas de chiffrement si pas de mot de passe
            encryption = serialization.NoEncryption()
        
        p12_data = pkcs12.serialize_key_and_certificates(
            name=cn.encode('utf-8'),
            key=private_key,
            cert=cert,
            cas=None,  # Pas de chaîne CA pour l'export navigateur
            encryption_algorithm=encryption,
        )

        return p12_data


"""Gestion des certificats X.509."""

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


class CertificateManager:
    """Gestionnaire de certificats X.509."""

    def __init__(self):
        self.key_manager = KeyManager()

    def generate_self_signed_cert(
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
        san_dns: Optional[List[str]] = None,
        san_ip: Optional[List[str]] = None,
    ) -> tuple[x509.Certificate, rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey, Dict]:
        """
        Génère un certificat auto-signé.

        Args:
            common_name: Nom commun (CN) du certificat
            key_type: Type de clé ("RSA" ou "ECDSA"). Défaut: RSA
            key_size: Taille de la clé (pour RSA: 2048, 3072, 4096). Défaut: 2048
            validity_days: Nombre de jours de validité. Défaut: 365
            country: Code pays (ex: "FR")
            state: État ou province
            locality: Ville
            organization: Organisation
            organizational_unit: Unité organisationnelle
            email: Adresse email
            san_dns: Liste de noms DNS pour Subject Alternative Name
            san_ip: Liste d'adresses IP pour Subject Alternative Name

        Returns:
            Tuple (certificat, clé privée, métadonnées)
        """
        # Générer la clé privée
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

        subject = issuer = x509.Name(name_attributes)

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

        # Ajouter les extensions
        extensions = []

        # Key Usage
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

        # Extended Key Usage (si nécessaire)
        extensions.append(
            x509.ExtendedKeyUsage([
                x509.ExtendedKeyUsageOID.SERVER_AUTH,
                x509.ExtendedKeyUsageOID.CLIENT_AUTH,
            ])
        )

        # Subject Alternative Name
        san_list = []
        if san_dns:
            # Valider les domaines (y compris wildcards)
            is_valid, invalid_domains = DomainValidator.validate_domains(san_dns)
            if not is_valid:
                raise ValueError(f"Domaines invalides: {', '.join(invalid_domains)}")
            san_list.extend([x509.DNSName(dns) for dns in san_dns])
        if san_ip:
            san_list.extend([x509.IPAddress(ip) for ip in san_ip])
        if not san_list:
            # Valider le CN s'il est fourni
            if not DomainValidator.is_valid_domain(common_name) and not DomainValidator.is_wildcard(common_name):
                raise ValueError(f"Nom commun invalide: {common_name}")
            # Ajouter le CN par défaut
            san_list.append(x509.DNSName(common_name))

        extensions.append(x509.SubjectAlternativeName(san_list))

        # Basic Constraints
        extensions.append(
            x509.BasicConstraints(ca=False, path_length=None)
        )

        # Ajouter toutes les extensions
        for ext in extensions:
            builder = builder.add_extension(ext, critical=False)

        # Signer le certificat
        cert = builder.sign(private_key, hashes.SHA256(), default_backend())

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
            "is_wildcard": DomainValidator.is_wildcard(common_name) or (
                san_dns and any(DomainValidator.is_wildcard(dns) for dns in san_dns)
            ),
            "certificate_type": "server",  # Par défaut, certificat serveur
        }

        return cert, private_key, metadata

    def generate_csr(
        self,
        common_name: str,
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
    ) -> tuple[x509.CertificateSigningRequest, rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey, Dict]:
        """
        Génère une Certificate Signing Request (CSR).

        Args:
            common_name: Nom commun (CN)
            key_type: Type de clé ("RSA" ou "ECDSA")
            key_size: Taille de la clé (pour RSA)
            country: Code pays
            state: État ou province
            locality: Ville
            organization: Organisation
            organizational_unit: Unité organisationnelle
            email: Adresse email
            san_dns: Liste de noms DNS pour SAN
            san_ip: Liste d'adresses IP pour SAN

        Returns:
            Tuple (CSR, clé privée, métadonnées)
        """
        # Générer la clé privée
        if key_type.upper() == "RSA":
            private_key = self.key_manager.generate_rsa_key(key_size)
        elif key_type.upper() == "ECDSA":
            private_key = self.key_manager.generate_ec_key()
        else:
            raise ValueError(f"Type de clé invalide: {key_type}")

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

        # Construire la CSR
        builder = x509.CertificateSigningRequestBuilder().subject_name(subject)

        # Ajouter les extensions
        extensions = []

        # Key Usage
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

        # Subject Alternative Name
        san_list = []
        if san_dns:
            # Valider les domaines (y compris wildcards)
            is_valid, invalid_domains = DomainValidator.validate_domains(san_dns)
            if not is_valid:
                raise ValueError(f"Domaines invalides: {', '.join(invalid_domains)}")
            san_list.extend([x509.DNSName(dns) for dns in san_dns])
        if san_ip:
            san_list.extend([x509.IPAddress(ip) for ip in san_ip])
        if not san_list:
            # Valider le CN s'il est fourni
            if not DomainValidator.is_valid_domain(common_name) and not DomainValidator.is_wildcard(common_name):
                raise ValueError(f"Nom commun invalide: {common_name}")
            san_list.append(x509.DNSName(common_name))

        extensions.append(x509.SubjectAlternativeName(san_list))

        # Ajouter les extensions
        for ext in extensions:
            builder = builder.add_extension(ext, critical=False)

        # Signer la CSR
        csr = builder.sign(private_key, hashes.SHA256(), default_backend())

        # Métadonnées
        metadata = {
            "id": str(uuid.uuid4()),
            "common_name": common_name,
            "key_type": key_type,
            "key_size": key_size if key_type.upper() == "RSA" else None,
            "created": datetime.utcnow().isoformat(),
        }

        return csr, private_key, metadata

    @staticmethod
    def cert_to_pem(cert: x509.Certificate) -> bytes:
        """
        Convertit un certificat en format PEM.

        Args:
            cert: Certificat à convertir

        Returns:
            Certificat au format PEM (bytes)
        """
        return cert.public_bytes(serialization.Encoding.PEM)

    @staticmethod
    def pem_to_cert(pem_data: bytes) -> x509.Certificate:
        """
        Charge un certificat depuis un format PEM.

        Args:
            pem_data: Données PEM du certificat

        Returns:
            Certificat X.509
        """
        return x509.load_pem_x509_certificate(pem_data, default_backend())


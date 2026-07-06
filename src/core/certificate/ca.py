"""Génération de CA et signature de certificats."""

import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from ..key import KeyManager
from ..validation.domain import DomainValidator


class CAGenerator:
    """Génération de certificats CA et signature par CA locale."""

    def __init__(self):
        self.key_manager = KeyManager()

    def generate_ca(
        self,
        common_name: str,
        key_type: str = "RSA",
        key_size: int = 2048,
        validity_days: int = 3650,
        is_root: bool = True,
        parent_cert: Optional[x509.Certificate] = None,
        parent_key: Optional[rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey] = None,
        country: Optional[str] = None,
        state: Optional[str] = None,
        locality: Optional[str] = None,
        organization: Optional[str] = None,
        organizational_unit: Optional[str] = None,
        email: Optional[str] = None,
    ) -> Tuple[x509.Certificate, rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey, Dict]:
        """
        Génère un certificat d'autorité de certification (racine ou intermédiaire).

        Args:
            common_name: CN de la CA
            is_root: True pour CA racine, False pour CA intermédiaire
            parent_cert: Certificat CA parent (requis si intermédiaire)
            parent_key: Clé privée du parent (requis si intermédiaire)
        """
        if not is_root and (parent_cert is None or parent_key is None):
            raise ValueError("parent_cert et parent_key sont requis pour une CA intermédiaire")

        if key_type.upper() == "RSA":
            private_key = self.key_manager.generate_rsa_key(key_size)
        elif key_type.upper() == "ECDSA":
            private_key = self.key_manager.generate_ec_key()
        else:
            raise ValueError(f"Type de clé invalide: {key_type}")

        name_attributes = self._build_name_attributes(
            common_name, country, state, locality, organization, organizational_unit, email
        )
        subject = x509.Name(name_attributes)
        issuer = subject if is_root else parent_cert.subject
        signing_key = private_key if is_root else parent_key

        now = datetime.utcnow().replace(tzinfo=None)
        path_length = 1 if is_root else 0

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=validity_days))
        )

        extensions = [
            x509.BasicConstraints(ca=True, path_length=path_length),
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False,
            ),
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
        ]

        if not is_root:
            extensions.append(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(parent_cert.public_key())
            )

        for ext in extensions:
            builder = builder.add_extension(ext, critical=True)

        cert = builder.sign(signing_key, hashes.SHA256(), default_backend())

        metadata = {
            "id": str(uuid.uuid4()),
            "common_name": common_name,
            "key_type": key_type,
            "key_size": key_size if key_type.upper() == "RSA" else None,
            "validity_days": validity_days,
            "is_root": is_root,
            "is_ca": True,
            "has_private_key": True,
            "created": datetime.utcnow().isoformat(),
            "not_valid_before": cert.not_valid_before_utc.isoformat(),
            "not_valid_after": cert.not_valid_after_utc.isoformat(),
        }
        if not is_root:
            metadata["parent_issuer_cn"] = self._extract_cn(parent_cert)

        return cert, private_key, metadata

    def sign_csr(
        self,
        csr: x509.CertificateSigningRequest,
        ca_cert: x509.Certificate,
        ca_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
        validity_days: int = 365,
    ) -> x509.Certificate:
        """Signe une CSR avec une CA locale."""
        now = datetime.utcnow().replace(tzinfo=None)
        builder = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=validity_days))
        )

        has_basic_constraints = False
        has_eku = False
        for ext in csr.extensions:
            if ext.oid == ExtensionOID.BASIC_CONSTRAINTS:
                has_basic_constraints = True
            if ext.oid == ExtensionOID.EXTENDED_KEY_USAGE:
                has_eku = True
            builder = builder.add_extension(ext.value, critical=ext.critical)

        if not has_basic_constraints:
            builder = builder.add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )

        if not has_eku:
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )

        return builder.sign(ca_key, hashes.SHA256(), default_backend())

    def generate_signed_server_certificate(
        self,
        common_name: str,
        ca_cert: x509.Certificate,
        ca_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
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
        private_key: Optional[rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey] = None,
    ) -> Tuple[x509.Certificate, rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey, Dict]:
        """Génère un certificat serveur signé par une CA locale."""
        if private_key is None:
            if key_type.upper() == "RSA":
                private_key = self.key_manager.generate_rsa_key(key_size)
            elif key_type.upper() == "ECDSA":
                private_key = self.key_manager.generate_ec_key()
            else:
                raise ValueError(f"Type de clé invalide: {key_type}")
        elif key_type.upper() == "RSA" and not isinstance(private_key, rsa.RSAPrivateKey):
            raise ValueError("La clé fournie ne correspond pas au type RSA")
        elif key_type.upper() == "ECDSA" and not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise ValueError("La clé fournie ne correspond pas au type ECDSA")

        name_attributes = self._build_name_attributes(
            common_name, country, state, locality, organization, organizational_unit, email
        )
        subject = x509.Name(name_attributes)

        now = datetime.utcnow().replace(tzinfo=None)
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=validity_days))
        )

        san_list = self._build_san_list(common_name, san_dns, san_ip)
        extensions = [
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
            ),
            x509.ExtendedKeyUsage([
                x509.ExtendedKeyUsageOID.SERVER_AUTH,
                x509.ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            x509.SubjectAlternativeName(san_list),
            x509.BasicConstraints(ca=False, path_length=None),
        ]

        for ext in extensions:
            builder = builder.add_extension(ext, critical=False)

        cert = builder.sign(ca_key, hashes.SHA256(), default_backend())

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
            "certificate_type": "server",
            "signed_by_ca": True,
            "is_wildcard": DomainValidator.is_wildcard(common_name) or (
                san_dns and any(DomainValidator.is_wildcard(d) for d in san_dns)
            ),
        }
        if organization:
            metadata["organization"] = organization
        if country:
            metadata["country"] = country

        return cert, private_key, metadata

    @staticmethod
    def _build_name_attributes(
        common_name: str,
        country: Optional[str],
        state: Optional[str],
        locality: Optional[str],
        organization: Optional[str],
        organizational_unit: Optional[str],
        email: Optional[str],
    ) -> list:
        attrs = []
        if country:
            attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
        if state:
            attrs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
        if locality:
            attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))
        if organization:
            attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
        if organizational_unit:
            attrs.append(
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit)
            )
        attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
        if email:
            attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))
        return attrs

    @staticmethod
    def _build_san_list(
        common_name: str,
        san_dns: Optional[List[str]],
        san_ip: Optional[List[str]],
    ) -> list:
        san_list = []
        if san_dns:
            is_valid, invalid = DomainValidator.validate_domains(san_dns)
            if not is_valid:
                raise ValueError(f"Domaines invalides: {', '.join(invalid)}")
            san_list.extend(x509.DNSName(d) for d in san_dns)
            if common_name not in san_dns:
                san_list.insert(0, x509.DNSName(common_name))
        if san_ip:
            san_list.extend(x509.IPAddress(ip) for ip in san_ip)
        if not san_list:
            if not DomainValidator.is_valid_domain(common_name) and not DomainValidator.is_wildcard(
                common_name
            ):
                raise ValueError(f"Nom commun invalide: {common_name}")
            san_list.append(x509.DNSName(common_name))
        return san_list

    @staticmethod
    def _extract_cn(cert: x509.Certificate) -> str:
        try:
            return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except IndexError:
            return "Unknown"

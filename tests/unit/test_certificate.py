"""Tests pour le module certificate."""

import pytest
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID

from src.core.certificate import CertificateManager


class TestCertificateManager:
    """Tests pour CertificateManager."""

    def test_generate_self_signed_cert_basic(self):
        """Test génération certificat auto-signé basique."""
        manager = CertificateManager()
        cert, private_key, metadata = manager.generate_self_signed_cert(
            common_name="test.example.com",
            validity_days=365
        )

        assert isinstance(cert, x509.Certificate)
        assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "test.example.com"
        assert cert.issuer == cert.subject  # Auto-signé
        assert metadata["common_name"] == "test.example.com"
        assert metadata["validity_days"] == 365
        assert "id" in metadata

    def test_generate_self_signed_cert_with_details(self):
        """Test génération certificat avec détails complets."""
        manager = CertificateManager()
        cert, _, metadata = manager.generate_self_signed_cert(
            common_name="example.com",
            country="FR",
            state="Ile-de-France",
            locality="Paris",
            organization="Test Org",
            organizational_unit="IT",
            email="test@example.com",
            validity_days=730
        )

        subject_dict = dict(cert.subject)
        assert subject_dict.get(NameOID.COUNTRY_NAME) == "FR"
        assert subject_dict.get(NameOID.STATE_OR_PROVINCE_NAME) == "Ile-de-France"
        assert subject_dict.get(NameOID.LOCALITY_NAME) == "Paris"
        assert subject_dict.get(NameOID.ORGANIZATION_NAME) == "Test Org"

    def test_generate_self_signed_cert_with_san(self):
        """Test génération certificat avec SAN."""
        manager = CertificateManager()
        cert, _, _ = manager.generate_self_signed_cert(
            common_name="example.com",
            san_dns=["www.example.com", "api.example.com"]
        )

        # Vérifier les extensions SAN
        san_ext = cert.extensions.get_extension_for_oid(
            x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        san_names = [name.value for name in san_ext.value if isinstance(name, x509.DNSName)]
        assert "example.com" in san_names
        assert "www.example.com" in san_names
        assert "api.example.com" in san_names

    def test_generate_csr(self):
        """Test génération CSR."""
        manager = CertificateManager()
        csr, private_key, metadata = manager.generate_csr(
            common_name="test.example.com"
        )

        assert isinstance(csr, x509.CertificateSigningRequest)
        assert csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "test.example.com"
        assert metadata["common_name"] == "test.example.com"
        assert "id" in metadata

    def test_cert_to_pem(self):
        """Test conversion certificat en PEM."""
        manager = CertificateManager()
        cert, _, _ = manager.generate_self_signed_cert("test.com")
        pem = manager.cert_to_pem(cert)

        assert isinstance(pem, bytes)
        assert b"BEGIN CERTIFICATE" in pem

    def test_pem_to_cert(self):
        """Test chargement certificat depuis PEM."""
        manager = CertificateManager()
        cert, _, _ = manager.generate_self_signed_cert("test.com")
        pem = manager.cert_to_pem(cert)
        loaded_cert = manager.pem_to_cert(pem)

        assert isinstance(loaded_cert, x509.Certificate)
        assert loaded_cert.serial_number == cert.serial_number

    def test_certificate_validity_dates(self):
        """Test dates de validité du certificat."""
        manager = CertificateManager()
        cert, _, _ = manager.generate_self_signed_cert(
            "test.com",
            validity_days=30
        )

        now = datetime.utcnow()
        assert cert.not_valid_before <= now
        assert cert.not_valid_after >= now + timedelta(days=29)
        assert cert.not_valid_after <= now + timedelta(days=31)


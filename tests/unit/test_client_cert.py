"""Tests pour les certificats client (mTLS)."""

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from src.core.certificate.client import ClientCertificateManager


class TestClientCertificateManager:
    """Tests pour ClientCertificateManager."""

    def test_generate_self_signed_client_cert(self):
        mgr = ClientCertificateManager()
        cert, key, meta = mgr.generate_client_cert("client.example.com")

        assert isinstance(cert, x509.Certificate)
        assert meta["certificate_type"] == "client"
        assert meta["signed_by_ca"] is False
        assert key is not None

    def test_generate_ca_signed_client_cert(self):
        from src.core.certificate import CertificateManager

        ca_mgr = CertificateManager()
        ca_cert, ca_key, _ = ca_mgr.generate_self_signed_cert("ca.local")

        mgr = ClientCertificateManager()
        cert, key, meta = mgr.generate_client_cert(
            "user.local", ca_cert=ca_cert, ca_key=ca_key, organization="ACME"
        )

        assert meta["signed_by_ca"] is True
        assert cert.issuer == ca_cert.subject

    def test_client_cert_has_client_auth_eku(self):
        cert, _, _ = ClientCertificateManager().generate_client_cert("mtls.example.com")
        eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
        assert x509.ExtendedKeyUsageOID.CLIENT_AUTH in eku.value

    def test_client_cert_not_ca(self):
        cert, _, _ = ClientCertificateManager().generate_client_cert("mtls.example.com")
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        assert bc.value.ca is False

    def test_export_for_browser_pkcs12(self):
        mgr = ClientCertificateManager()
        cert, key, _ = mgr.generate_client_cert("browser.example.com")
        p12_data = mgr.export_for_browser(cert, key, password="test123")
        assert isinstance(p12_data, bytes)
        assert len(p12_data) > 0

    def test_invalid_key_type_raises(self):
        with pytest.raises(ValueError, match="Type de clé invalide"):
            ClientCertificateManager().generate_client_cert("x.com", key_type="DSA")

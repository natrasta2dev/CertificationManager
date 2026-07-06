"""Tests pour le module ca_manager."""

from datetime import datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from src.core.ca_manager import CAManager
from src.core.certificate.client import ClientCertificateManager


def _make_ca_certificate(common_name: str = "ca.local"):
    """Génère un certificat CA valide (BasicConstraints ca=True)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
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
            critical=True,
        )
        .sign(key, hashes.SHA256(), default_backend())
    )
    return cert, key


class TestCAManager:
    """Tests pour CAManager."""

    def test_add_and_list_ca(self, temp_storage):
        ca_cert, _ = _make_ca_certificate("ca-root.local")
        manager = CAManager(temp_storage)

        ca_id = manager.add_ca_certificate(ca_cert, name="Test CA", is_root=True)
        cas = manager.list_ca_certificates()
        assert len(cas) == 1
        assert cas[0]["id"] == ca_id
        assert cas[0]["name"] == "Test CA"

    def test_get_and_delete_ca(self, temp_storage):
        ca_cert, _ = _make_ca_certificate("ca-delete.local")
        manager = CAManager(temp_storage)
        ca_id = manager.add_ca_certificate(ca_cert)

        loaded, meta = manager.get_ca_certificate(ca_id)
        assert meta["common_name"] == "ca-delete.local"

        manager.delete_ca_certificate(ca_id)
        with pytest.raises(FileNotFoundError):
            manager.get_ca_certificate(ca_id)

    def test_reject_non_ca_certificate(self, temp_storage):
        client_mgr = ClientCertificateManager()
        cert, _, _ = client_mgr.generate_client_cert("not-a-ca.example.com")
        manager = CAManager(temp_storage)

        with pytest.raises(ValueError, match="autorité de certification"):
            manager.add_ca_certificate(cert)

    def test_import_ca_from_file(self, temp_storage, tmp_path):
        ca_cert, _ = _make_ca_certificate("ca-file.local")
        from cryptography.hazmat.primitives import serialization
        cert_path = tmp_path / "ca.pem"
        cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

        ca_id = CAManager(temp_storage).import_ca_from_file(str(cert_path), name="Imported CA")
        loaded, meta = CAManager(temp_storage).get_ca_certificate(ca_id)
        assert meta["name"] == "Imported CA"
        assert loaded.subject == ca_cert.subject

    def test_verify_certificate_chain_success(self, temp_storage):
        ca_cert, ca_key = _make_ca_certificate("chain-ca.local")
        manager = CAManager(temp_storage)
        ca_id = manager.add_ca_certificate(ca_cert)

        client_mgr = ClientCertificateManager()
        client_cert, _, _ = client_mgr.generate_client_cert(
            "client.example.com", ca_cert=ca_cert, ca_key=ca_key
        )

        valid, errors = manager.verify_certificate_chain(client_cert, ca_cert_ids=[ca_id])
        assert valid is True
        assert errors == []

    def test_verify_certificate_chain_no_trusted_ca(self, temp_storage):
        from src.core.certificate import CertificateManager

        cert, _, _ = CertificateManager().generate_self_signed_cert("orphan.example.com")
        manager = CAManager(temp_storage)

        valid, errors = manager.verify_certificate_chain(cert)
        assert valid is False
        assert any("Aucune CA" in e for e in errors)

    def test_verify_certificate_chain_wrong_issuer(self, temp_storage):
        ca_cert, ca_key = _make_ca_certificate("real-ca.local")
        other_ca, other_key = _make_ca_certificate("other-ca.local")
        manager = CAManager(temp_storage)
        ca_id = manager.add_ca_certificate(ca_cert)

        client_mgr = ClientCertificateManager()
        client_cert, _, _ = client_mgr.generate_client_cert(
            "client.example.com", ca_cert=other_ca, ca_key=other_key
        )

        valid, errors = manager.verify_certificate_chain(client_cert, ca_cert_ids=[ca_id])
        assert valid is False

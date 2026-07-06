"""Tests pour la génération de CA et la signature."""

import pytest
from cryptography import x509

from src.core.ca_manager import CAManager
from src.core.certificate import CertificateManager
from src.core.renewal import CertificateRenewal


class TestCAGeneration:
    """Tests génération et signature CA."""

    def test_generate_root_ca(self, temp_storage):
        manager = CAManager(temp_storage)
        ca_id = manager.generate_ca("root-ca.local", name="Root Test")
        cas = manager.list_ca_certificates()
        assert len(cas) == 1
        assert cas[0]["has_private_key"] is True
        assert cas[0]["is_root"] is True
        assert manager.get_ca_private_key(ca_id) is not None

    def test_generate_intermediate_ca(self, temp_storage):
        manager = CAManager(temp_storage)
        root_id = manager.generate_ca("root.local")
        inter_id = manager.generate_ca(
            "intermediate.local", is_root=False, parent_ca_id=root_id
        )
        inter_cert, inter_meta = manager.get_ca_certificate(inter_id)
        root_cert, _ = manager.get_ca_certificate(root_id)
        assert inter_meta["parent_ca_id"] == root_id
        assert inter_cert.issuer == root_cert.subject

    def test_sign_server_certificate(self, temp_storage):
        manager = CAManager(temp_storage)
        ca_id = manager.generate_ca("signing-ca.local")
        cert_id = manager.sign_server_certificate(
            ca_id, "server.example.com", validity_days=90
        )
        cert, meta = temp_storage.load_certificate(cert_id)
        assert meta["signed_by_ca"] is True
        assert meta["ca_id"] == ca_id
        ca_cert, _ = manager.get_ca_certificate(ca_id)
        assert cert.issuer == ca_cert.subject

    def test_sign_csr_from_storage(self, temp_storage):
        cert_mgr = CertificateManager()
        csr, private_key, csr_meta = cert_mgr.generate_csr("csr.example.com")
        csr_id = temp_storage.save_csr(csr, private_key, csr_meta)

        manager = CAManager(temp_storage)
        ca_id = manager.generate_ca("csr-ca.local")
        cert_id = manager.sign_csr_from_storage(ca_id, csr_id)

        cert, meta = temp_storage.load_certificate(cert_id)
        assert meta["common_name"] == "csr.example.com"
        assert meta["signed_by_ca"] is True
        assert isinstance(cert, x509.Certificate)

    def test_renew_ca_signed_certificate(self, temp_storage):
        manager = CAManager(temp_storage)
        ca_id = manager.generate_ca("renew-ca.local")
        cert_id = manager.sign_server_certificate(
            ca_id, "renew-ca-signed.example.com", validity_days=60
        )

        renewal = CertificateRenewal(temp_storage)
        can_renew, msg = renewal.can_renew(cert_id)
        assert can_renew is True, msg

        new_id, new_meta = renewal.renew_certificate(cert_id, archive_old=True)
        assert new_meta["signed_by_ca"] is True
        assert new_meta["ca_id"] == ca_id
        assert new_id != cert_id

    def test_intermediate_requires_parent(self, temp_storage):
        manager = CAManager(temp_storage)
        with pytest.raises(ValueError, match="parent_ca_id"):
            manager.generate_ca("orphan.local", is_root=False)

    def test_sign_without_ca_key_fails(self, temp_storage, tmp_path):
        from tests.unit.test_ca_manager import _make_ca_certificate

        manager = CAManager(temp_storage)
        ca_cert, _ = _make_ca_certificate("external-ca.local")
        ca_id = manager.add_ca_certificate(ca_cert)

        with pytest.raises(ValueError, match="clé privée"):
            manager.sign_server_certificate(ca_id, "fail.example.com")

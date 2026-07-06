"""Tests pour le module letsencrypt."""

from unittest.mock import MagicMock, patch

import pytest

from src.core.certificate import CertificateManager
from src.core.letsencrypt import LetsEncryptManager


class TestLetsEncryptManager:
    """Tests pour LetsEncryptManager (mocks certbot)."""

    def test_check_certbot_available_true(self, temp_storage):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert LetsEncryptManager(temp_storage).check_certbot_available() is True

    def test_check_certbot_available_false(self, temp_storage):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            assert LetsEncryptManager(temp_storage).check_certbot_available() is False

    def test_obtain_without_domains_raises(self, temp_storage):
        manager = LetsEncryptManager(temp_storage)
        with patch.object(manager, "check_certbot_available", return_value=True):
            with pytest.raises(ValueError, match="domaine"):
                manager.obtain_certificate(domains=[])

    def test_obtain_without_certbot_raises(self, temp_storage):
        manager = LetsEncryptManager(temp_storage)
        with patch.object(manager, "check_certbot_available", return_value=False):
            with pytest.raises(RuntimeError, match="certbot"):
                manager.obtain_certificate(domains=["example.com"])

    def test_list_letsencrypt_certificates(self, temp_storage):
        manager = CertificateManager()
        cert, key, meta = manager.generate_self_signed_cert("le.example.com")
        meta["letsencrypt"] = True
        temp_storage.save_certificate(cert, key, meta)

        le_certs = LetsEncryptManager(temp_storage).list_letsencrypt_certificates()
        assert len(le_certs) == 1
        assert le_certs[0]["common_name"] == "le.example.com"

    def test_renew_certificate_not_letsencrypt(self, temp_storage):
        manager = CertificateManager()
        cert, key, meta = manager.generate_self_signed_cert("normal.example.com")
        cert_id = temp_storage.save_certificate(cert, key, meta)

        le_mgr = LetsEncryptManager(temp_storage)
        with patch.object(le_mgr, "check_certbot_available", return_value=True):
            with pytest.raises(ValueError, match="Let's Encrypt"):
                le_mgr.renew_certificate(cert_id)

    def test_renew_all_expiring_skips_non_le(self, temp_storage):
        manager = CertificateManager()
        cert, key, meta = manager.generate_self_signed_cert("soon.example.com", validity_days=3)
        temp_storage.save_certificate(cert, key, meta)

        le_mgr = LetsEncryptManager(temp_storage)
        renewed = le_mgr.renew_all_expiring(days_threshold=30)
        assert renewed == []

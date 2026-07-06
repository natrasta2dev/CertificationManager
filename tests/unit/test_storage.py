"""Tests pour le module storage."""

import os

import pytest
from cryptography import x509

from src.core.certificate import CertificateManager
from src.core.storage import SecureStorage


class TestSecureStorage:
  """Tests pour SecureStorage."""

  def test_save_and_load_certificate(self, temp_storage):
      manager = CertificateManager()
      cert, private_key, metadata = manager.generate_self_signed_cert("test.example.com")

      cert_id = temp_storage.save_certificate(cert, private_key, metadata)
      loaded_cert, loaded_meta = temp_storage.load_certificate(cert_id)
      loaded_key = temp_storage.load_private_key(cert_id)

      assert isinstance(loaded_cert, x509.Certificate)
      assert loaded_meta["common_name"] == "test.example.com"
      assert loaded_key is not None

  def test_list_certificates_timezone_aware(self, temp_storage):
      manager = CertificateManager()
      cert, private_key, metadata = manager.generate_self_signed_cert("list.example.com")
      temp_storage.save_certificate(cert, private_key, metadata)

      certificates = temp_storage.list_certificates()
      assert len(certificates) == 1
      assert "is_expired" in certificates[0]
      assert "days_until_expiry" in certificates[0]
      assert certificates[0]["is_expired"] is False

  def test_delete_certificate(self, temp_storage):
      manager = CertificateManager()
      cert, private_key, metadata = manager.generate_self_signed_cert("delete.example.com")
      cert_id = temp_storage.save_certificate(cert, private_key, metadata)

      temp_storage.delete_certificate(cert_id)

      with pytest.raises(FileNotFoundError):
          temp_storage.load_certificate(cert_id)

  def test_update_metadata(self, temp_storage):
      manager = CertificateManager()
      cert, private_key, metadata = manager.generate_self_signed_cert("meta.example.com")
      cert_id = temp_storage.save_certificate(cert, private_key, metadata)

      temp_storage.update_metadata(cert_id, {"organization": "ACME Corp"})
      _, updated = temp_storage.load_certificate(cert_id)
      assert updated["organization"] == "ACME Corp"

  def test_secure_file_permissions(self, temp_storage):
      manager = CertificateManager()
      cert, private_key, metadata = manager.generate_self_signed_cert("perms.example.com")
      cert_id = temp_storage.save_certificate(cert, private_key, metadata)

      cert_file = temp_storage.certs_dir / f"{cert_id}.pem"
      key_file = temp_storage.keys_dir / f"{cert_id}.key"

      assert oct(os.stat(cert_file).st_mode & 0o777) == oct(0o600)
      assert oct(os.stat(key_file).st_mode & 0o777) == oct(0o600)

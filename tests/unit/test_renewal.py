"""Tests pour le module renewal."""

import pytest

from src.core.certificate import CertificateManager
from src.core.renewal import CertificateRenewal
from src.core.storage import SecureStorage


class TestCertificateRenewal:
  """Tests pour CertificateRenewal."""

  def test_renew_self_signed_certificate(self, temp_storage):
      manager = CertificateManager()
      cert, private_key, metadata = manager.generate_self_signed_cert(
          "renew.example.com",
          organization="Test Org",
          validity_days=90,
      )
      cert_id = temp_storage.save_certificate(cert, private_key, metadata)

      renewal = CertificateRenewal(temp_storage)
      new_cert_id, new_metadata = renewal.renew_certificate(cert_id, archive_old=True)

      assert new_cert_id != cert_id
      assert new_metadata["renewed_from"] == cert_id
      assert new_metadata["organization"] == "Test Org"

      active = temp_storage.list_certificates()
      assert len(active) == 1
      assert active[0]["id"] == new_cert_id

  def test_cannot_renew_external_ca_signed(self, temp_storage):
      """Un certificat signé par une CA externe ne peut pas être renouvelé sans clé CA."""
      from src.core.certificate import CertificateManager
      from src.core.certificate.client import ClientCertificateManager

      ca_mgr = CertificateManager()
      ca_cert, ca_key, _ = ca_mgr.generate_self_signed_cert("ca.local")

      client_mgr = ClientCertificateManager()
      cert, private_key, metadata = client_mgr.generate_client_cert(
          "user.local",
          ca_cert=ca_cert,
          ca_key=ca_key,
      )
      cert_id = temp_storage.save_certificate(cert, private_key, metadata)

      renewal = CertificateRenewal(temp_storage)
      can_renew, message = renewal.can_renew(cert_id)

      assert can_renew is False
      assert "CA externe" in message

  def test_renew_letsencrypt_requires_certbot(self, temp_storage):
      manager = CertificateManager()
      cert, private_key, metadata = manager.generate_self_signed_cert("le.example.com")
      metadata["letsencrypt"] = True
      metadata["letsencrypt_domains"] = ["le.example.com"]
      cert_id = temp_storage.save_certificate(cert, private_key, metadata)

      renewal = CertificateRenewal(temp_storage)
      can_renew, message = renewal.can_renew(cert_id)

      # certbot peut être absent en CI
      if not renewal.letsencrypt_manager.check_certbot_available():
          assert can_renew is False
          assert "certbot" in message.lower()

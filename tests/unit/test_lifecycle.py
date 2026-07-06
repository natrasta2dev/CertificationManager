"""Tests pour le module lifecycle."""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from src.core.certificate import CertificateManager
from src.core.lifecycle import CertificateLifecycle


class TestCertificateLifecycle:
    """Tests pour CertificateLifecycle."""

    def test_get_statistics_empty(self, temp_storage):
        lifecycle = CertificateLifecycle(temp_storage)
        stats = lifecycle.get_statistics()
        assert stats["total"] == 0
        assert stats["valid"] == 0
        assert stats["expired"] == 0

    def test_get_statistics_with_valid_cert(self, temp_storage):
        manager = CertificateManager()
        cert, key, meta = manager.generate_self_signed_cert("valid.example.com", validity_days=365)
        temp_storage.save_certificate(cert, key, meta)

        stats = CertificateLifecycle(temp_storage).get_statistics()
        assert stats["total"] == 1
        assert stats["valid"] == 1
        assert stats["expired"] == 0

    def test_get_expiring_certificates_threshold(self, temp_storage):
        manager = CertificateManager()
        cert, key, meta = manager.generate_self_signed_cert("soon.example.com", validity_days=5)
        temp_storage.save_certificate(cert, key, meta)

        expiring = CertificateLifecycle(temp_storage).get_expiring_certificates(days_threshold=30)
        assert len(expiring) == 1
        assert expiring[0]["common_name"] == "soon.example.com"
        assert expiring[0]["days_until_expiry"] <= 5

    def test_get_expiring_excludes_far_future(self, temp_storage):
        manager = CertificateManager()
        cert, key, meta = manager.generate_self_signed_cert("far.example.com", validity_days=365)
        temp_storage.save_certificate(cert, key, meta)

        expiring = CertificateLifecycle(temp_storage).get_expiring_certificates(days_threshold=30)
        assert len(expiring) == 0

    def test_get_certificate_status_valid(self, temp_storage):
        manager = CertificateManager()
        cert, key, meta = manager.generate_self_signed_cert("status.example.com", validity_days=365)
        cert_id = temp_storage.save_certificate(cert, key, meta)

        status = CertificateLifecycle(temp_storage).get_certificate_status(cert_id)
        assert status["status"] == "valid"
        assert status["is_valid"] is True
        assert status["days_until_expiry"] > 30

    def test_get_certificate_status_critical(self, temp_storage):
        manager = CertificateManager()
        cert, key, meta = manager.generate_self_signed_cert("critical.example.com", validity_days=3)
        cert_id = temp_storage.save_certificate(cert, key, meta)

        status = CertificateLifecycle(temp_storage).get_certificate_status(cert_id)
        assert status["status"] == "critical"
        assert status["days_until_expiry"] <= 7

    def test_get_certificate_status_not_found(self, temp_storage):
        status = CertificateLifecycle(temp_storage).get_certificate_status("missing-id")
        assert status["status"] == "not_found"

    def test_get_certificate_status_expired(self, temp_storage):
        manager = CertificateManager()
        cert, key, meta = manager.generate_self_signed_cert("expired.example.com", validity_days=30)
        cert_id = temp_storage.save_certificate(cert, key, meta)

        future = cert.not_valid_after_utc + timedelta(days=1)
        with patch("src.core.lifecycle.datetime") as mock_dt:
            mock_dt.now.return_value = future
            mock_dt.side_effect = lambda *args, **kwargs: datetime(*args, **kwargs)
            status = CertificateLifecycle(temp_storage).get_certificate_status(cert_id)

        assert status["status"] == "expired"
        assert status["is_expired"] is True

    def test_categorize_certificates(self, temp_storage):
        manager = CertificateManager()
        c1, k1, m1 = manager.generate_self_signed_cert("valid.example.com", validity_days=365)
        c2, k2, m2 = manager.generate_self_signed_cert("soon.example.com", validity_days=5)
        temp_storage.save_certificate(c1, k1, m1)
        temp_storage.save_certificate(c2, k2, m2)

        categories = CertificateLifecycle(temp_storage).categorize_certificates()
        assert len(categories["valid"]) == 1
        assert len(categories["critical"]) == 1
        assert len(categories["expiring_soon"]) == 1

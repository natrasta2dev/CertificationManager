"""Tests pour le module validation."""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from src.core.certificate import CertificateManager
from src.core.validation import CertificateValidator


class TestCertificateValidator:
    """Tests pour CertificateValidator."""

    def test_validate_valid_certificate(self):
        """Test validation d'un certificat valide."""
        manager = CertificateManager()
        cert, _, _ = manager.generate_self_signed_cert(
            "test.example.com",
            validity_days=365
        )

        validator = CertificateValidator()
        is_valid, errors = validator.validate_certificate(cert)

        assert is_valid is True
        assert len(errors) == 0

    def test_validate_expired_certificate(self):
        """Test validation d'un certificat expiré."""
        manager = CertificateManager()
        cert, _, _ = manager.generate_self_signed_cert(
            "test.example.com",
            validity_days=365,
        )

        validator = CertificateValidator()
        future_time = cert.not_valid_after_utc + timedelta(days=1)

        with patch("src.core.validation.certificate.datetime") as mock_datetime:
            mock_datetime.now.return_value = future_time
            mock_datetime.side_effect = lambda *args, **kwargs: datetime(*args, **kwargs)

            is_valid, errors = validator.validate_certificate(cert)

        assert is_valid is False
        assert any("expiré" in error.lower() for error in errors)

    def test_get_certificate_info(self):
        """Test extraction d'informations d'un certificat."""
        manager = CertificateManager()
        cert, _, _ = manager.generate_self_signed_cert(
            "test.example.com",
            validity_days=365
        )

        validator = CertificateValidator()
        info = validator.get_certificate_info(cert)

        assert "subject" in info
        assert "issuer" in info
        assert "serial_number" in info
        assert "not_valid_before" in info
        assert "not_valid_after" in info
        assert "is_expired" in info
        assert info["is_expired"] is False
        assert "days_until_expiry" in info
        assert info["days_until_expiry"] > 0


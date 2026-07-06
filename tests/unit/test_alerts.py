"""Tests pour le module alerts."""

import pytest

from src.core.alerts import AlertLevel, AlertManager
from src.core.certificate import CertificateManager
from src.core.lifecycle import CertificateLifecycle


class TestAlertManager:
    """Tests pour AlertManager."""

    def test_check_certificates_empty(self, temp_storage):
        manager = AlertManager(CertificateLifecycle(temp_storage))
        alerts = manager.check_certificates()
        assert alerts == []

    def test_critical_alert_for_soon_expiring(self, temp_storage):
        cert_mgr = CertificateManager()
        cert, key, meta = cert_mgr.generate_self_signed_cert("alert.example.com", validity_days=3)
        temp_storage.save_certificate(cert, key, meta)

        alerts = AlertManager(CertificateLifecycle(temp_storage)).check_certificates()
        assert len(alerts) == 1
        assert alerts[0].level == AlertLevel.CRITICAL
        assert "ACTION REQUISE" in alerts[0].message

    def test_warning_alert_for_30_day_threshold(self, temp_storage):
        cert_mgr = CertificateManager()
        cert, key, meta = cert_mgr.generate_self_signed_cert("warn.example.com", validity_days=20)
        temp_storage.save_certificate(cert, key, meta)

        alerts = AlertManager(CertificateLifecycle(temp_storage)).check_certificates()
        assert len(alerts) == 1
        assert alerts[0].level == AlertLevel.WARNING

    def test_expired_alert_level(self, temp_storage):
        from datetime import datetime, timedelta
        from unittest.mock import patch

        cert_mgr = CertificateManager()
        cert, key, meta = cert_mgr.generate_self_signed_cert("old.example.com", validity_days=30)
        cert_id = temp_storage.save_certificate(cert, key, meta)

        future = cert.not_valid_after_utc + timedelta(days=1)
        lifecycle = CertificateLifecycle(temp_storage)
        with patch("src.core.lifecycle.datetime") as mock_dt:
            mock_dt.now.return_value = future
            mock_dt.side_effect = lambda *args, **kwargs: datetime(*args, **kwargs)
            alerts = AlertManager(lifecycle).check_certificates(include_expired=True)

        assert len(alerts) == 1
        assert alerts[0].level == AlertLevel.ERROR
        assert alerts[0].cert_id == cert_id

    def test_alert_handler_called(self, temp_storage):
        cert_mgr = CertificateManager()
        cert, key, meta = cert_mgr.generate_self_signed_cert("handler.example.com", validity_days=3)
        temp_storage.save_certificate(cert, key, meta)

        received = []
        manager = AlertManager(CertificateLifecycle(temp_storage))
        manager.register_handler(lambda a: received.append(a))
        manager.check_certificates()

        assert len(received) == 1
        assert received[0].to_dict()["level"] == "critical"

    def test_get_alerts_for_certificate(self, temp_storage):
        cert_mgr = CertificateManager()
        cert, key, meta = cert_mgr.generate_self_signed_cert("single.example.com", validity_days=5)
        cert_id = temp_storage.save_certificate(cert, key, meta)

        alerts = AlertManager(CertificateLifecycle(temp_storage)).get_alerts_for_certificate(cert_id)
        assert len(alerts) == 1
        assert alerts[0].level == AlertLevel.CRITICAL

    def test_get_alerts_for_missing_certificate(self, temp_storage):
        alerts = AlertManager(CertificateLifecycle(temp_storage)).get_alerts_for_certificate("nope")
        assert alerts == []

    def test_custom_thresholds(self, temp_storage):
        cert_mgr = CertificateManager()
        cert, key, meta = cert_mgr.generate_self_signed_cert("custom.example.com", validity_days=45)
        temp_storage.save_certificate(cert, key, meta)

        thresholds = {14: AlertLevel.CRITICAL, 90: AlertLevel.INFO}
        alerts = AlertManager(
            CertificateLifecycle(temp_storage),
            thresholds=thresholds,
        ).check_certificates()

        assert len(alerts) == 1
        assert alerts[0].level == AlertLevel.INFO

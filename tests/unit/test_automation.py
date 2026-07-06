"""Tests notifications, webhooks et scheduler."""

import json
from unittest.mock import MagicMock, patch

import pytest

from src.core.alerts import Alert, AlertLevel
from src.core.notifications import EmailNotifier
from src.core.scheduler import SchedulerService
from src.core.webhooks import WebhookManager


class TestEmailNotifier:
    def test_config_store(self, temp_storage):
        notifier = EmailNotifier(str(temp_storage.storage_path))
        notifier.update_config({
            "enabled": True,
            "smtp_host": "smtp.test.local",
            "smtp_port": 587,
            "from_email": "cert@test.local",
            "to_emails": ["admin@test.local"],
        })
        assert notifier.is_enabled() is True

    @patch("smtplib.SMTP")
    def test_send_alert(self, mock_smtp, temp_storage):
        notifier = EmailNotifier(str(temp_storage.storage_path))
        notifier.update_config({
            "enabled": True,
            "smtp_host": "smtp.test.local",
            "smtp_port": 587,
            "use_tls": True,
            "from_email": "cert@test.local",
            "to_emails": ["admin@test.local"],
        })
        mock_server = MagicMock()
        mock_smtp.return_value = mock_server

        alert = Alert("id1", "test.example.com", AlertLevel.CRITICAL, "Expire bientôt", 3, "2026-01-01")
        notifier.send_alert(alert)
        mock_server.starttls.assert_called_once()
        mock_server.sendmail.assert_called_once()


class TestWebhookManager:
    @patch("urllib.request.urlopen")
    def test_dispatch_with_hmac(self, mock_urlopen, temp_storage):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        wh = WebhookManager(str(temp_storage.storage_path))
        wh.update_config({
            "enabled": True,
            "secret": "test-secret",
            "endpoints": [{
                "url": "https://hooks.test.local/callback",
                "events": ["alert.triggered"],
            }],
        })

        results = wh.dispatch("alert.triggered", {"cert_id": "abc"})
        assert len(results) == 1
        assert results[0]["success"] is True

        req = mock_urlopen.call_args[0][0]
        header_names = [k.lower() for k, _ in req.header_items()]
        assert "x-certmanager-signature" in header_names

    def test_unknown_event_raises(self, temp_storage):
        wh = WebhookManager(str(temp_storage.storage_path))
        with pytest.raises(ValueError, match="Événement inconnu"):
            wh.dispatch("invalid.event", {})


class TestSchedulerService:
    def test_run_check_alerts(self, temp_storage):
        from src.core.certificate import CertificateManager

        mgr = CertificateManager()
        cert, key, meta = mgr.generate_self_signed_cert("sched.example.com", validity_days=3)
        temp_storage.save_certificate(cert, key, meta)

        service = SchedulerService(str(temp_storage.storage_path))
        result = service.run_job("check-alerts")
        assert result["alerts_count"] >= 1

    def test_auto_renew_skipped_when_disabled(self, temp_storage):
        service = SchedulerService(str(temp_storage.storage_path))
        result = service.run_job("auto-renew")
        assert result.get("skipped") is True

    def test_compliance_scan(self, temp_storage):
        from src.core.certificate import CertificateManager

        mgr = CertificateManager()
        cert, key, meta = mgr.generate_self_signed_cert("comply.example.com")
        temp_storage.save_certificate(cert, key, meta)

        service = SchedulerService(str(temp_storage.storage_path))
        result = service.run_job("compliance-scan")
        assert "issues_count" in result

    def test_get_status(self, temp_storage):
        service = SchedulerService(str(temp_storage.storage_path))
        status = service.get_status()
        assert "config" in status
        assert status["running"] is False

    def test_weekly_report_without_smtp(self, temp_storage):
        from src.core.certificate import CertificateManager

        mgr = CertificateManager()
        cert, key, meta = mgr.generate_self_signed_cert("weekly.example.com", validity_days=3)
        temp_storage.save_certificate(cert, key, meta)

        service = SchedulerService(str(temp_storage.storage_path))
        result = service.run_job("weekly-report")
        assert result["alerts_count"] >= 1
        assert result["email_sent"] is False

    def test_send_weekly_report_builds_email(self, temp_storage):
        from src.core.alerts import AlertManager
        from src.core.certificate import CertificateManager
        from src.core.lifecycle import CertificateLifecycle

        mgr = CertificateManager()
        cert, key, meta = mgr.generate_self_signed_cert("report.example.com", validity_days=3)
        temp_storage.save_certificate(cert, key, meta)

        notifier = EmailNotifier(str(temp_storage.storage_path))
        notifier.update_config({
            "enabled": True,
            "smtp_host": "localhost",
            "smtp_port": 25,
            "from_email": "test@local",
            "to_emails": ["admin@local"],
        })
        alerts = AlertManager(CertificateLifecycle(temp_storage)).check_certificates()
        stats = {"total": 1, "valid": 0, "expiring_soon": 1, "critical": 0, "expired": 0}
        import unittest.mock as mock
        with mock.patch.object(notifier, "send_email") as send_mock:
            notifier.send_weekly_report(alerts, stats)
            send_mock.assert_called_once()
            assert "hebdomadaire" in send_mock.call_args[0][0].lower()

"""Planificateur de tâches CertificationManager."""

import os
import signal
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .alerts import AlertManager
from .app_config import alert_manager_for_storage
from .compliance import ComplianceScanner
from .lifecycle import CertificateLifecycle
from .notifications import EmailNotifier
from .renewal import CertificateRenewal
from .storage import SecureStorage
from .validation import CertificateValidator
from .webhooks import WebhookManager
from .config_store import ConfigStore


class SchedulerService:
    """Exécute les tâches planifiées (alertes, renouvellement, conformité)."""

    AVAILABLE_JOBS = (
        "check-alerts", "auto-renew", "compliance-scan",
        "weekly-report", "monthly-report", "all",
    )

    def __init__(self, storage_path: Optional[str] = None):
        if storage_path is None:
            from ..config import get_settings
            storage_path = get_settings().storage_path

        self.storage_path = Path(storage_path)
        self.storage = SecureStorage(storage_path=str(self.storage_path))
        self.lifecycle = CertificateLifecycle(self.storage)
        self.alert_manager = alert_manager_for_storage(self.storage)
        self.renewal = CertificateRenewal(self.storage)
        self.email_notifier = EmailNotifier(str(self.storage_path))
        self.webhook_manager = WebhookManager(str(self.storage_path))
        self.validator = CertificateValidator()
        self.config_store = ConfigStore(str(self.storage_path), "scheduler.json")
        self.pid_file = self.storage_path / "scheduler.pid"
        self.log_file = self.storage_path / "scheduler.log"

    def get_config(self) -> Dict:
        defaults = {
            "interval_minutes": 60,
            "auto_renew_enabled": False,
            "auto_renew_days": 30,
            "alert_email_enabled": True,
            "alert_webhook_enabled": True,
        }
        cfg = self.config_store.load()
        return {**defaults, **cfg}

    def update_config(self, updates: Dict) -> Dict:
        return self.config_store.update(updates)

    def _log(self, message: str) -> None:
        line = f"{datetime.now(timezone.utc).isoformat()} {message}\n"
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(line)

    def run_job(self, job_name: str, **kwargs) -> Dict[str, Any]:
        """Exécute une tâche nommée."""
        if job_name not in self.AVAILABLE_JOBS:
            raise ValueError(
                f"Tâche inconnue: {job_name}. Disponibles: {', '.join(self.AVAILABLE_JOBS)}"
            )

        if job_name == "all":
            results = {}
            for name in ("check-alerts", "auto-renew", "compliance-scan", "weekly-report"):
                try:
                    results[name] = self.run_job(name, **kwargs)
                except Exception as e:
                    results[name] = {"error": str(e)}
            return results

        if job_name == "check-alerts":
            return self._job_check_alerts()
        if job_name == "auto-renew":
            return self._job_auto_renew(kwargs.get("days"))
        if job_name == "compliance-scan":
            return self._job_compliance_scan()
        if job_name == "weekly-report":
            return self._job_weekly_report()
        if job_name == "monthly-report":
            return self._job_monthly_report()

        return {}

    def _job_check_alerts(self) -> Dict[str, Any]:
        cfg = self.get_config()
        alerts = self.alert_manager.check_certificates(include_expired=True)
        result: Dict[str, Any] = {"alerts_count": len(alerts), "email_sent": False, "webhooks": []}

        if alerts and cfg.get("alert_email_enabled") and self.email_notifier.is_enabled():
            try:
                critical = [a for a in alerts if a.level.value in ("critical", "error")]
                to_send = critical if critical else alerts
                self.email_notifier.send_alerts_summary(to_send)
                result["email_sent"] = True
            except Exception as e:
                result["email_error"] = str(e)

        if alerts and cfg.get("alert_webhook_enabled") and self.webhook_manager.is_enabled():
            for alert in alerts:
                alert_data = alert.to_dict()
                wh = self.webhook_manager.dispatch("alert.triggered", alert_data)
                result["webhooks"].extend(wh)
                if alert.level.value in ("warning", "critical", "error"):
                    wh2 = self.webhook_manager.dispatch("certificate.expiring", alert_data)
                    result["webhooks"].extend(wh2)

        self._log(f"check-alerts: {len(alerts)} alerte(s)")
        return result

    def _job_auto_renew(self, days: Optional[int] = None) -> Dict[str, Any]:
        cfg = self.get_config()
        if not cfg.get("auto_renew_enabled"):
            return {"skipped": True, "reason": "auto_renew_disabled"}

        threshold = days or cfg.get("auto_renew_days", 30)
        results = self.renewal.renew_all_expiring(
            days_threshold=threshold,
            dry_run=False,
            archive_old=True,
        )
        renewed = sum(1 for _, new_id, err in results if new_id and not err)
        failed = sum(1 for _, _, err in results if err)

        if self.webhook_manager.is_enabled():
            for old_id, new_id, err in results:
                if new_id and not err:
                    self.webhook_manager.dispatch(
                        "certificate.renewed",
                        {"old_id": old_id, "new_id": new_id},
                    )

        self._log(f"auto-renew: {renewed} renouvelé(s), {failed} échec(s)")
        return {
            "renewed": renewed,
            "failed": failed,
            "details": [
                {"old_id": o, "new_id": n, "error": e} for o, n, e in results
            ],
        }

    def _job_compliance_scan(self) -> Dict[str, Any]:
        result = ComplianceScanner(self.storage).scan_all()
        self._log(f"compliance-scan: {result['issues_count']} problème(s)")
        return result

    def _job_weekly_report(self) -> Dict[str, Any]:
        alerts = self.alert_manager.check_certificates(include_expired=True)
        stats = self.lifecycle.get_statistics()
        result: Dict[str, Any] = {"alerts_count": len(alerts), "email_sent": False}

        if self.email_notifier.is_enabled():
            try:
                self.email_notifier.send_weekly_report(alerts, stats)
                result["email_sent"] = True
            except Exception as e:
                result["email_error"] = str(e)

        self._log(f"weekly-report: {len(alerts)} alerte(s)")
        return result

    def _job_monthly_report(self) -> Dict[str, Any]:
        alerts = self.alert_manager.check_certificates(include_expired=True)
        stats = self.lifecycle.get_statistics()
        compliance = ComplianceScanner(self.storage).guidelines_dashboard()
        result: Dict[str, Any] = {
            "alerts_count": len(alerts),
            "compliance_rate": compliance.get("compliance_rate"),
            "email_sent": False,
        }
        if self.email_notifier.is_enabled():
            try:
                self.email_notifier.send_monthly_report(alerts, stats, compliance)
                result["email_sent"] = True
            except Exception as e:
                result["email_error"] = str(e)
        self._log(f"monthly-report: {len(alerts)} alerte(s)")
        return result

    def write_pid(self) -> None:
        self.pid_file.write_text(str(os.getpid()), encoding="utf-8")
        os.chmod(self.pid_file, 0o600)

    def remove_pid(self) -> None:
        if self.pid_file.exists():
            self.pid_file.unlink()

    def get_status(self) -> Dict[str, Any]:
        cfg = self.get_config()
        status: Dict[str, Any] = {
            "config": cfg,
            "running": False,
            "pid": None,
        }
        if self.pid_file.exists():
            try:
                pid = int(self.pid_file.read_text(encoding="utf-8").strip())
                os.kill(pid, 0)
                status["running"] = True
                status["pid"] = pid
            except (OSError, ValueError):
                status["stale_pid_file"] = True
        if self.log_file.exists():
            lines = self.log_file.read_text(encoding="utf-8").strip().splitlines()
            status["last_log_lines"] = lines[-5:]
        return status

    def start_foreground(self, interval_minutes: Optional[int] = None) -> None:
        """Boucle planifiée (bloquante jusqu'à SIGINT/SIGTERM)."""
        cfg = self.get_config()
        interval = interval_minutes or cfg.get("interval_minutes", 60)
        running = True

        def _stop(signum, frame):
            nonlocal running
            running = False

        signal.signal(signal.SIGINT, _stop)
        signal.signal(signal.SIGTERM, _stop)

        self.write_pid()
        self._log(f"scheduler started interval={interval}min")
        try:
            while running:
                try:
                    self.run_job("all")
                except Exception as e:
                    self._log(f"scheduler error: {e}")
                for _ in range(interval * 60):
                    if not running:
                        break
                    time.sleep(1)
        finally:
            self.remove_pid()
            self._log("scheduler stopped")

    def stop(self) -> bool:
        """Arrête le scheduler via signal SIGTERM."""
        if not self.pid_file.exists():
            return False
        try:
            pid = int(self.pid_file.read_text(encoding="utf-8").strip())
            os.kill(pid, signal.SIGTERM)
            return True
        except (OSError, ValueError):
            self.remove_pid()
            return False

"""Notifications email via SMTP."""

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, List, Optional

from .alerts import Alert
from .config_store import ConfigStore


def _alert_email_html(alert: Alert) -> str:
    level_colors = {
        "info": "#17a2b8",
        "warning": "#ffc107",
        "critical": "#dc3545",
        "error": "#6c757d",
    }
    color = level_colors.get(alert.level.value, "#333")
    return f"""
    <html><body style="font-family: sans-serif;">
    <h2 style="color: {color};">Alerte certificat — {alert.level.value.upper()}</h2>
    <p><strong>{alert.message}</strong></p>
    <table style="border-collapse: collapse;">
      <tr><td style="padding:4px 12px 4px 0;">Certificat</td><td>{alert.common_name}</td></tr>
      <tr><td style="padding:4px 12px 4px 0;">ID</td><td>{alert.cert_id}</td></tr>
      <tr><td style="padding:4px 12px 4px 0;">Expire le</td><td>{alert.expires_at}</td></tr>
      <tr><td style="padding:4px 12px 4px 0;">Jours restants</td><td>{alert.days_until_expiry}</td></tr>
    </table>
    <p style="color:#666;font-size:12px;">CertificationManager — notification automatique</p>
    </body></html>
    """


def _alerts_summary_html(alerts: List[Alert]) -> str:
    rows = "".join(
        f"<tr><td>{a.common_name}</td><td>{a.level.value}</td>"
        f"<td>{a.days_until_expiry}j</td><td>{a.message}</td></tr>"
        for a in alerts
    )
    return f"""
    <html><body style="font-family: sans-serif;">
    <h2>Rapport d'alertes CertificationManager</h2>
    <p>{len(alerts)} alerte(s) détectée(s).</p>
    <table border="1" cellpadding="6" style="border-collapse:collapse;">
      <tr><th>CN</th><th>Niveau</th><th>Jours</th><th>Message</th></tr>
      {rows}
    </table>
    </body></html>
    """


class EmailNotifier:
    """Envoi d'emails SMTP configurable."""

    def __init__(self, storage_path: Optional[str] = None):
        self.store = ConfigStore(storage_path, "notifications.json")
        self._apply_env_defaults()

    def _apply_env_defaults(self) -> None:
        import os
        data = self.store.load()
        if not data and os.getenv("CERTMANAGER_SMTP_HOST"):
            data = {
                "enabled": os.getenv("CERTMANAGER_SMTP_ENABLED", "false").lower()
                in ("1", "true", "yes"),
                "smtp_host": os.getenv("CERTMANAGER_SMTP_HOST", ""),
                "smtp_port": int(os.getenv("CERTMANAGER_SMTP_PORT", "587")),
                "smtp_user": os.getenv("CERTMANAGER_SMTP_USER", ""),
                "smtp_password": os.getenv("CERTMANAGER_SMTP_PASSWORD", ""),
                "use_tls": os.getenv("CERTMANAGER_SMTP_TLS", "true").lower()
                in ("1", "true", "yes"),
                "from_email": os.getenv("CERTMANAGER_SMTP_FROM", ""),
                "to_emails": [
                    e.strip()
                    for e in os.getenv("CERTMANAGER_SMTP_TO", "").split(",")
                    if e.strip()
                ],
            }
            self.store.save(data)

    def get_config(self) -> Dict:
        return self.store.load()

    def update_config(self, updates: Dict) -> Dict:
        return self.store.update(updates)

    def is_enabled(self) -> bool:
        cfg = self.store.load()
        return bool(cfg.get("enabled")) and bool(cfg.get("smtp_host"))

    def send_email(
        self,
        subject: str,
        html_body: str,
        text_body: Optional[str] = None,
        to_emails: Optional[List[str]] = None,
    ) -> None:
        cfg = self.store.load()
        if not cfg.get("enabled"):
            raise RuntimeError("Notifications email désactivées")

        recipients = to_emails or cfg.get("to_emails", [])
        if not recipients:
            raise RuntimeError("Aucun destinataire configuré")

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = cfg.get("from_email") or cfg.get("smtp_user", "certmanager@localhost")
        msg["To"] = ", ".join(recipients)

        plain = text_body or "Voir la version HTML de cet email."
        msg.attach(MIMEText(plain, "plain", "utf-8"))
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        host = cfg["smtp_host"]
        port = int(cfg.get("smtp_port", 587))
        user = cfg.get("smtp_user")
        password = cfg.get("smtp_password")
        use_tls = cfg.get("use_tls", True)

        if use_tls:
            server = smtplib.SMTP(host, port, timeout=30)
            server.starttls()
        else:
            server = smtplib.SMTP(host, port, timeout=30)

        try:
            if user and password:
                server.login(user, password)
            server.sendmail(msg["From"], recipients, msg.as_string())
        finally:
            server.quit()

    def send_alert(self, alert: Alert) -> None:
        subject = f"[CertManager] {alert.level.value.upper()} — {alert.common_name}"
        self.send_email(subject, _alert_email_html(alert), text_body=alert.message)

    def send_alerts_summary(self, alerts: List[Alert]) -> None:
        if not alerts:
            return
        subject = f"[CertManager] {len(alerts)} alerte(s) certificat"
        self.send_email(
            subject,
            _alerts_summary_html(alerts),
            text_body="\n".join(a.message for a in alerts),
        )

    def send_weekly_report(self, alerts: List[Alert], stats: Dict) -> None:
        """Envoie un rapport hebdomadaire par email."""
        rows = "".join(
            f"<tr><td>{a.common_name}</td><td>{a.level.value}</td>"
            f"<td>{a.days_until_expiry}j</td></tr>"
            for a in alerts[:50]
        )
        html = f"""
        <html><body style="font-family: sans-serif;">
        <h2>Rapport hebdomadaire CertificationManager</h2>
        <h3>Statistiques</h3>
        <ul>
          <li>Total : {stats.get('total', 0)}</li>
          <li>Valides : {stats.get('valid', 0)}</li>
          <li>Expirent bientôt : {stats.get('expiring_soon', 0)}</li>
          <li>Critiques : {stats.get('critical', 0)}</li>
          <li>Expirés : {stats.get('expired', 0)}</li>
        </ul>
        <h3>Alertes ({len(alerts)})</h3>
        <table border="1" cellpadding="6"><tr><th>CN</th><th>Niveau</th><th>Jours</th></tr>{rows}</table>
        </body></html>
        """
        subject = f"[CertManager] Rapport hebdomadaire — {stats.get('total', 0)} certificat(s)"
        self.send_email(subject, html, text_body=f"{len(alerts)} alerte(s) cette semaine")

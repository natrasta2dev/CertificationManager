"""Système d'alertes pour les certificats."""

from datetime import datetime, timezone
from typing import List, Dict, Optional, Callable
from enum import Enum

from .lifecycle import CertificateLifecycle


class AlertLevel(Enum):
    """Niveaux d'alerte."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    ERROR = "error"


class Alert:
    """Représente une alerte."""

    def __init__(
        self,
        cert_id: str,
        common_name: str,
        level: AlertLevel,
        message: str,
        days_until_expiry: int,
        expires_at: str
    ):
        self.cert_id = cert_id
        self.common_name = common_name
        self.level = level
        self.message = message
        self.days_until_expiry = days_until_expiry
        self.expires_at = expires_at
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict:
        """Convertit l'alerte en dictionnaire."""
        return {
            "cert_id": self.cert_id,
            "common_name": self.common_name,
            "level": self.level.value,
            "message": self.message,
            "days_until_expiry": self.days_until_expiry,
            "expires_at": self.expires_at,
            "timestamp": self.timestamp,
        }


class AlertManager:
    """Gestionnaire d'alertes pour les certificats."""

    def __init__(
        self,
        lifecycle: Optional[CertificateLifecycle] = None,
        thresholds: Optional[Dict[int, AlertLevel]] = None
    ):
        """
        Initialise le gestionnaire d'alertes.

        Args:
            lifecycle: Instance de CertificateLifecycle
            thresholds: Dictionnaire {jours: niveau_alerte}
                       Par défaut: {7: CRITICAL, 30: WARNING, 60: INFO}
        """
        self.lifecycle = lifecycle or CertificateLifecycle()
        
        if thresholds is None:
            self.thresholds = {
                7: AlertLevel.CRITICAL,
                30: AlertLevel.WARNING,
                60: AlertLevel.INFO,
            }
        else:
            self.thresholds = thresholds

        self.alert_handlers: List[Callable[[Alert], None]] = []

    def register_handler(self, handler: Callable[[Alert], None]):
        """
        Enregistre un gestionnaire d'alertes.

        Args:
            handler: Fonction qui sera appelée pour chaque alerte
        """
        self.alert_handlers.append(handler)

    def check_certificates(self, include_expired: bool = True) -> List[Alert]:
        """
        Vérifie tous les certificats et génère les alertes.

        Args:
            include_expired: Inclure les certificats expirés. Défaut: True

        Returns:
            Liste des alertes générées
        """
        alerts = []
        
        # Récupérer le seuil maximum
        max_threshold = max(self.thresholds.keys()) if self.thresholds else 60
        
        # Récupérer les certificats expirant bientôt
        expiring_certs = self.lifecycle.get_expiring_certificates(
            days_threshold=max_threshold,
            include_expired=include_expired
        )

        for cert_data in expiring_certs:
            cert_id = cert_data.get("id")
            common_name = cert_data.get("common_name", "N/A")
            days_until_expiry = cert_data.get("days_until_expiry", 0)
            expires_at = cert_data.get("expires_at", "")
            is_expired = cert_data.get("is_expired", False)

            # Déterminer le niveau d'alerte
            if is_expired:
                level = AlertLevel.ERROR
                message = f"Le certificat '{common_name}' a expiré"
            else:
                # Trouver le seuil approprié
                level = AlertLevel.INFO
                for threshold_days in sorted(self.thresholds.keys()):
                    if days_until_expiry <= threshold_days:
                        level = self.thresholds[threshold_days]
                        break

                if level == AlertLevel.CRITICAL:
                    message = f"Le certificat '{common_name}' expire dans {days_until_expiry} jour(s) - ACTION REQUISE"
                elif level == AlertLevel.WARNING:
                    message = f"Le certificat '{common_name}' expire dans {days_until_expiry} jour(s)"
                else:
                    message = f"Le certificat '{common_name}' expire dans {days_until_expiry} jour(s)"

            alert = Alert(
                cert_id=cert_id,
                common_name=common_name,
                level=level,
                message=message,
                days_until_expiry=days_until_expiry,
                expires_at=expires_at
            )

            alerts.append(alert)

            # Notifier les gestionnaires
            for handler in self.alert_handlers:
                try:
                    handler(alert)
                except Exception:
                    # Ignorer les erreurs des gestionnaires
                    pass

        return alerts

    def get_alerts_for_certificate(self, cert_id: str) -> List[Alert]:
        """
        Récupère les alertes pour un certificat spécifique.

        Args:
            cert_id: ID du certificat

        Returns:
            Liste des alertes pour ce certificat
        """
        status = self.lifecycle.get_certificate_status(cert_id)
        
        if status.get("status") == "not_found":
            return []

        alerts = []
        common_name = status.get("common_name", "N/A")
        days_until_expiry = status.get("days_until_expiry", 0)
        expires_at = status.get("expires_at", "")
        is_expired = status.get("is_expired", False)

        if is_expired:
            alert = Alert(
                cert_id=cert_id,
                common_name=common_name,
                level=AlertLevel.ERROR,
                message=f"Le certificat '{common_name}' a expiré",
                days_until_expiry=0,
                expires_at=expires_at
            )
            alerts.append(alert)
        elif days_until_expiry <= 7:
            alert = Alert(
                cert_id=cert_id,
                common_name=common_name,
                level=AlertLevel.CRITICAL,
                message=f"Le certificat '{common_name}' expire dans {days_until_expiry} jour(s)",
                days_until_expiry=days_until_expiry,
                expires_at=expires_at
            )
            alerts.append(alert)
        elif days_until_expiry <= 30:
            alert = Alert(
                cert_id=cert_id,
                common_name=common_name,
                level=AlertLevel.WARNING,
                message=f"Le certificat '{common_name}' expire dans {days_until_expiry} jour(s)",
                days_until_expiry=days_until_expiry,
                expires_at=expires_at
            )
            alerts.append(alert)

        return alerts


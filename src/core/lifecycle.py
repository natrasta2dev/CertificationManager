"""Gestion du cycle de vie des certificats."""

from datetime import datetime, timezone, timedelta
from typing import List, Dict, Optional
from .storage import SecureStorage
from .validation.certificate import CertificateValidator


class CertificateLifecycle:
    """Gestionnaire du cycle de vie des certificats."""

    def __init__(self, storage: Optional[SecureStorage] = None):
        """
        Initialise le gestionnaire de cycle de vie.

        Args:
            storage: Instance de SecureStorage. Si None, crée une nouvelle instance.
        """
        self.storage = storage or SecureStorage()
        self.validator = CertificateValidator()

    def get_expiring_certificates(
        self,
        days_threshold: int = 30,
        include_expired: bool = False
    ) -> List[Dict]:
        """
        Récupère les certificats expirant dans les X jours.

        Args:
            days_threshold: Nombre de jours avant expiration. Défaut: 30
            include_expired: Inclure les certificats déjà expirés. Défaut: False

        Returns:
            Liste des certificats expirant bientôt avec leurs métadonnées
        """
        certificates = self.storage.list_certificates()
        expiring = []

        now = datetime.now(timezone.utc)

        for cert_data in certificates:
            try:
                cert_id = cert_data.get("id")
                if not cert_id:
                    continue

                cert, _ = self.storage.load_certificate(cert_id)
                expires_at = cert.not_valid_after_utc

                # Vérifier si expiré
                is_expired = expires_at < now
                if is_expired and not include_expired:
                    continue

                # Calculer les jours restants
                if is_expired:
                    days_until_expiry = 0
                else:
                    days_until_expiry = (expires_at - now).days

                # Vérifier si dans le seuil
                if days_until_expiry <= days_threshold or is_expired:
                    cert_data["days_until_expiry"] = days_until_expiry
                    cert_data["is_expired"] = is_expired
                    cert_data["expires_at"] = expires_at.isoformat()
                    expiring.append(cert_data)

            except Exception:
                # Si le certificat ne peut pas être chargé, continuer
                continue

        # Trier par date d'expiration (les plus proches en premier)
        expiring.sort(key=lambda x: x.get("expires_at", ""))
        return expiring

    def get_certificate_status(self, cert_id: str) -> Dict:
        """
        Récupère le statut détaillé d'un certificat.

        Args:
            cert_id: ID du certificat

        Returns:
            Dictionnaire avec le statut du certificat
        """
        try:
            cert, metadata = self.storage.load_certificate(cert_id)
            now = datetime.now(timezone.utc)
            expires_at = cert.not_valid_after_utc
            is_expired = expires_at < now

            if is_expired:
                days_until_expiry = 0
                status = "expired"
                status_label = "Expiré"
            else:
                days_until_expiry = (expires_at - now).days
                if days_until_expiry <= 7:
                    status = "critical"
                    status_label = "Expiration critique"
                elif days_until_expiry <= 30:
                    status = "warning"
                    status_label = "Expire bientôt"
                else:
                    status = "valid"
                    status_label = "Valide"

            # Validation du certificat
            is_valid, errors = self.validator.validate_certificate(cert)

            return {
                "id": cert_id,
                "common_name": metadata.get("common_name", "N/A"),
                "status": status,
                "status_label": status_label,
                "is_expired": is_expired,
                "days_until_expiry": days_until_expiry,
                "expires_at": expires_at.isoformat(),
                "not_valid_before": cert.not_valid_before_utc.isoformat(),
                "not_valid_after": expires_at.isoformat(),
                "is_valid": is_valid,
                "validation_errors": errors,
                "metadata": metadata,
            }
        except FileNotFoundError:
            return {
                "id": cert_id,
                "status": "not_found",
                "status_label": "Non trouvé",
                "error": "Certificat introuvable",
            }
        except Exception as e:
            return {
                "id": cert_id,
                "status": "error",
                "status_label": "Erreur",
                "error": str(e),
            }

    def get_statistics(self) -> Dict:
        """
        Récupère les statistiques globales sur les certificats.

        Returns:
            Dictionnaire avec les statistiques
        """
        certificates = self.storage.list_certificates()
        now = datetime.now(timezone.utc)

        stats = {
            "total": len(certificates),
            "valid": 0,
            "expired": 0,
            "expiring_soon": 0,  # Dans les 30 prochains jours
            "critical": 0,  # Dans les 7 prochains jours
        }

        for cert_data in certificates:
            try:
                cert_id = cert_data.get("id")
                if not cert_id:
                    continue

                cert, _ = self.storage.load_certificate(cert_id)
                expires_at = cert.not_valid_after_utc
                is_expired = expires_at < now

                if is_expired:
                    stats["expired"] += 1
                else:
                    days_until_expiry = (expires_at - now).days
                    stats["valid"] += 1
                    if days_until_expiry <= 7:
                        stats["critical"] += 1
                        stats["expiring_soon"] += 1
                    elif days_until_expiry <= 30:
                        stats["expiring_soon"] += 1

            except Exception:
                continue

        return stats

    def categorize_certificates(self) -> Dict[str, List[Dict]]:
        """
        Catégorise les certificats par statut.

        Returns:
            Dictionnaire avec les certificats catégorisés
        """
        certificates = self.storage.list_certificates()
        now = datetime.now(timezone.utc)

        categories = {
            "valid": [],
            "expiring_soon": [],  # 30 jours
            "critical": [],  # 7 jours
            "expired": [],
        }

        for cert_data in certificates:
            try:
                cert_id = cert_data.get("id")
                if not cert_id:
                    continue

                cert, _ = self.storage.load_certificate(cert_id)
                expires_at = cert.not_valid_after_utc
                is_expired = expires_at < now

                if is_expired:
                    categories["expired"].append(cert_data)
                else:
                    days_until_expiry = (expires_at - now).days
                    if days_until_expiry <= 7:
                        categories["critical"].append(cert_data)
                        categories["expiring_soon"].append(cert_data)
                    elif days_until_expiry <= 30:
                        categories["expiring_soon"].append(cert_data)
                    else:
                        categories["valid"].append(cert_data)

            except Exception:
                continue

        return categories


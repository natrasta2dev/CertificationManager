"""Instances partagées des gestionnaires métier pour l'API web."""

from functools import lru_cache

from ..config import get_settings
from ..core.app_config import alert_manager_for_storage
from ..core import (
    CAManager,
    CertificateExporter,
    CertificateImporter,
    CertificateLifecycle,
    CertificateManager,
    CertificateRenewal,
    CertificateValidator,
    ClientCertificateManager,
    LetsEncryptManager,
    SecureStorage,
)


class Managers:
    """Conteneur des services métier."""

    def __init__(self) -> None:
        settings = get_settings()
        self.storage = SecureStorage(storage_path=settings.storage_path)
        self.cert_manager = CertificateManager()
        self.client_cert_manager = ClientCertificateManager()
        self.validator = CertificateValidator()
        self.lifecycle = CertificateLifecycle(self.storage)
        self.alert_manager = alert_manager_for_storage(self.storage)
        self.renewal = CertificateRenewal(self.storage)
        self.importer = CertificateImporter(self.storage)
        self.exporter = CertificateExporter(self.storage)
        self.ca_manager = CAManager(self.storage)
        self.letsencrypt_manager = LetsEncryptManager(self.storage)


@lru_cache
def get_managers() -> Managers:
    """Retourne les gestionnaires partagés (singleton)."""
    return Managers()

"""Génération de rapports d'inventaire."""

import csv
import io
from typing import List

from .storage import SecureStorage


class ReportGenerator:
    """Rapports CSV et inventaire."""

    def __init__(self, storage: SecureStorage):
        self.storage = storage

    def certificates_csv(self) -> str:
        """Génère un CSV de l'inventaire des certificats."""
        certs = self.storage.list_certificates()
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "id",
            "common_name",
            "organization",
            "key_type",
            "key_size",
            "not_valid_after",
            "days_until_expiry",
            "is_expired",
            "issuer_type",
        ])
        for c in certs:
            writer.writerow([
                c.get("id", ""),
                c.get("common_name", ""),
                c.get("organization", ""),
                c.get("key_type", ""),
                c.get("key_size", ""),
                c.get("not_valid_after", ""),
                c.get("days_until_expiry", ""),
                c.get("is_expired", False),
                c.get("issuer_type", ""),
            ])
        return output.getvalue()

    def archives_csv(self) -> str:
        """Génère un CSV des certificats archivés."""
        archives = self.storage.list_archived_certificates()
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["id", "common_name", "organization", "archived_at", "reason"])
        for a in archives:
            writer.writerow([
                a.get("id", ""),
                a.get("common_name", ""),
                a.get("organization", ""),
                a.get("archived_at", ""),
                a.get("archive_reason", ""),
            ])
        return output.getvalue()

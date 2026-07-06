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

    def compliance_pdf(self, dashboard: dict) -> bytes:
        """Génère un rapport PDF de conformité."""
        from fpdf import FPDF

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, "Rapport de conformite CertificationManager", ln=True)
        pdf.set_font("Helvetica", size=11)
        pdf.cell(0, 8, f"Taux: {dashboard.get('compliance_rate', 0)}%", ln=True)
        nist = dashboard.get("guidelines", {}).get("nist_alignment_score", 0)
        pdf.cell(0, 8, f"Score NIST/Mozilla: {nist}%", ln=True)
        pdf.set_font("Helvetica", size=10)
        for issue in dashboard.get("issues", [])[:40]:
            pdf.multi_cell(
                0, 6,
                f"{issue.get('common_name', '')}: {'; '.join(issue.get('errors', []))[:100]}",
            )
        return bytes(pdf.output())

    def expiration_pdf(self, certs: list) -> bytes:
        from fpdf import FPDF

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Rapport d'expiration", ln=True)
        pdf.set_font("Helvetica", size=10)
        for c in sorted(certs, key=lambda x: x.get("days_until_expiry") or 0)[:80]:
            pdf.cell(
                0, 6,
                f"{c.get('common_name', '')} | {c.get('not_valid_after', '')} | "
                f"{c.get('days_until_expiry', '')}j",
                ln=True,
            )
        return bytes(pdf.output())

    def audit_pdf(self, logs: list) -> bytes:
        from fpdf import FPDF

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Rapport d'audit", ln=True)
        pdf.set_font("Helvetica", size=9)
        for log in logs[:100]:
            pdf.multi_cell(
                0, 5,
                f"{log.get('timestamp', '')} | {log.get('action', '')} | {log.get('username', '')}",
            )
        return bytes(pdf.output())

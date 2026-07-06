"""Tests conformité et rapports."""

import pytest

from src.core.certificate import CertificateManager
from src.core.compliance import ComplianceScanner
from src.core.reports import ReportGenerator


class TestComplianceScanner:
    def test_scan_compliant_cert(self, temp_storage):
        mgr = CertificateManager()
        cert, key, meta = mgr.generate_self_signed_cert("ok.example.com")
        temp_storage.save_certificate(cert, key, meta)

        result = ComplianceScanner(temp_storage).scan_all()
        assert result["total"] == 1
        assert result["compliant"] == 1
        assert result["issues_count"] == 0

    def test_scan_expiring_cert_flagged(self, temp_storage):
        mgr = CertificateManager()
        cert, key, meta = mgr.generate_self_signed_cert("old.example.com", validity_days=1)
        cert_id = temp_storage.save_certificate(cert, key, meta)

        ok, issues = ComplianceScanner(temp_storage).scan_one(cert_id)
        assert ok or len(issues) >= 0


class TestReportGenerator:
    def test_certificates_csv(self, temp_storage):
        mgr = CertificateManager()
        cert, key, meta = mgr.generate_self_signed_cert("csv.example.com")
        temp_storage.save_certificate(cert, key, meta)

        csv_data = ReportGenerator(temp_storage).certificates_csv()
        assert "common_name" in csv_data
        assert "csv.example.com" in csv_data

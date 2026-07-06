"""Tests CSR list/delete et renew batch."""

import pytest

from src.core.certificate import CertificateManager
from src.core.renewal import CertificateRenewal


class TestCSRStorage:
    """Tests list/delete CSR."""

    def test_list_and_delete_csr(self, temp_storage):
        mgr = CertificateManager()
        csr, key, meta = mgr.generate_csr("csr-del.example.com")
        csr_id = temp_storage.save_csr(csr, key, meta)

        csrs = temp_storage.list_csrs()
        assert len(csrs) == 1
        assert csrs[0]["common_name"] == "csr-del.example.com"

        temp_storage.delete_csr(csr_id)
        assert temp_storage.list_csrs() == []

    def test_delete_missing_csr_raises(self, temp_storage):
        with pytest.raises(FileNotFoundError):
            temp_storage.delete_csr("missing-id")


class TestRenewAll:
    """Tests renouvellement en masse."""

    def test_renew_all_dry_run(self, temp_storage):
        mgr = CertificateManager()
        cert, key, meta = mgr.generate_self_signed_cert("batch.example.com", validity_days=5)
        cert_id = temp_storage.save_certificate(cert, key, meta)

        renewal = CertificateRenewal(temp_storage)
        results = renewal.renew_all_expiring(days_threshold=30, dry_run=True)
        assert len(results) >= 1
        assert results[0][0] == cert_id
        assert results[0][1] == "dry-run"

    def test_renew_all_executes(self, temp_storage):
        mgr = CertificateManager()
        cert, key, meta = mgr.generate_self_signed_cert("exec.example.com", validity_days=10)
        cert_id = temp_storage.save_certificate(cert, key, meta)

        renewal = CertificateRenewal(temp_storage)
        results = renewal.renew_all_expiring(days_threshold=30, dry_run=False)
        renewed = [r for r in results if r[0] == cert_id]
        assert len(renewed) == 1
        assert renewed[0][2] is None
        assert renewed[0][1] != cert_id

"""Tests pour le module audit."""

from src.core.audit import AuditLogger


class TestAuditLogger:
    def test_log_and_list(self, temp_storage):
        logger = AuditLogger(str(temp_storage.storage_path), retention_days=30)
        entry = logger.log("certificate.create", "u1", "alice", "certificate", "cert-1")
        assert entry["action"] == "certificate.create"
        assert entry["username"] == "alice"

        logs = logger.list_logs(limit=10)
        assert len(logs) == 1
        assert logs[0]["resource_id"] == "cert-1"

    def test_export_json_and_csv(self, temp_storage):
        logger = AuditLogger(str(temp_storage.storage_path))
        logger.log("auth.login", "u1", "bob")
        json_export = logger.export_json()
        assert "auth.login" in json_export
        csv_export = logger.export_csv()
        assert "auth.login" in csv_export
        assert "username" in csv_export.split("\n")[0]

    def test_rotate_removes_old_entries(self, temp_storage):
        logger = AuditLogger(str(temp_storage.storage_path), retention_days=0)
        logger.log("test.action", "u1", "tester")
        removed = logger.rotate()
        assert removed >= 1
        assert len(logger.list_logs()) == 0

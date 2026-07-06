"""Tests pour backup/restore."""

import pytest

from src.core.backup import BackupManager
from src.core.certificate import CertificateManager
from src.core.storage import SecureStorage


class TestBackupManager:
    """Tests BackupManager."""

    def test_create_and_restore_backup(self, temp_storage, tmp_path):
        manager = CertificateManager()
        cert, key, meta = manager.generate_self_signed_cert("backup.example.com")
        temp_storage.save_certificate(cert, key, meta)

        backup_path = str(tmp_path / "backup.tar.gz")
        backup = BackupManager(str(temp_storage.storage_path))
        meta_out = backup.create_backup(backup_path)
        assert meta_out["encrypted"] is False

        restore_target = tmp_path / "restored"
        restore = BackupManager(str(restore_target))
        result = restore.restore_backup(backup_path, overwrite=True)

        restored = SecureStorage(storage_path=str(restore_target))
        certs = restored.list_certificates()
        assert len(certs) == 1
        assert certs[0]["common_name"] == "backup.example.com"
        assert result["target_path"] == str(restore_target)

    def test_encrypted_backup(self, temp_storage, tmp_path):
        manager = CertificateManager()
        cert, key, meta = manager.generate_self_signed_cert("enc.example.com")
        temp_storage.save_certificate(cert, key, meta)

        backup_path = str(tmp_path / "backup.enc")
        backup = BackupManager(str(temp_storage.storage_path))
        backup.create_backup(backup_path, password="secret123")

        restore_target = tmp_path / "restored_enc"
        restore = BackupManager(str(restore_target))
        restore.restore_backup(backup_path, password="secret123", overwrite=True)

        restored = SecureStorage(storage_path=str(restore_target))
        assert len(restored.list_certificates()) == 1

    def test_restore_requires_password(self, temp_storage, tmp_path):
        backup_path = str(tmp_path / "backup.enc")
        BackupManager(str(temp_storage.storage_path)).create_backup(
            backup_path, password="secret"
        )
        with pytest.raises(ValueError, match="Mot de passe"):
            BackupManager(str(tmp_path / "fail")).restore_backup(backup_path)

    def test_restore_nonempty_without_overwrite(self, temp_storage, tmp_path):
        backup_path = str(tmp_path / "backup.tar.gz")
        BackupManager(str(temp_storage.storage_path)).create_backup(backup_path)

        manager = CertificateManager()
        cert, key, meta = manager.generate_self_signed_cert("existing.example.com")
        temp_storage.save_certificate(cert, key, meta)

        with pytest.raises(ValueError, match="pas vide"):
            BackupManager(str(temp_storage.storage_path)).restore_backup(backup_path)

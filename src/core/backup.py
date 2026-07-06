"""Sauvegarde et restauration du stockage CertificationManager."""

import base64
import json
import os
import shutil
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Tuple

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class BackupManager:
    """Gestionnaire de backup/restore du répertoire de stockage."""

    MAGIC = b"CERTMGR_BACKUP_v1"

    def __init__(self, storage_path: Optional[str] = None):
        if storage_path is None:
            from ..config import get_settings
            storage_path = get_settings().storage_path
        self.storage_path = Path(storage_path)

    def create_backup(
        self,
        output_path: str,
        password: Optional[str] = None,
    ) -> Dict:
        """
        Crée une archive du stockage.

        Args:
            output_path: Chemin du fichier de sortie (.tar.gz ou .tar.gz.enc)
            password: Mot de passe optionnel pour chiffrer l'archive

        Returns:
            Métadonnées du backup
        """
        if not self.storage_path.exists():
            raise FileNotFoundError(f"Stockage introuvable: {self.storage_path}")

        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)

        manifest = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "storage_path": str(self.storage_path),
            "encrypted": password is not None,
            "version": "1.0",
        }

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            archive_path = tmp_path / "backup.tar.gz"
            manifest_path = tmp_path / "manifest.json"
            manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

            with tarfile.open(archive_path, "w:gz") as tar:
                tar.add(manifest_path, arcname="manifest.json")
                for item in self.storage_path.rglob("*"):
                    if item.is_file():
                        arcname = str(item.relative_to(self.storage_path.parent))
                        tar.add(item, arcname=arcname)

            data = self.MAGIC + archive_path.read_bytes()

            if password:
                salt = os.urandom(16)
                key = self._derive_key(password, salt)
                fernet = Fernet(key)
                encrypted = fernet.encrypt(data)
                output.write_bytes(salt + encrypted)
                os.chmod(output, 0o600)
            else:
                output.write_bytes(data)
                os.chmod(output, 0o644)

        manifest["output_path"] = str(output)
        manifest["size_bytes"] = output.stat().st_size
        return manifest

    def restore_backup(
        self,
        archive_path: str,
        password: Optional[str] = None,
        target_path: Optional[str] = None,
        overwrite: bool = False,
    ) -> Dict:
        """
        Restaure un backup vers le stockage.

        Args:
            archive_path: Chemin de l'archive
            password: Mot de passe si archive chiffrée
            target_path: Chemin cible (défaut: storage_path actuel)
            overwrite: Écraser le stockage existant

        Returns:
            Métadonnées de restauration
        """
        archive = Path(archive_path)
        if not archive.exists():
            raise FileNotFoundError(f"Archive introuvable: {archive_path}")

        target = Path(target_path) if target_path else self.storage_path

        if target.exists() and any(target.iterdir()) and not overwrite:
            raise ValueError(
                "Le répertoire cible n'est pas vide. Utilisez overwrite=True."
            )

        raw = archive.read_bytes()

        if raw.startswith(self.MAGIC):
            data = raw[len(self.MAGIC) :]
        elif len(raw) > 16:
            salt = raw[:16]
            encrypted = raw[16:]
            if not password:
                raise ValueError("Mot de passe requis pour une archive chiffrée")
            key = self._derive_key(password, salt)
            fernet = Fernet(key)
            try:
                data = fernet.decrypt(encrypted)
                if data.startswith(self.MAGIC):
                    data = data[len(self.MAGIC) :]
                else:
                    raise ValueError("Archive invalide après déchiffrement")
            except Exception as e:
                raise ValueError(f"Déchiffrement échoué: {e}") from e
        else:
            raise ValueError("Format d'archive non reconnu")

        with tempfile.TemporaryDirectory() as tmp_dir:
            tar_path = Path(tmp_dir) / "restore.tar.gz"
            tar_path.write_bytes(data)

            with tarfile.open(tar_path, "r:gz") as tar:
                tar.extractall(path=tmp_dir)

            manifest_file = Path(tmp_dir) / "manifest.json"
            if not manifest_file.exists():
                raise ValueError("Archive invalide: manifest.json manquant")

            manifest = json.loads(manifest_file.read_text(encoding="utf-8"))

            certmanager_root = Path(tmp_dir) / self.storage_path.name
            if not certmanager_root.exists():
                certmanager_root = Path(tmp_dir) / "certmanager"
            if not certmanager_root.exists():
                raise ValueError("Archive invalide: structure de stockage introuvable")

            metadata_file = certmanager_root / "metadata.json"
            if not metadata_file.exists():
                raise ValueError("Archive invalide: metadata.json manquant")

            if target.exists():
                if overwrite:
                    shutil.rmtree(target)
                else:
                    target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)

            shutil.copytree(certmanager_root, target, dirs_exist_ok=overwrite)

        return {
            "restored_at": datetime.now(timezone.utc).isoformat(),
            "target_path": str(target),
            "backup_created_at": manifest.get("created_at"),
        }

    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480_000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))

"""Stockage JSON de configuration dans le répertoire de stockage."""

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional


class ConfigStore:
    """Lecture/écriture de fichiers de configuration applicatifs."""

    def __init__(self, storage_path: Optional[str] = None, filename: str = "config.json"):
        if storage_path is None:
            from ..config import get_settings
            storage_path = get_settings().storage_path
        self.config_dir = Path(storage_path) / "config"
        self.config_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.config_dir, 0o700)
        self.config_file = self.config_dir / filename

    def load(self) -> Dict[str, Any]:
        if not self.config_file.exists():
            return {}
        try:
            with open(self.config_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}

    def save(self, data: Dict[str, Any]) -> None:
        tmp = self.config_file.with_suffix(".json.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.chmod(tmp, 0o600)
        tmp.replace(self.config_file)
        os.chmod(self.config_file, 0o600)

    def update(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        data = self.load()
        data.update(updates)
        self.save(data)
        return data

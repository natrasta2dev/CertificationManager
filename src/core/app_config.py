"""Configuration applicative persistante (seuils alertes, export/import)."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from .alerts import AlertLevel, AlertManager
from .config_store import ConfigStore
from .lifecycle import CertificateLifecycle
from .storage import SecureStorage


CONFIG_FILES = (
    "alerts.json",
    "scheduler.json",
    "notifications.json",
    "webhooks.json",
)


def load_alert_thresholds(storage_path: str) -> Optional[Dict[int, AlertLevel]]:
    """Charge les seuils d'alerte depuis le stockage."""
    data = ConfigStore(storage_path, "alerts.json").load()
    raw = data.get("thresholds")
    if not raw:
        return None
    return {int(days): AlertLevel(level) for days, level in raw.items()}


def save_alert_thresholds(storage_path: str, thresholds: Dict[int, AlertLevel]) -> Dict:
    """Persiste les seuils d'alerte."""
    store = ConfigStore(storage_path, "alerts.json")
    payload = {
        "thresholds": {str(days): level.value for days, level in thresholds.items()},
    }
    store.save(payload)
    return payload


def alert_manager_for_storage(storage: SecureStorage) -> AlertManager:
    """Crée un AlertManager avec seuils persistés."""
    thresholds = load_alert_thresholds(str(storage.storage_path))
    lifecycle = CertificateLifecycle(storage)
    return AlertManager(lifecycle, thresholds)


def get_app_config_summary(storage_path: Optional[str] = None) -> Dict[str, Any]:
    """Résumé de la configuration applicative."""
    if storage_path is None:
        from ..config import get_settings
        storage_path = get_settings().storage_path

    from ..config import get_settings
    settings = get_settings()

    config_dir = Path(storage_path) / "config"
    summary: Dict[str, Any] = {
        "storage_path": storage_path,
        "auth_enabled": settings.auth_enabled,
        "encrypt_keys": settings.encrypt_keys,
        "rate_limit_enabled": settings.rate_limit_enabled,
        "alert_thresholds": {},
        "config_files": {},
    }

    thresholds = load_alert_thresholds(storage_path)
    if thresholds:
        summary["alert_thresholds"] = {
            str(days): level.value for days, level in thresholds.items()
        }

    for name in CONFIG_FILES:
        path = config_dir / name
        summary["config_files"][name] = path.exists()

    return summary


def export_app_config(storage_path: str, output_path: str) -> Dict[str, Any]:
    """Exporte les fichiers de configuration en un seul JSON."""
    config_dir = Path(storage_path) / "config"
    bundle: Dict[str, Any] = {
        "version": "1.0",
        "configs": {},
    }
    for name in CONFIG_FILES:
        path = config_dir / name
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                bundle["configs"][name] = json.load(f)

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(bundle, indent=2, ensure_ascii=False), encoding="utf-8")

    return {"exported": list(bundle["configs"].keys()), "path": str(out)}


def import_app_config(storage_path: str, input_path: str) -> Dict[str, Any]:
    """Importe une configuration exportée."""
    data = json.loads(Path(input_path).read_text(encoding="utf-8"))
    configs = data.get("configs", {})
    imported: List[str] = []

    config_dir = Path(storage_path) / "config"
    config_dir.mkdir(parents=True, exist_ok=True)

    for name, content in configs.items():
        if name not in CONFIG_FILES:
            continue
        target = config_dir / name
        tmp = target.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(content, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(target)
        imported.append(name)

    return {"imported": imported}

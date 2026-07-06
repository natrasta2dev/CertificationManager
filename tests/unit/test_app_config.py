"""Tests configuration applicative."""

import json
from pathlib import Path

from src.core.alerts import AlertLevel
from src.core.app_config import (
    export_app_config,
    get_app_config_summary,
    import_app_config,
    load_alert_thresholds,
    save_alert_thresholds,
)


class TestAppConfig:
    def test_save_and_load_thresholds(self, temp_storage):
        path = str(temp_storage.storage_path)
        save_alert_thresholds(path, {14: AlertLevel.WARNING, 7: AlertLevel.CRITICAL})
        loaded = load_alert_thresholds(path)
        assert loaded[14] == AlertLevel.WARNING
        assert loaded[7] == AlertLevel.CRITICAL

    def test_export_import_roundtrip(self, temp_storage, tmp_path):
        path = str(temp_storage.storage_path)
        save_alert_thresholds(path, {30: AlertLevel.WARNING})
        out = tmp_path / "config-bundle.json"
        export_app_config(path, str(out))
        assert out.exists()

        import_app_config(path, str(out))
        loaded = load_alert_thresholds(path)
        assert loaded[30] == AlertLevel.WARNING

    def test_config_summary(self, temp_storage):
        summary = get_app_config_summary(str(temp_storage.storage_path))
        assert "storage_path" in summary
        assert "alert_thresholds" in summary

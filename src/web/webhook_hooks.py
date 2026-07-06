"""Hooks webhooks pour les événements certificats."""

from typing import Any, Dict, Optional

from ..config import get_settings
from ..core.webhooks import WebhookManager


def emit_webhook(
    event: str,
    payload: Dict[str, Any],
    storage_path: Optional[str] = None,
) -> None:
    """Émet un webhook si configuré (erreurs ignorées)."""
    try:
        path = storage_path or get_settings().storage_path
        manager = WebhookManager(path)
        if manager.is_enabled():
            manager.dispatch(event, payload)
    except Exception:
        pass

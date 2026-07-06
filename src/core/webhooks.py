"""Webhooks pour événements certificats."""

import hashlib
import hmac
import json
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .config_store import ConfigStore

WEBHOOK_EVENTS = {
    "certificate.created",
    "certificate.expiring",
    "certificate.renewed",
    "certificate.deleted",
    "alert.triggered",
}


class WebhookManager:
    """Dispatch de webhooks avec signature HMAC et retry."""

    def __init__(self, storage_path: Optional[str] = None):
        self.store = ConfigStore(storage_path, "webhooks.json")

    def get_config(self) -> Dict:
        return self.store.load()

    def update_config(self, updates: Dict) -> Dict:
        return self.store.update(updates)

    def is_enabled(self) -> bool:
        cfg = self.store.load()
        return bool(cfg.get("enabled")) and bool(cfg.get("endpoints"))

    def dispatch(
        self,
        event: str,
        payload: Dict[str, Any],
        max_retries: int = 3,
    ) -> List[Dict]:
        """
        Envoie un événement aux endpoints configurés.

        Returns:
            Liste des résultats par endpoint
        """
        if event not in WEBHOOK_EVENTS:
            raise ValueError(f"Événement inconnu: {event}")

        cfg = self.store.load()
        if not cfg.get("enabled"):
            return []

        secret = cfg.get("secret", "")
        endpoints = cfg.get("endpoints", [])
        results = []

        body = {
            "event": event,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": payload,
        }
        body_bytes = json.dumps(body, ensure_ascii=False).encode("utf-8")

        headers = {"Content-Type": "application/json", "User-Agent": "CertificationManager/0.2"}
        if secret:
            sig = hmac.new(secret.encode(), body_bytes, hashlib.sha256).hexdigest()
            headers["X-CertManager-Signature"] = f"sha256={sig}"

        for endpoint in endpoints:
            url = endpoint.get("url")
            events = endpoint.get("events", list(WEBHOOK_EVENTS))
            if not url or event not in events:
                continue

            result = {"url": url, "event": event, "success": False, "attempts": 0}
            for attempt in range(max_retries):
                result["attempts"] = attempt + 1
                try:
                    req = urllib.request.Request(url, data=body_bytes, headers=headers, method="POST")
                    with urllib.request.urlopen(req, timeout=15) as resp:
                        result["status_code"] = resp.status
                        result["success"] = 200 <= resp.status < 300
                        if result["success"]:
                            break
                except urllib.error.HTTPError as e:
                    result["status_code"] = e.code
                    result["error"] = str(e)
                except Exception as e:
                    result["error"] = str(e)

                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)

            results.append(result)

        return results

    def dispatch_alert(self, alert_dict: Dict) -> List[Dict]:
        return self.dispatch("alert.triggered", alert_dict)

    def dispatch_certificate_event(self, event: str, cert_metadata: Dict) -> List[Dict]:
        return self.dispatch(event, cert_metadata)

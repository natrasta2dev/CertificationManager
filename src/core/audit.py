"""Journal d'audit structuré."""

import csv
import io
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


class AuditLogger:
    """Journalise les opérations sensibles en JSON Lines."""

    def __init__(self, storage_path: str, retention_days: int = 90):
        self.audit_dir = Path(storage_path) / "audit"
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.audit_dir / "audit.jsonl"
        self.retention_days = retention_days
        os.chmod(self.audit_dir, 0o700)
        if self.log_file.exists():
            os.chmod(self.log_file, 0o600)

    def log(
        self,
        action: str,
        user_id: str = "system",
        username: str = "system",
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        success: bool = True,
        ip_address: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Ajoute une entrée d'audit."""
        entry = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "user_id": user_id,
            "username": username,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "details": details or {},
            "success": success,
            "ip_address": ip_address,
        }
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        os.chmod(self.log_file, 0o600)
        return entry

    def list_logs(
        self,
        limit: int = 100,
        offset: int = 0,
        action: Optional[str] = None,
        username: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Liste les entrées d'audit (plus récentes en premier)."""
        if not self.log_file.exists():
            return []

        entries: List[Dict[str, Any]] = []
        with open(self.log_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    if action and entry.get("action") != action:
                        continue
                    if username and entry.get("username") != username:
                        continue
                    entries.append(entry)
                except json.JSONDecodeError:
                    continue

        entries.reverse()
        return entries[offset : offset + limit]

    def export_json(self, limit: int = 1000) -> str:
        """Exporte les logs en JSON."""
        return json.dumps(self.list_logs(limit=limit), indent=2, ensure_ascii=False)

    def export_csv(self, limit: int = 1000) -> str:
        """Exporte les logs en CSV."""
        entries = self.list_logs(limit=limit)
        output = io.StringIO()
        if not entries:
            return ""
        writer = csv.DictWriter(
            output,
            fieldnames=[
                "id", "timestamp", "action", "username", "resource_type",
                "resource_id", "success", "ip_address", "details",
            ],
        )
        writer.writeheader()
        for entry in entries:
            writer.writerow({
                "id": entry.get("id", ""),
                "timestamp": entry.get("timestamp", ""),
                "action": entry.get("action", ""),
                "username": entry.get("username", ""),
                "resource_type": entry.get("resource_type") or "",
                "resource_id": entry.get("resource_id") or "",
                "success": entry.get("success", True),
                "ip_address": entry.get("ip_address") or "",
                "details": json.dumps(entry.get("details", {})),
            })
        return output.getvalue()

    def rotate(self) -> int:
        """Supprime les entrées plus anciennes que retention_days."""
        if not self.log_file.exists():
            return 0

        cutoff = datetime.now(timezone.utc) - timedelta(days=self.retention_days)
        kept: List[str] = []
        removed = 0

        with open(self.log_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    ts = datetime.fromisoformat(entry["timestamp"])
                    if ts >= cutoff:
                        kept.append(line)
                    else:
                        removed += 1
                except (json.JSONDecodeError, KeyError, ValueError):
                    kept.append(line)

        tmp = self.log_file.with_suffix(".jsonl.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            for line in kept:
                f.write(line + "\n")
        os.chmod(tmp, 0o600)
        tmp.replace(self.log_file)
        os.chmod(self.log_file, 0o600)
        return removed
